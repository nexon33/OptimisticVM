use crate::error::{OvpError, Result};
use crate::hash::{hash_data, hash_transition};
use crate::merkle::verify_proof;
use crate::types::{Commitment, Hash, TransitionProof};

/// Trait for domain-specific step functions.
///
/// Given the previous state and inputs, produce the next state.
/// Must be deterministic: same inputs → same output.
pub trait StepFunction {
    fn execute(&self, state: &[u8], inputs: &[u8]) -> Vec<u8>;
}

/// Blanket implementation so closures work as StepFunction.
impl<F> StepFunction for F
where
    F: Fn(&[u8], &[u8]) -> Vec<u8>,
{
    fn execute(&self, state: &[u8], inputs: &[u8]) -> Vec<u8> {
        (self)(state, inputs)
    }
}

/// Verify a state transition with full re-execution (Section 9.2).
///
/// Returns the computed output hash on success.
pub fn verify_transition(
    commitment: &Commitment,
    proof: &TransitionProof,
    step_fn: &dyn StepFunction,
) -> Result<Hash> {
    // Step 1: Verify Merkle inclusion
    if proof.merkle_proof.root != commitment.root {
        return Err(OvpError::RootMismatch);
    }
    if !verify_proof(&proof.merkle_proof) {
        return Err(OvpError::MerkleVerificationFailed);
    }

    // Step 2: Verify transition hash matches Merkle leaf
    let expected = hash_transition(
        &proof.previous_state_hash,
        &proof.input_hash,
        &proof.claimed_state_hash,
    );
    if proof.merkle_proof.leaf != expected {
        return Err(OvpError::TransitionHashMismatch);
    }

    // Step 3: Verify previous state hash
    let computed_prev = hash_data(&proof.previous_state);
    if computed_prev != proof.previous_state_hash {
        return Err(OvpError::PreviousStateHashMismatch);
    }

    // Step 4: Verify input hash
    let computed_input = hash_data(&proof.inputs);
    if computed_input != proof.input_hash {
        return Err(OvpError::InputHashMismatch);
    }

    // Step 5: Re-execute the step function
    let computed_state = step_fn.execute(&proof.previous_state, &proof.inputs);
    let computed_hash = hash_data(&computed_state);

    // Step 6: Compare computed output to claimed output
    if computed_hash != proof.claimed_state_hash {
        return Err(OvpError::FraudDetected);
    }

    Ok(computed_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::create_commitment;
    use crate::hash::hash_data;
    use crate::types::TransitionProof;

    /// Simple step function: XOR each byte of state with the first byte of input.
    fn xor_step(state: &[u8], inputs: &[u8]) -> Vec<u8> {
        let key = inputs.first().copied().unwrap_or(0);
        state.iter().map(|b| b ^ key).collect()
    }

    fn build_transition_scenario() -> (
        crate::types::Commitment,
        crate::merkle::MerkleTree,
        Vec<Vec<u8>>,  // states
        Vec<Vec<u8>>,  // inputs
        Vec<Hash>,     // checkpoint hashes (transition hashes)
    ) {
        let initial_state = vec![0x00u8; 4];
        let step_inputs: Vec<Vec<u8>> = vec![vec![0x01], vec![0x02], vec![0x03], vec![0x04]];

        let mut states = vec![initial_state.clone()];
        let mut checkpoints = Vec::new();

        for input in &step_inputs {
            let prev_state = states.last().unwrap();
            let next_state = xor_step(prev_state, input);
            let prev_hash = hash_data(prev_state);
            let input_hash = hash_data(input);
            let next_hash = hash_data(&next_state);
            let transition = hash_transition(&prev_hash, &input_hash, &next_hash);
            checkpoints.push(transition);
            states.push(next_state);
        }

        let wasm_hash = hash_data(b"xor_step");
        let (commitment, tree) = create_commitment(&checkpoints, &wasm_hash);

        (commitment, tree, states, step_inputs, checkpoints)
    }

    #[test]
    fn test_verify_transition_success() {
        let (commitment, tree, states, inputs, _) = build_transition_scenario();

        // Verify transition at index 0 (first step)
        let proof = tree.generate_proof(0).unwrap();
        let prev = &states[0];
        let inp = &inputs[0];
        let next = &states[1];

        let tp = TransitionProof {
            merkle_proof: proof,
            previous_state: prev.clone(),
            previous_state_hash: hash_data(prev),
            inputs: inp.clone(),
            input_hash: hash_data(inp),
            claimed_state_hash: hash_data(next),
            checkpoint_index: 0,
        };

        let result = verify_transition(&commitment, &tp, &xor_step);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_transition_fraud() {
        let (commitment, tree, states, inputs, _) = build_transition_scenario();

        let proof = tree.generate_proof(0).unwrap();
        let prev = &states[0];
        let inp = &inputs[0];

        // Claim a wrong output state
        let wrong_state = vec![0xFF; 4];
        let tp = TransitionProof {
            merkle_proof: proof,
            previous_state: prev.clone(),
            previous_state_hash: hash_data(prev),
            inputs: inp.clone(),
            input_hash: hash_data(inp),
            claimed_state_hash: hash_data(&wrong_state),
            checkpoint_index: 0,
        };

        // The transition hash won't match the Merkle leaf
        let result = verify_transition(&commitment, &tp, &xor_step);
        assert!(result.is_err());
    }
}
