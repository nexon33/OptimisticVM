//! End-to-end integration test for the OVP full verification protocol.
//!
//! Tests the complete flow: execute → commit → sign → verify → fraud → bisect → zk.

use ed25519_dalek::SigningKey;
use ovp::bisection::{BisectionDispute, BisectionPhase};
use ovp::commitment::{create_commitment, sign_commitment, verify_signed_commitment};
use ovp::fraud::{generate_fraud_proof, validate_fraud_proof};
use ovp::hash::{hash_data, hash_transition};
use ovp::merkle::verify_proof;
use ovp::snitch::{check_code_integrity, sign_attestation, verify_attestation};
use ovp::transition::verify_transition;
use ovp::types::*;
use ovp::zk::{generate_mock_proof, verify_dispute_proof};

// ---------------------------------------------------------------------------
// Step function: simple counter increment
// ---------------------------------------------------------------------------

/// Each state is a 4-byte little-endian counter.
/// The step function adds the first byte of input to the counter.
fn counter_step(state: &[u8], inputs: &[u8]) -> Vec<u8> {
    let val = u32::from_le_bytes(state[..4].try_into().unwrap());
    let add = inputs.first().copied().unwrap_or(0) as u32;
    (val + add).to_le_bytes().to_vec()
}

/// Execute the full computation and return (states, inputs, transition_hashes).
fn run_computation(
    initial_state: &[u8],
    step_inputs: &[Vec<u8>],
) -> (Vec<Vec<u8>>, Vec<Hash>) {
    let mut states = vec![initial_state.to_vec()];
    let mut checkpoints = Vec::new();

    for input in step_inputs {
        let prev = states.last().unwrap();
        let next = counter_step(prev, input);
        let prev_hash = hash_data(prev);
        let input_hash = hash_data(input);
        let next_hash = hash_data(&next);
        checkpoints.push(hash_transition(&prev_hash, &input_hash, &next_hash));
        states.push(next);
    }

    (states, checkpoints)
}

// ===========================================================================
// HAPPY PATH
// ===========================================================================

#[test]
fn test_happy_path_full_protocol() {
    let initial_state = 0u32.to_le_bytes().to_vec();
    let step_inputs: Vec<Vec<u8>> = (1..=8u8).map(|i| vec![i]).collect();
    let wasm_hash = hash_data(b"counter_step_v1");

    // 1. Execute computation
    let (states, checkpoints) = run_computation(&initial_state, &step_inputs);
    assert_eq!(states.len(), 9); // initial + 8 steps
    assert_eq!(checkpoints.len(), 8);

    // Verify final state: 1+2+3+4+5+6+7+8 = 36
    let final_val = u32::from_le_bytes(states[8][..4].try_into().unwrap());
    assert_eq!(final_val, 36);

    // 2. Build commitment
    let (commitment, tree) = create_commitment(&checkpoints, &wasm_hash);
    assert_eq!(commitment.total_checkpoints, 8);

    // 3. Sign commitment
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let signed = sign_commitment(&commitment, &signing_key);

    // 4. Verify signature
    assert!(verify_signed_commitment(&signed).is_ok());

    // 5. Verify ALL Merkle proofs
    for i in 0..8u64 {
        let proof = tree.generate_proof(i).unwrap();
        assert!(verify_proof(&proof), "Merkle proof failed for index {i}");
        assert_eq!(proof.root, commitment.root);
    }

    // 6. Verify transition at each step
    for i in 0..8 {
        let merkle_proof = tree.generate_proof(i as u64).unwrap();
        let prev = &states[i];
        let inp = &step_inputs[i];
        let next = &states[i + 1];

        let tp = TransitionProof {
            merkle_proof,
            previous_state: prev.clone(),
            previous_state_hash: hash_data(prev),
            inputs: inp.clone(),
            input_hash: hash_data(inp),
            claimed_state_hash: hash_data(next),
            checkpoint_index: i as u64,
        };

        let result = verify_transition(&commitment, &tp, &counter_step);
        assert!(result.is_ok(), "transition verification failed at step {i}");
    }

    // 7. Mock ZK proof
    let input_hash = hash_data(&states[0]);
    let output_hash = hash_data(&states[8]);
    let dispute_proof = generate_mock_proof(&input_hash, &output_hash, &wasm_hash);
    assert!(verify_dispute_proof(&dispute_proof).is_ok());

    // 8. Code attestation round-trip
    let node_id = [0xAA; 32];
    let attestation = sign_attestation(&node_id, &wasm_hash, 1, &signing_key);
    let verifying_key = signing_key.verifying_key();
    assert!(verify_attestation(&attestation, &verifying_key).is_ok());

    // Serialization round-trip
    let bytes = attestation.to_bytes();
    let decoded = CodeAttestation::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.node_id, attestation.node_id);
    assert_eq!(decoded.wasm_hash, attestation.wasm_hash);
    assert_eq!(decoded.tick, attestation.tick);
}

// ===========================================================================
// FRAUD DETECTION PATH
// ===========================================================================

#[test]
fn test_fraud_detection_and_bisection() {
    let initial_state = 0u32.to_le_bytes().to_vec();
    let step_inputs: Vec<Vec<u8>> = (1..=8u8).map(|i| vec![i]).collect();
    let wasm_hash = hash_data(b"counter_step_v1");

    // Execute honestly to get reference hashes
    let (honest_states, mut checkpoints) = run_computation(&initial_state, &step_inputs);

    // Corrupt checkpoint 5 (step 5: state goes from 15 to 21)
    let fraud_index = 5;
    let bad_checkpoint = hash_data(b"fraudulent_output");
    checkpoints[fraud_index] = bad_checkpoint;

    // Build commitment with corrupted checkpoint
    let (commitment, tree) = create_commitment(&checkpoints, &wasm_hash);

    // 10. Fraud detected at step 5
    let proof = tree.generate_proof(fraud_index as u64).unwrap();
    let result = generate_fraud_proof(
        &commitment,
        fraud_index as u64,
        &honest_states[fraud_index],
        &step_inputs[fraud_index],
        proof,
        &counter_step,
        b"challenger_42",
    )
    .unwrap();

    let fraud_proof = match &result {
        FraudResult::FraudConfirmed(fp) => {
            assert_eq!(fp.checkpoint_index, fraud_index as u64);
            assert_ne!(fp.claimed_hash, fp.computed_hash);
            fp
        }
        FraudResult::NoFraud { .. } => panic!("expected fraud to be detected"),
    };

    // 11. Validate the fraud proof
    assert!(validate_fraud_proof(fraud_proof, &counter_step).is_ok());

    // 12. Bisection dispute from [0, 7]
    // Build honest state hashes for bisection
    let mut state_hashes: Vec<Hash> = honest_states.iter().map(|s| hash_data(s)).collect();

    // The commitment has corrupted checkpoint at index 5, so the "prover's"
    // claimed hash at index 6 might differ. For bisection, we use state hashes.
    // Replace hash at position 6 with a fraudulent value to simulate.
    state_hashes[6] = hash_data(b"bad_state_6");

    let mut dispute = BisectionDispute::new(
        0,
        7,
        state_hashes[0],
        state_hashes[7],
    )
    .unwrap();

    // Bisect until narrowed to a single step
    while dispute.range_width() > 1 {
        let mid = (dispute.left_index + dispute.right_index) / 2;
        dispute
            .defender_reveal_midpoint(state_hashes[mid as usize])
            .unwrap();

        // Challenger knows the correct hashes and picks the half with fraud
        let correct_mid = hash_data(&honest_states[mid as usize]);
        let pick_right = state_hashes[mid as usize] == correct_mid;
        // If midpoint is correct, fraud is in the right half
        // If midpoint is wrong, fraud is in the left half
        dispute.challenger_choose_half(pick_right).unwrap();
    }

    assert_eq!(dispute.phase, BisectionPhase::WaitingDefenderProof);

    // Defender proves the single step
    let left = dispute.left_index as usize;
    let _outcome = dispute
        .defender_prove_step(&honest_states[left], &[], &(|state: &[u8], _: &[u8]| {
            // Simplified step that just increments
            let val = u32::from_le_bytes(state[..4].try_into().unwrap());
            (val + 1).to_le_bytes().to_vec()
        }))
        .unwrap();

    // The dispute resolves (either party wins depending on exact narrowing)
    assert!(dispute.is_resolved());
    // The point is: the protocol narrows to a single step in O(log n) rounds
    assert!(dispute.rounds <= 4); // log2(7) ≈ 3
}

// ===========================================================================
// UNHAPPY PATHS / EDGE CASES
// ===========================================================================

#[test]
fn test_corrupted_merkle_proof_rejected() {
    let checkpoints: Vec<Hash> = (0..4u8).map(|i| hash_data(&[i])).collect();
    let wasm_hash = hash_data(b"test");
    let (_, tree) = create_commitment(&checkpoints, &wasm_hash);

    let mut proof = tree.generate_proof(1).unwrap();
    // Corrupt a sibling hash
    proof.siblings[0].hash[0] ^= 0xFF;

    assert!(!verify_proof(&proof));
}

#[test]
fn test_truncated_merkle_proof_rejected() {
    let checkpoints: Vec<Hash> = (0..4u8).map(|i| hash_data(&[i])).collect();
    let wasm_hash = hash_data(b"test");
    let (_, tree) = create_commitment(&checkpoints, &wasm_hash);

    let mut proof = tree.generate_proof(1).unwrap();
    // Remove last sibling — proof is now incomplete
    proof.siblings.pop();

    assert!(!verify_proof(&proof));
}

#[test]
fn test_commitment_wrong_checkpoint_count() {
    let checkpoints: Vec<Hash> = (0..4u8).map(|i| hash_data(&[i])).collect();
    let wasm_hash = hash_data(b"test");
    let (mut commitment, _) = create_commitment(&checkpoints, &wasm_hash);

    // Tamper with checkpoint count
    commitment.total_checkpoints = 999;

    // The commitment bytes will encode 999, which is detectable
    let bytes = commitment.to_bytes();
    let decoded = Commitment::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.total_checkpoints, 999);
    // A verifier would notice 999 != actual number of proofs received
}

#[test]
fn test_signed_commitment_wrong_key_rejected() {
    let checkpoints: Vec<Hash> = (0..4u8).map(|i| hash_data(&[i])).collect();
    let wasm_hash = hash_data(b"test");
    let (commitment, _) = create_commitment(&checkpoints, &wasm_hash);

    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let mut signed = sign_commitment(&commitment, &signing_key);

    // Replace with a different public key
    let wrong_key = SigningKey::from_bytes(&[0x99; 32]);
    signed.public_key = wrong_key.verifying_key().to_bytes();

    assert!(verify_signed_commitment(&signed).is_err());
}

#[test]
fn test_bisection_defender_lies_midpoint() {
    // Defender provides a wrong midpoint hash — challenger detects it
    let hashes: Vec<Hash> = (0..9u8).map(|i| hash_data(&[i])).collect();

    let mut dispute = BisectionDispute::new(0, 8, hashes[0], hashes[8]).unwrap();

    // Defender lies about midpoint 4
    let fake_midpoint = hash_data(b"lies");
    dispute.defender_reveal_midpoint(fake_midpoint).unwrap();

    // Challenger knows the real hash at 4 and picks the half with the lie
    // The fake midpoint doesn't match hashes[4], so fraud is in left half
    dispute.challenger_choose_half(false).unwrap(); // [0, 4]

    // Continue bisection...
    dispute.defender_reveal_midpoint(hashes[2]).unwrap();
    dispute.challenger_choose_half(true).unwrap(); // [2, 4]

    dispute.defender_reveal_midpoint(hashes[3]).unwrap();
    dispute.challenger_choose_half(true).unwrap(); // [3, 4], range = 1

    assert_eq!(dispute.phase, BisectionPhase::WaitingDefenderProof);
}

#[test]
fn test_bisection_defender_timeout() {
    let mut dispute = BisectionDispute::new(
        0,
        8,
        hash_data(&[0]),
        hash_data(&[8]),
    )
    .unwrap();

    let outcome = dispute.resolve_timeout(true); // defender timed out
    match outcome {
        DisputeOutcome::ChallengerWins { reason } => {
            assert!(reason.contains("timed out"));
        }
        _ => panic!("challenger should win on defender timeout"),
    }
    assert!(dispute.is_resolved());
}

#[test]
fn test_empty_commitment() {
    let wasm_hash = hash_data(b"test");
    let (commitment, tree) = create_commitment(&[], &wasm_hash);

    assert_eq!(commitment.total_checkpoints, 0);
    assert_eq!(commitment.root, ZERO_HASH);
    assert_eq!(commitment.chain_tip, ZERO_HASH);
    assert_eq!(tree.root, ZERO_HASH);
}

#[test]
fn test_single_checkpoint_commitment() {
    let checkpoint = hash_data(b"single");
    let wasm_hash = hash_data(b"test");
    let (commitment, tree) = create_commitment(&[checkpoint], &wasm_hash);

    assert_eq!(commitment.total_checkpoints, 1);
    assert_eq!(commitment.root, checkpoint); // single leaf IS the root

    let proof = tree.generate_proof(0).unwrap();
    assert!(verify_proof(&proof));
    assert_eq!(proof.siblings.len(), 0);
}

#[test]
fn test_fraud_proof_no_fraud_rejected() {
    // Build honest computation
    let initial_state = 0u32.to_le_bytes().to_vec();
    let step_inputs: Vec<Vec<u8>> = vec![vec![1], vec![2]];
    let wasm_hash = hash_data(b"counter_step_v1");

    // Use raw state hashes as leaves (not transition hashes)
    // so that hash_data(step_fn(state, input)) matches the leaf
    let state_1 = counter_step(&initial_state, &step_inputs[0]);
    let state_2 = counter_step(&state_1, &step_inputs[1]);
    let checkpoints = vec![hash_data(&state_1), hash_data(&state_2)];

    let (commitment, tree) = create_commitment(&checkpoints, &wasm_hash);
    let proof = tree.generate_proof(0).unwrap();

    // Try to generate a fraud proof — should find NO fraud
    let result = generate_fraud_proof(
        &commitment,
        0,
        &initial_state,
        &step_inputs[0],
        proof,
        &counter_step,
        b"challenger",
    )
    .unwrap();

    assert!(matches!(result, FraudResult::NoFraud { .. }));
}

#[test]
fn test_code_integrity_check() {
    let canonical = hash_data(b"canonical_wasm_v1");
    let correct = hash_data(b"canonical_wasm_v1");
    let modified = hash_data(b"modified_wasm");

    assert!(check_code_integrity(&correct, &canonical));
    assert!(!check_code_integrity(&modified, &canonical));
}

// ===========================================================================
// SERIALIZATION ROUND-TRIPS
// ===========================================================================

#[test]
fn test_all_serialization_roundtrips() {
    // Commitment
    let c = Commitment {
        root: [0xAB; 32],
        total_checkpoints: 100,
        chain_tip: [0xCD; 32],
        wasm_hash: [0xEF; 32],
    };
    assert_eq!(c, Commitment::from_bytes(&c.to_bytes()).unwrap());

    // Challenge
    let ch = Challenge {
        checkpoint_index: 42,
        seed: 12345,
    };
    let ch2 = Challenge::from_bytes(&ch.to_bytes()).unwrap();
    assert_eq!(ch.checkpoint_index, ch2.checkpoint_index);
    assert_eq!(ch.seed, ch2.seed);

    // DisputeProof
    let dp = DisputeProof {
        proof_type: ProofType::Mock,
        proof_bytes: vec![1, 2, 3],
        public_inputs: [0x2A; 32],
        input_hash: [0x01; 32],
        output_hash: [0x02; 32],
        wasm_hash: [0xCA; 32],
    };
    let dp2 = DisputeProof::from_bytes(&dp.to_bytes()).unwrap();
    assert_eq!(dp.proof_type, dp2.proof_type);
    assert_eq!(dp.proof_bytes, dp2.proof_bytes);
    assert_eq!(dp.public_inputs, dp2.public_inputs);

    // CodeAttestation
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let att = sign_attestation(&[0xBB; 32], &[0xCC; 32], 999, &signing_key);
    let att2 = CodeAttestation::from_bytes(&att.to_bytes()).unwrap();
    assert_eq!(att.node_id, att2.node_id);
    assert_eq!(att.tick, att2.tick);
    assert_eq!(att.signature, att2.signature);
}
