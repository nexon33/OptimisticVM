use crate::error::{OvpError, Result};
use crate::hash::hash_data;
use crate::types::{DisputeProof, Hash, ProofType};

/// Generate a Mock dispute proof (type 0x00) for testing.
///
/// The mock proof simply includes the raw input/output bytes as proof_bytes.
pub fn generate_mock_proof(
    input_hash: &Hash,
    output_hash: &Hash,
    wasm_hash: &Hash,
) -> DisputeProof {
    // public_inputs = SHA256(input_hash || output_hash)
    let mut pi_input = Vec::with_capacity(64);
    pi_input.extend_from_slice(input_hash);
    pi_input.extend_from_slice(output_hash);
    let public_inputs = hash_data(&pi_input);

    // Mock proof bytes: just the concatenation as a marker
    let proof_bytes = b"MOCK_PROOF".to_vec();

    DisputeProof {
        proof_type: ProofType::Mock,
        proof_bytes,
        public_inputs,
        input_hash: *input_hash,
        output_hash: *output_hash,
        wasm_hash: *wasm_hash,
    }
}

/// Verify a DisputeProof.
///
/// For all proof types:
/// 1. public_inputs must equal hash_data(input_hash || output_hash)
///
/// For Mock proofs: always passes if public inputs are correct.
/// For other types: returns an error (not implemented in full verification mode).
pub fn verify_dispute_proof(proof: &DisputeProof) -> Result<()> {
    // Verify public inputs are correctly derived
    let mut pi_input = Vec::with_capacity(64);
    pi_input.extend_from_slice(&proof.input_hash);
    pi_input.extend_from_slice(&proof.output_hash);
    let expected_pi = hash_data(&pi_input);

    if proof.public_inputs != expected_pi {
        return Err(OvpError::InvalidProof(
            "public_inputs != hash_data(input_hash || output_hash)".to_string(),
        ));
    }

    match proof.proof_type {
        ProofType::Mock => Ok(()),
        _ => Err(OvpError::InvalidProof(format!(
            "proof type {:?} not supported in full verification mode",
            proof.proof_type
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_data;

    #[test]
    fn test_mock_proof_roundtrip() {
        let input_hash = hash_data(b"input_state");
        let output_hash = hash_data(b"output_state");
        let wasm_hash = hash_data(b"code");

        let proof = generate_mock_proof(&input_hash, &output_hash, &wasm_hash);
        assert!(verify_dispute_proof(&proof).is_ok());
    }

    #[test]
    fn test_mock_proof_wrong_public_inputs() {
        let input_hash = hash_data(b"input_state");
        let output_hash = hash_data(b"output_state");
        let wasm_hash = hash_data(b"code");

        let mut proof = generate_mock_proof(&input_hash, &output_hash, &wasm_hash);
        proof.public_inputs[0] ^= 0xFF; // corrupt

        assert!(verify_dispute_proof(&proof).is_err());
    }

    // Appendix B.6: DisputeProof binary encoding
    #[test]
    fn test_dispute_proof_encoding() {
        let proof = DisputeProof {
            proof_type: ProofType::Mock,
            proof_bytes: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            public_inputs: [0x2A; 32],
            input_hash: [0x01; 32],
            output_hash: [0x02; 32],
            wasm_hash: [0xCA; 32],
        };

        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), 138);

        // Byte 0: proof_type = 0x00 (Mock)
        assert_eq!(bytes[0], 0x00);
        // Bytes 1-4: proof_length = 5 (BE)
        assert_eq!(&bytes[1..5], &[0x00, 0x00, 0x00, 0x05]);
        // Bytes 5-9: proof_bytes
        assert_eq!(&bytes[5..10], &[0x01, 0x02, 0x03, 0x04, 0x05]);
        // Bytes 10-41: public_inputs
        assert_eq!(&bytes[10..42], &[0x2A; 32]);
        // Bytes 42-73: input_hash
        assert_eq!(&bytes[42..74], &[0x01; 32]);
        // Bytes 74-105: output_hash
        assert_eq!(&bytes[74..106], &[0x02; 32]);
        // Bytes 106-137: wasm_hash
        assert_eq!(&bytes[106..138], &[0xCA; 32]);
    }

    #[test]
    fn test_dispute_proof_deserialization() {
        let original = DisputeProof {
            proof_type: ProofType::Mock,
            proof_bytes: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            public_inputs: [0x2A; 32],
            input_hash: [0x01; 32],
            output_hash: [0x02; 32],
            wasm_hash: [0xCA; 32],
        };

        let bytes = original.to_bytes();
        let decoded = DisputeProof::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.proof_type, original.proof_type);
        assert_eq!(decoded.proof_bytes, original.proof_bytes);
        assert_eq!(decoded.public_inputs, original.public_inputs);
        assert_eq!(decoded.input_hash, original.input_hash);
        assert_eq!(decoded.output_hash, original.output_hash);
        assert_eq!(decoded.wasm_hash, original.wasm_hash);
    }
}
