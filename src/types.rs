use serde::{Deserialize, Serialize};

use crate::error::{OvpError, Result};

/// Serde helper for [u8; 64] arrays (signatures).
mod serde_byte64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        bytes: &[u8; 64],
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        bytes.to_vec().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

/// 32-byte SHA-256 digest.
pub type Hash = [u8; 32];

/// The zero hash: 32 bytes of 0x00.
pub const ZERO_HASH: Hash = [0u8; 32];

/// Constant-time comparison for two hashes (prevents timing side-channels).
pub fn hash_eq(a: &Hash, b: &Hash) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Commitment (104 bytes)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commitment {
    pub root: Hash,
    pub total_checkpoints: u64,
    pub chain_tip: Hash,
    pub wasm_hash: Hash,
}

impl Commitment {
    pub const SIZE: usize = 104;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..32].copy_from_slice(&self.root);
        buf[32..40].copy_from_slice(&self.total_checkpoints.to_le_bytes());
        buf[40..72].copy_from_slice(&self.chain_tip);
        buf[72..104].copy_from_slice(&self.wasm_hash);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(OvpError::InvalidEncoding(format!(
                "commitment: expected {} bytes, got {}",
                Self::SIZE,
                data.len()
            )));
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&data[0..32]);
        let total_checkpoints = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let mut chain_tip = [0u8; 32];
        chain_tip.copy_from_slice(&data[40..72]);
        let mut wasm_hash = [0u8; 32];
        wasm_hash.copy_from_slice(&data[72..104]);
        Ok(Self {
            root,
            total_checkpoints,
            chain_tip,
            wasm_hash,
        })
    }
}

impl PartialEq for Commitment {
    fn eq(&self, other: &Self) -> bool {
        hash_eq(&self.root, &other.root)
            && self.total_checkpoints == other.total_checkpoints
            && hash_eq(&self.chain_tip, &other.chain_tip)
            && hash_eq(&self.wasm_hash, &other.wasm_hash)
    }
}

impl Eq for Commitment {}

// ---------------------------------------------------------------------------
// SignedCommitment (200 bytes)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedCommitment {
    pub commitment: Commitment,
    #[serde(with = "serde_byte64")]
    pub signature: [u8; 64],
    pub public_key: [u8; 32],
}

impl SignedCommitment {
    pub const SIZE: usize = 200;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..104].copy_from_slice(&self.commitment.to_bytes());
        buf[104..168].copy_from_slice(&self.signature);
        buf[168..200].copy_from_slice(&self.public_key);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(OvpError::InvalidEncoding(format!(
                "signed commitment: expected {} bytes, got {}",
                Self::SIZE,
                data.len()
            )));
        }
        let commitment = Commitment::from_bytes(&data[0..104])?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[104..168]);
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[168..200]);
        Ok(Self {
            commitment,
            signature,
            public_key,
        })
    }
}

// ---------------------------------------------------------------------------
// ProofNode (33 bytes)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofNode {
    pub hash: Hash,
    /// `true` means this sibling is on the LEFT: hash_combine(sibling, current).
    pub is_left: bool,
}

impl ProofNode {
    pub const SIZE: usize = 33;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..32].copy_from_slice(&self.hash);
        buf[32] = if self.is_left { 0x01 } else { 0x00 };
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(OvpError::InvalidEncoding(format!(
                "proof node: expected {} bytes, got {}",
                Self::SIZE,
                data.len()
            )));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[0..32]);
        let is_left = match data[32] {
            0x00 => false,
            0x01 => true,
            v => {
                return Err(OvpError::InvalidEncoding(format!(
                    "proof node is_left: expected 0x00 or 0x01, got 0x{v:02x}"
                )))
            }
        };
        Ok(Self { hash, is_left })
    }
}

// ---------------------------------------------------------------------------
// MerkleProof (variable: 108 + 33*N bytes)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf: Hash,
    pub leaf_index: u64,
    pub siblings: Vec<ProofNode>,
    pub root: Hash,
    pub wasm_hash: Hash,
}

impl MerkleProof {
    pub fn byte_size(&self) -> usize {
        108 + 33 * self.siblings.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let sibling_count = self.siblings.len() as u32;
        let size = 108 + 33 * self.siblings.len();
        let mut buf = Vec::with_capacity(size);

        buf.extend_from_slice(&self.leaf);
        buf.extend_from_slice(&self.leaf_index.to_le_bytes());
        buf.extend_from_slice(&sibling_count.to_be_bytes()); // BE per spec
        for node in &self.siblings {
            buf.extend_from_slice(&node.to_bytes());
        }
        buf.extend_from_slice(&self.root);
        buf.extend_from_slice(&self.wasm_hash);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 108 {
            return Err(OvpError::InvalidEncoding(
                "merkle proof: too short".to_string(),
            ));
        }
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&data[0..32]);
        let leaf_index = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let sibling_count = u32::from_be_bytes(data[40..44].try_into().unwrap()) as usize;

        let expected_size = 108 + 33 * sibling_count;
        if data.len() < expected_size {
            return Err(OvpError::InvalidEncoding(format!(
                "merkle proof: expected {} bytes, got {}",
                expected_size,
                data.len()
            )));
        }

        let mut siblings = Vec::with_capacity(sibling_count);
        for i in 0..sibling_count {
            let offset = 44 + 33 * i;
            siblings.push(ProofNode::from_bytes(&data[offset..offset + 33])?);
        }

        let tail_offset = 44 + 33 * sibling_count;
        let mut root = [0u8; 32];
        root.copy_from_slice(&data[tail_offset..tail_offset + 32]);
        let mut wasm_hash = [0u8; 32];
        wasm_hash.copy_from_slice(&data[tail_offset + 32..tail_offset + 64]);

        Ok(Self {
            leaf,
            leaf_index,
            siblings,
            root,
            wasm_hash,
        })
    }
}

// ---------------------------------------------------------------------------
// Challenge (16 bytes)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Challenge {
    pub checkpoint_index: u64,
    pub seed: u64,
}

impl Challenge {
    pub const SIZE: usize = 16;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..8].copy_from_slice(&self.checkpoint_index.to_le_bytes());
        buf[8..16].copy_from_slice(&self.seed.to_le_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(OvpError::InvalidEncoding(format!(
                "challenge: expected {} bytes, got {}",
                Self::SIZE,
                data.len()
            )));
        }
        let checkpoint_index = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let seed = u64::from_le_bytes(data[8..16].try_into().unwrap());
        Ok(Self {
            checkpoint_index,
            seed,
        })
    }
}

// ---------------------------------------------------------------------------
// TransitionProof
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransitionProof {
    pub merkle_proof: MerkleProof,
    pub previous_state: Vec<u8>,
    pub previous_state_hash: Hash,
    pub inputs: Vec<u8>,
    pub input_hash: Hash,
    pub claimed_state_hash: Hash,
    pub checkpoint_index: u64,
}

// ---------------------------------------------------------------------------
// FraudProof
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FraudProof {
    pub checkpoint_index: u64,
    pub commitment_root: Hash,
    pub merkle_proof: MerkleProof,
    pub previous_state: Vec<u8>,
    pub previous_hash: Hash,
    pub inputs: Vec<u8>,
    pub claimed_hash: Hash,
    pub computed_hash: Hash,
    pub challenger_id: Vec<u8>,
}

// ---------------------------------------------------------------------------
// DisputeProof (variable: 133 + proof_length bytes)
// ---------------------------------------------------------------------------

/// ZK proof type registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProofType {
    Mock = 0x00,
    RiscZeroGroth16 = 0x01,
    RiscZeroStark = 0x02,
    SP1 = 0x03,
    Binius = 0x04,
}

impl ProofType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x00 => Ok(Self::Mock),
            0x01 => Ok(Self::RiscZeroGroth16),
            0x02 => Ok(Self::RiscZeroStark),
            0x03 => Ok(Self::SP1),
            0x04 => Ok(Self::Binius),
            _ => Err(OvpError::InvalidEncoding(format!(
                "unknown proof type: 0x{v:02x}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeProof {
    pub proof_type: ProofType,
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Hash,
    pub input_hash: Hash,
    pub output_hash: Hash,
    pub wasm_hash: Hash,
}

impl DisputeProof {
    pub fn byte_size(&self) -> usize {
        133 + self.proof_bytes.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let proof_length = self.proof_bytes.len() as u32;
        let mut buf = Vec::with_capacity(self.byte_size());

        buf.push(self.proof_type as u8);
        buf.extend_from_slice(&proof_length.to_be_bytes()); // BE per spec
        buf.extend_from_slice(&self.proof_bytes);
        buf.extend_from_slice(&self.public_inputs);
        buf.extend_from_slice(&self.input_hash);
        buf.extend_from_slice(&self.output_hash);
        buf.extend_from_slice(&self.wasm_hash);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 133 {
            return Err(OvpError::InvalidEncoding(
                "dispute proof: too short".to_string(),
            ));
        }
        let proof_type = ProofType::from_u8(data[0])?;
        let proof_length = u32::from_be_bytes(data[1..5].try_into().unwrap()) as usize;

        let expected_size = 133 + proof_length;
        if data.len() < expected_size {
            return Err(OvpError::InvalidEncoding(format!(
                "dispute proof: expected {} bytes, got {}",
                expected_size,
                data.len()
            )));
        }

        let proof_bytes = data[5..5 + proof_length].to_vec();

        let t = 5 + proof_length;
        let mut public_inputs = [0u8; 32];
        public_inputs.copy_from_slice(&data[t..t + 32]);
        let mut input_hash = [0u8; 32];
        input_hash.copy_from_slice(&data[t + 32..t + 64]);
        let mut output_hash = [0u8; 32];
        output_hash.copy_from_slice(&data[t + 64..t + 96]);
        let mut wasm_hash = [0u8; 32];
        wasm_hash.copy_from_slice(&data[t + 96..t + 128]);

        Ok(Self {
            proof_type,
            proof_bytes,
            public_inputs,
            input_hash,
            output_hash,
            wasm_hash,
        })
    }
}

// ---------------------------------------------------------------------------
// CodeAttestation (136 bytes)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeAttestation {
    pub node_id: [u8; 32],
    pub wasm_hash: Hash,
    pub tick: u64,
    #[serde(with = "serde_byte64")]
    pub signature: [u8; 64],
}

impl CodeAttestation {
    pub const SIZE: usize = 136;

    /// The 72-byte message that is signed: node_id || wasm_hash || tick_LE.
    pub fn sign_message(&self) -> [u8; 72] {
        let mut msg = [0u8; 72];
        msg[0..32].copy_from_slice(&self.node_id);
        msg[32..64].copy_from_slice(&self.wasm_hash);
        msg[64..72].copy_from_slice(&self.tick.to_le_bytes());
        msg
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..32].copy_from_slice(&self.node_id);
        buf[32..64].copy_from_slice(&self.wasm_hash);
        buf[64..72].copy_from_slice(&self.tick.to_le_bytes());
        buf[72..136].copy_from_slice(&self.signature);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(OvpError::InvalidEncoding(format!(
                "code attestation: expected {} bytes, got {}",
                Self::SIZE,
                data.len()
            )));
        }
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&data[0..32]);
        let mut wasm_hash = [0u8; 32];
        wasm_hash.copy_from_slice(&data[32..64]);
        let tick = u64::from_le_bytes(data[64..72].try_into().unwrap());
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[72..136]);
        Ok(Self {
            node_id,
            wasm_hash,
            tick,
            signature,
        })
    }
}

// ---------------------------------------------------------------------------
// Dispute outcome types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisputeOutcome {
    DefenderWins,
    ChallengerWins { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FraudResult {
    FraudConfirmed(Box<FraudProof>),
    NoFraud { checkpoint_index: u64 },
}

impl PartialEq for FraudProof {
    fn eq(&self, other: &Self) -> bool {
        self.checkpoint_index == other.checkpoint_index
            && hash_eq(&self.commitment_root, &other.commitment_root)
            && hash_eq(&self.claimed_hash, &other.claimed_hash)
            && hash_eq(&self.computed_hash, &other.computed_hash)
    }
}

impl Eq for FraudProof {}
