use thiserror::Error;

#[derive(Debug, Error)]
pub enum OvpError {
    #[error("invalid proof: {0}")]
    InvalidProof(String),

    #[error("merkle proof verification failed")]
    MerkleVerificationFailed,

    #[error("root mismatch: proof root does not match commitment root")]
    RootMismatch,

    #[error("transition hash mismatch")]
    TransitionHashMismatch,

    #[error("previous state hash mismatch")]
    PreviousStateHashMismatch,

    #[error("input hash mismatch")]
    InputHashMismatch,

    #[error("fraud detected: computed state does not match claimed state")]
    FraudDetected,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),

    #[error("index out of bounds: {index} >= {length}")]
    IndexOutOfBounds { index: u64, length: u64 },

    #[error("invalid dispute phase: expected {expected}, got {got}")]
    InvalidDisputePhase { expected: String, got: String },

    #[error("dispute timeout: {0}")]
    DisputeTimeout(String),

    #[error("code integrity check failed")]
    CodeIntegrityFailed,

    #[error("no fraud found")]
    NoFraudFound,

    #[error("empty commitment")]
    EmptyCommitment,
}

pub type Result<T> = std::result::Result<T, OvpError>;
