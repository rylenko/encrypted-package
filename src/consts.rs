//! All consts for encrypted package.

/// Length of session for AES encryption of all data.
pub const SESSION_RANDOM_BYTES_DEFAULT_LENGTH: usize = 32;

/// Difficulty of proof of work. Also count of zeros in the start of proof
/// of work string.
#[cfg(feature = "proof-of-work")]
pub const PROOF_OF_WORK_DEFAULT_DIFFICULTY: usize = 4;
