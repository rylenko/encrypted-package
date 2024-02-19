use crate::error::GenerateRandomBytesError;

/// Generates `length` random bytes.
#[cfg_attr(feature = "tracing", tracing::instrument)]
pub fn generate_random_bytes(
	length: usize,
) -> Result<Vec<u8>, GenerateRandomBytesError> {
	let mut b = vec![0u8; length];
	getrandom::getrandom(&mut b)?;
	Ok(b)
}
