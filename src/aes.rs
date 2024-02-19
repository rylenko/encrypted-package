use crate::error::{AesDecryptError, AesEncryptError};

pub struct Cipher<'a> {
	inner: openssl::symm::Cipher,
	key: &'a [u8],
	iv: &'a [u8],
	aad: &'a [u8],
}

impl<'a> Cipher<'a> {
	#[inline]
	#[must_use]
	pub fn new(key: &'a [u8], iv: &'a [u8], aad: &'a [u8]) -> Self {
		Self { inner: openssl::symm::Cipher::aes_256_gcm(), key, iv, aad }
	}

	#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
	pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, AesEncryptError> {
		let mut tag = [0u8; 16];
		let encrypted_data = openssl::symm::encrypt_aead(
			self.inner,
			self.key,
			Some(self.iv),
			self.aad,
			data,
			&mut tag,
		)?;
		Ok([&encrypted_data, &tag[..]].concat())
	}

	#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
	pub fn decrypt(&self, slice: &[u8]) -> Result<Vec<u8>, AesDecryptError> {
		let data = &slice[..slice.len() - 16];
		let tag = &slice[slice.len() - 16..];
		Ok(openssl::symm::decrypt_aead(
			self.inner,
			self.key,
			Some(self.iv),
			self.aad,
			data,
			tag,
		)?)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const DATA: &[u8] = b"Hello, world!";
	const KEY: &[u8] = b"keykeykeykeykeykeykeykeykeykeyke";
	const IV: &[u8] = b"iviviviviviviviv";
	const AAD: &[u8] = b"123";

	#[test]
	fn test_encrypt_and_decrypt() {
		let cipher = Cipher::new(KEY, IV, AAD);
		let encrypted_data = cipher.encrypt(DATA).unwrap();
		assert_eq!(encrypted_data, [
			50, 123, 172, 2, 179, 218, 84, 145, 77, 89, 144, 171, 62, 168,
			165, 242, 101, 146, 215, 94, 241, 195, 59, 1, 195, 162, 132, 183,
			9,
		]);
		let decrypted_data = cipher.decrypt(&encrypted_data).unwrap();
		assert_eq!(decrypted_data, DATA);
	}
}
