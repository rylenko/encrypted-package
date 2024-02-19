//! All you need to configure encrypted packages.

use crate::error::{BuildDefaultConfigError, DefaultDefaultConfigError};

macro_rules! config_trait_body {
	() => {
		/// Length of session (key for AES encryption of all data).
		fn session_length(&self) -> usize;

		/// Initialization vector for AES.
		fn aes_iv(&self) -> &[u8];

		/// Authentication associated data for AES.
		fn aes_aad(&self) -> &[u8];

		/// Proof of work difficulty (zeros count in the beggining of proof of
		/// work string).
		#[cfg(feature = "proof-of-work")]
		fn proof_of_work_difficulty(&self) -> usize;
	};
}

macro_rules! setter {
	($field:ident: $value_type:ty) => {
		#[doc = concat!("Sets the new ", stringify!($field), " .")]
		pub fn $field(mut self, value: $value_type) -> Self {
			self.$field = Some(value);
			self
		}
	};
}

/// Trait for configs with useful fields.
#[cfg(feature = "tracing")]
pub trait Config: std::fmt::Debug {
	config_trait_body!();
}

/// Trait for configs with useful fields.
#[cfg(not(feature = "tracing"))]
pub trait Config {
	config_trait_body!();
}

/// Default config for [`Package`](crate::Package).
///
/// # Examples
///
/// ```rust
/// # fn main() -> anyhow::Result<()> {
/// use encrypted_package::Config as _;
/// let config = encrypted_package::DefaultConfig::try_default()?;
/// assert_eq!(config.aes_iv().len(), 16);
/// assert_eq!(
/// 	config.session_length(),
/// 	encrypted_package::consts::SESSION_RANDOM_BYTES_DEFAULT_LENGTH,
/// );
/// #     Ok(())
/// # }
/// ```
///
/// ```rust
/// # const IV: [u8; 16] =
/// #    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
/// # const AAD: [u8; 3] = [1, 2, 3];
/// # fn main() -> anyhow::Result<()> {
/// use encrypted_package::Config as _;
/// let config = encrypted_package::DefaultConfig::builder()
/// 	.session_length(100)
/// 	.aes_iv(IV.to_vec())
/// 	.aes_aad(AAD.to_vec())
/// 	.build()?;
/// assert_eq!(config.session_length(), 100);
/// assert_eq!(config.aes_iv(), IV);
/// assert_eq!(config.aes_aad(), AAD);
/// #     Ok(())
/// # }
/// ```
#[cfg_attr(feature = "tracing", derive(Debug))]
#[derive(serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub struct DefaultConfig {
	session_length: usize,
	aes_iv: Vec<u8>,
	aes_aad: Vec<u8>,
	#[cfg(feature = "proof-of-work")]
	proof_of_work_difficulty: usize,
}

impl DefaultConfig {
	/// Creates default [`DefaultConfig`].
	#[inline]
	pub fn try_default() -> Result<Self, DefaultDefaultConfigError> {
		Ok(Self::builder().build()?)
	}

	/// Creates "empty" [`DefaultConfigBuilder`].
	#[inline]
	#[must_use]
	pub fn builder() -> DefaultConfigBuilder {
		DefaultConfigBuilder::default()
	}
}

impl Config for DefaultConfig {
	#[inline]
	#[must_use]
	fn session_length(&self) -> usize {
		self.session_length
	}

	#[inline]
	#[must_use]
	fn aes_iv(&self) -> &[u8] {
		&self.aes_iv
	}

	#[inline]
	#[must_use]
	fn aes_aad(&self) -> &[u8] {
		&self.aes_aad
	}

	#[cfg(feature = "proof-of-work")]
	#[inline]
	#[must_use]
	fn proof_of_work_difficulty(&self) -> usize {
		self.proof_of_work_difficulty
	}
}

/// Builder for [`DefaultConfig`]. See [`DefaultConfig`] for more details.
#[derive(Default)]
#[non_exhaustive]
pub struct DefaultConfigBuilder {
	session_length: Option<usize>,
	aes_iv: Option<Vec<u8>>,
	aes_aad: Option<Vec<u8>>,
	#[cfg(feature = "proof-of-work")]
	proof_of_work_difficulty: Option<usize>,
}

impl DefaultConfigBuilder {
	setter!(session_length: usize);

	setter!(aes_iv: Vec<u8>);

	setter!(aes_aad: Vec<u8>);

	#[cfg(feature = "proof-of-work")]
	setter!(proof_of_work_difficulty: usize);

	/// Builds new config
	#[cfg_attr(feature = "tracing", tracing::instrument(skip(self), ret))]
	pub fn build(self) -> Result<DefaultConfig, BuildDefaultConfigError> {
		// Get initialization vector
		let aes_iv = if let Some(iv) = self.aes_iv {
			iv
		} else {
			crate::helpers::generate_random_bytes(16)?
		};

		// Get proof of work difficulty
		#[cfg(feature = "proof-of-work")]
		let proof_of_work_difficulty = match self.proof_of_work_difficulty {
			Some(d) if d > 32 => {
				return Err(
					BuildDefaultConfigError::InvalidProofOfWorkDifficulty(d),
				);
			}
			Some(d) => d,
			None => crate::consts::PROOF_OF_WORK_DEFAULT_DIFFICULTY,
		};

		Ok(DefaultConfig {
			session_length: self
				.session_length
				.unwrap_or(crate::consts::SESSION_RANDOM_BYTES_DEFAULT_LENGTH),
			aes_iv,
			aes_aad: self.aes_aad.unwrap_or_default(),
			#[cfg(feature = "proof-of-work")]
			proof_of_work_difficulty,
		})
	}
}
