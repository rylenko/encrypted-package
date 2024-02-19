/// Error for AES decryption function.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AesDecryptError {
	/// Failed to decrypt using `openssl` cipher.
	#[error("Failed to decrypt.")]
	Decrypt(#[from] openssl::error::ErrorStack),
}

/// Error for AES encryption function.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AesEncryptError {
	/// Failed to encrypt using `openssl` cipher.
	#[error("Failed to encrypt.")]
	Encrypt(#[from] openssl::error::ErrorStack),
}

/// Error for [build](crate::config::DefaultConfigBuilder::build).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildDefaultConfigError {
	/// Failed to generate random bytes for AES IV.
	#[error("Failed to generate IV.")]
	GenerateIv(#[from] GenerateRandomBytesError),
	/// Invalid proof of work difficulty
	#[error("Invalid proof of work difficulty: {0} > 32.")]
	InvalidProofOfWorkDifficulty(usize),
}

/// Error for serialization with size check function.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CheckedSerializeError {
	/// Failed to serialize with [`bincode`].
	#[error("Failed to serialize.")]
	Serialize(#[from] bincode::Error),
}

/// Error for signature checking function.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CheckSignatureError {
	/// Failed to convert a public key to PKey.
	#[error("Failed to convert a public key to PKey.")]
	PkeyFromPublicKey(#[source] openssl::error::ErrorStack),
	/// Failed to convert public key to PEM.
	#[error("Failed to convert PEM to a public key.")]
	PublicKeyFromPem(#[source] openssl::error::ErrorStack),
	/// Failed to set padding.
	#[error("Failed to set a padding.")]
	SetPadding(#[source] openssl::error::ErrorStack),
	/// Failed to update a verifier.
	#[error("Failed to update a verifier.")]
	UpdateVerifier(#[source] openssl::error::ErrorStack),
	/// Failed to convert a PKey to a verifier.
	#[error("Failed to convert a PKey to a verifier.")]
	VerifierFromPkey(#[source] openssl::error::ErrorStack),
	/// Failed to verify.
	#[error("Failed to verify.")]
	Verify(#[source] openssl::error::ErrorStack),
}

/// Error for [decrypt](crate::Package::decrypt).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecryptError {
	/// Failed to decrypt data bytes.
	#[error("Failed to decrypt data bytes.")]
	DataBytes(#[source] AesDecryptError),
	/// Failed to deserialize data.
	#[error("Failed to deserialize data.")]
	DeserializeData(#[from] bincode::Error),
	/// Failed to decrypt a sender public key PEM.
	#[error("Failed to decrypt a sender public key PEM.")]
	SenderPublicKeyPem(#[source] AesDecryptError),
	/// Failed to decrypt a session.
	#[error("Failed to decrypt a session.")]
	Session(#[from] openssl::error::ErrorStack),
	/// Failed to decrypt a signature.
	#[error("Failed to decrypt a signature.")]
	Signature(#[source] AesDecryptError),
}

/// Error for [try_default](crate::DefaultConfig::try_default).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DefaultDefaultConfigError {
	/// Failed to build the config.
	#[error("Failed to build the config.")]
	Build(#[from] BuildDefaultConfigError),
}

/// Error for random bytes generation function.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GenerateRandomBytesError {
	/// Failed to get random bytes.
	#[error("Failed to get random bytes.")]
	GetRandom(#[from] getrandom::Error),
}

/// Error for [new](crate::Package::new).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NewError {
	/// Failed to make the default config.
	#[error("Failed to make the default config.")]
	DefaultDefaultConfig(#[from] DefaultDefaultConfigError),
	/// Failed to encrypt a data bytes.
	#[error("Failed to encrypt a data bytes.")]
	EncryptDataBytes(#[from] AesEncryptError),
	/// Failed to encrypt a session.
	#[error("Failed to encrypt a session.")]
	EncryptSession(#[from] openssl::error::ErrorStack),
	/// Failed to generate a session.
	#[error("Failed to generate a session.")]
	GenerateSession(#[from] GenerateRandomBytesError),
	/// Failed to serialize a data.
	#[error("Failed to serialize a data.")]
	SerializeData(#[from] bincode::Error),
}

/// Error for [receive](crate::Package::receive) and
/// [areceive](crate::Package::areceive) if "async" feature is enabled.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReceiveError {
	/// Failed to deserialize bytes.
	#[error("Failed to deserialize bytes.")]
	Deserialize(#[from] bincode::Error),
	/// Failed to read bytes.
	#[error("Failed to read bytes.")]
	ReadBytes(#[source] std::io::Error),
	/// Failed to read a size.
	#[error("Failed to read a size.")]
	ReadSize(#[source] std::io::Error),
	/// Failed to validate a size.
	#[error("Failed to validate a size.")]
	ValidateSize(#[from] ValidateSizeError),
}

/// Error for [send](crate::Package::send) and
/// [asend](crate::Package::asend) if "async" feature is enabled.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SendError {
	/// Failed to serialize with a size check.
	#[error("Failed to serialize with a size check.")]
	CheckedSerialize(#[from] CheckedSerializeError),
	/// Failed to write bytes.
	#[error("Failed to write bytes.")]
	WriteBytes(#[source] std::io::Error),
	/// Failed to write size.
	#[error("Failed to write a size.")]
	WriteSize(#[source] std::io::Error),
}

/// Error for [sign](crate::Package::sign).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
	/// Failed to encrypt a sender public key PEM.
	#[error("Failed to encrypt a sender public key PEM.")]
	EncryptSenderPublicKeyPem(#[source] AesEncryptError),
	/// Failed to encrypt a signature.
	#[error("Failed to encrypt a signature.")]
	EncryptSignature(#[source] AesEncryptError),
	/// Failed to convert private key to a PKey.
	#[error("Failed to convert private key to a PKey.")]
	PkeyFromPrivateKey(#[source] openssl::error::ErrorStack),
	/// Failed to convert private key to a public key PEM.
	#[error("Failed to convert private key to a public key PEM.")]
	PrivateKeyToPublicKeyPem(#[source] openssl::error::ErrorStack),
	/// Failed to set a padding.
	#[error("Failed to set a padding.")]
	SetPadding(#[source] openssl::error::ErrorStack),
	/// Failed to sign.
	#[error("Failed to sign.")]
	Sign(#[source] openssl::error::ErrorStack),
	/// Failed to convert a PKey to a signer.
	#[error("Failed to convert a PKey to a signer.")]
	SignerFromPkey(#[source] openssl::error::ErrorStack),
	/// Failed to update a signer.
	#[error("Failed to update a signer.")]
	UpdateSigner(#[source] openssl::error::ErrorStack),
}

/// Error for size validation function.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ValidateSizeError {
	/// Greater than `isize::MAX`.
	#[error("Greater than isize::MAX.")]
	Invalid,
	/// Limit reached.
	#[error("Limit reached.")]
	Limit,
}
