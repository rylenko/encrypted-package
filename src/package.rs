use crate::error::{
	CheckSignatureError, CheckedSerializeError, DecryptError, NewError,
	ReceiveError, SendError, SignError, ValidateSizeError,
};

macro_rules! receive_doc {
	() => {
		"Receives bytes from a `r` with `size_limit` limit and deserializes into the
structure.

See [module level documentation](crate) for more algorithm details.
"
	};
}

macro_rules! send_doc {
	() => {
		"Sends `self` to `w`.

See [module level documentation](crate) for more algorithm details.
"
	};
}

/// Encrypted package struct. `PD` is public data type, which doesn't encrypt.
/// `D` is private data type for decryption. `C` is config.
///
/// See [the module level documentation](crate) and
/// [DefaultConfig](crate::config::DefaultConfig) for more.
#[derive(serde::Deserialize, serde::Serialize)]
pub struct Package<PD, D, C> {
	config: C,
	public_data: Option<PD>,
	#[serde(skip)]
	session: Box<[u8]>,
	e_session: Box<[u8]>,
	#[serde(skip)]
	#[serde(default = "Option::default")]
	data: Option<D>,
	e_data_bytes: Box<[u8]>,
	#[serde(skip)]
	sender_public_key_pem: Box<[u8]>,
	e_sender_public_key_pem: Box<[u8]>,
	#[serde(skip)]
	signature: Box<[u8]>,
	e_signature: Box<[u8]>,
	#[cfg(feature = "proof-of-work")]
	nonce: u64,
}

impl<PD, D, C> Package<PD, D, C>
where
	PD: serde::de::DeserializeOwned + serde::Serialize,
	D: serde::de::DeserializeOwned + serde::Serialize,
	C: crate::config::Config + serde::de::DeserializeOwned + serde::Serialize,
{
	/// Creates a new encrypted package with `config`.
	///
	/// See also: [DefaultConfig](crate::config::DefaultConfig).
	#[cfg_attr(
		feature = "tracing",
		tracing::instrument(skip(recipient_public_key, public_data, data))
	)]
	pub fn new(
		recipient_public_key: &openssl::rsa::Rsa<openssl::pkey::Public>,
		public_data: Option<PD>,
		data: D,
		config: C,
	) -> Result<Self, NewError> {
		// Generate and encrypt a session
		let session =
			crate::helpers::generate_random_bytes(config.session_length())?
				.into_boxed_slice();
		let mut e_session =
			vec![0; recipient_public_key.size() as usize].into_boxed_slice();
		recipient_public_key.public_encrypt(
			&session,
			&mut e_session,
			openssl::rsa::Padding::PKCS1_OAEP,
		)?;

		// Make `Self`
		let mut rv = Self {
			config,
			public_data,
			session,
			e_session,
			data: None,
			e_data_bytes: Default::default(),
			sender_public_key_pem: Default::default(),
			e_sender_public_key_pem: Default::default(),
			signature: Default::default(),
			e_signature: Default::default(),
			#[cfg(feature = "proof-of-work")]
			nonce: 0,
		};

		// Serialize a encrypt data bytes
		rv.e_data_bytes = rv
			.make_aes_cipher()
			.encrypt(&bincode::serialize(&data)?)?
			.into_boxed_slice();
		rv.data = Some(data);
		Ok(rv)
	}

	#[cfg(feature = "async")]
	#[cfg_attr(feature = "doc_cfg", doc(cfg(feature = "async")))]
	#[cfg_attr(feature = "tracing", tracing::instrument(skip(r)))]
	#[doc = receive_doc!()]
	pub async fn areceive<R: tokio::io::AsyncReadExt + Unpin>(
		r: &mut R,
		size_limit: Option<usize>,
	) -> Result<Self, ReceiveError> {
		// Receive and validate a size
		let size = {
			let mut be_bytes_buffer = [0; 8];
			r.read_exact(&mut be_bytes_buffer)
				.await
				.map_err(ReceiveError::ReadSize)?;
			usize::from_be_bytes(be_bytes_buffer)
		};
		Self::validate_size(size, size_limit)?;

		// Receive and deserialize bytes
		let mut bytes_buffer = vec![0; size].into_boxed_slice();
		r.read_exact(&mut bytes_buffer)
			.await
			.map_err(ReceiveError::ReadBytes)?;
		Ok(bincode::deserialize(&bytes_buffer)?)
	}

	#[cfg_attr(feature = "tracing", tracing::instrument(skip(r)))]
	#[doc = receive_doc!()]
	pub fn receive<R: std::io::Read>(
		r: &mut R,
		size_limit: Option<usize>,
	) -> Result<Self, ReceiveError> {
		// Receive and validate a size
		let size = {
			let mut be_bytes_buffer = [0; 8];
			r.read_exact(&mut be_bytes_buffer)
				.map_err(ReceiveError::ReadSize)?;
			usize::from_be_bytes(be_bytes_buffer)
		};
		Self::validate_size(size, size_limit)?;

		// Receive and deserialize bytes
		let mut bytes_buffer = vec![0; size].into_boxed_slice();
		r.read_exact(&mut bytes_buffer).map_err(ReceiveError::ReadBytes)?;
		Ok(bincode::deserialize(&bytes_buffer)?)
	}

	fn validate_size(
		size: usize,
		limit: Option<usize>,
	) -> Result<(), ValidateSizeError> {
		if size > isize::MAX as usize {
			return Err(ValidateSizeError::Invalid);
		}
		if let Some(limit) = limit {
			#[cfg(feature = "tracing")]
			if limit > isize::MAX as usize {
				tracing::warn!(
					"Size limit {limit} > isize::MAX, so makes no sense."
				);
			}
			if size > limit {
				return Err(ValidateSizeError::Limit);
			}
		}
		Ok(())
	}

	/// Accessor for config.
	#[inline]
	#[must_use]
	pub fn config(&self) -> &C {
		&self.config
	}

	/// Accessor for data.
	#[inline]
	#[must_use]
	pub fn data(&self) -> Option<&D> {
		self.data.as_ref()
	}

	/// Accessor for public data.
	#[inline]
	#[must_use]
	pub fn public_data(&self) -> Option<&PD> {
		self.public_data.as_ref()
	}

	#[cfg(feature = "async")]
	#[cfg_attr(feature = "doc_cfg", doc(cfg(feature = "async")))]
	#[cfg_attr(feature = "tracing", tracing::instrument(skip(self, w), ret))]
	#[doc = send_doc!()]
	pub async fn asend<W: tokio::io::AsyncWriteExt + Unpin>(
		&self,
		w: &mut W,
		size_limit: Option<usize>,
	) -> Result<(), SendError> {
		// Serialize, send a size and bytes
		let bytes = self.checked_serialize(size_limit)?;
		w.write_all(&bytes.len().to_be_bytes())
			.await
			.map_err(SendError::WriteSize)?;
		w.write_all(&bytes).await.map_err(SendError::WriteBytes)?;
		Ok(())
	}

	#[cfg_attr(feature = "tracing", tracing::instrument(skip(self, w), ret))]
	#[doc = send_doc!()]
	pub fn send<W: std::io::Write>(
		&self,
		w: &mut W,
		size_limit: Option<usize>,
	) -> Result<(), SendError> {
		// Serialize, send a size and bytes
		let bytes = self.checked_serialize(size_limit)?;
		w.write_all(&bytes.len().to_be_bytes())
			.map_err(SendError::WriteSize)?;
		w.write_all(&bytes).map_err(SendError::WriteBytes)?;
		Ok(())
	}

	/// With the [`private_key`](openssl::rsa::Rsa<openssl::pkey::Private>)
	/// it decrypts data.
	#[cfg_attr(feature = "tracing", tracing::instrument(skip_all, ret))]
	pub fn decrypt(
		&mut self,
		private_key: &openssl::rsa::Rsa<openssl::pkey::Private>,
	) -> Result<(), DecryptError> {
		// Decrypt a session
		self.session = {
			let mut session = vec![0; private_key.size() as usize];
			private_key.private_decrypt(
				&self.e_session,
				&mut session,
				openssl::rsa::Padding::PKCS1_OAEP,
			)?;
			session.truncate(self.config.session_length());
			session.into_boxed_slice()
		};

		// Decrypt a sender's public key PEM
		self.sender_public_key_pem = self
			.make_aes_cipher()
			.decrypt(&self.e_sender_public_key_pem)
			.map_err(DecryptError::SenderPublicKeyPem)?
			.into_boxed_slice();

		// Decrypt a signature
		self.signature = self
			.make_aes_cipher()
			.decrypt(&self.e_signature)
			.map_err(DecryptError::Signature)?
			.into_boxed_slice();

		// Decrypt and deserialize data bytes
		self.data = {
			let data_bytes = self
				.make_aes_cipher()
				.decrypt(&self.e_data_bytes)
				.map_err(DecryptError::DataBytes)?;
			Some(bincode::deserialize(&data_bytes)?)
		};
		Ok(())
	}

	/// Generates a proof-of-work with difficulty
	/// `self.config().proof_of_work_difficulty()`.
	///
	/// May take a long time. It is better to use this in conjunction with
	/// async blocking code spawner.
	#[cfg(feature = "proof-of-work")]
	#[cfg_attr(feature = "doc_cfg", doc(cfg(feature = "proof-of-work")))]
	#[cfg_attr(
		feature = "tracing",
		tracing::instrument(
			skip(self),
			fields(difficulty = self.config.proof_of_work_difficulty()),
		),
	)]
	pub fn generate_proof_of_work(&mut self) {
		while !self.check_proof_of_work() {
			self.nonce += 1;
		}
	}

	/// Signs the current hash with the
	/// [`private_key`](openssl::rsa::Rsa<openssl::pkey::Private>).
	#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
	pub fn sign(
		&mut self,
		sender_private_key: &openssl::rsa::Rsa<openssl::pkey::Private>,
	) -> Result<(), SignError> {
		// Create PKey
		let pkey = openssl::pkey::PKey::from_rsa(sender_private_key.clone())
			.map_err(SignError::PkeyFromPrivateKey)?;

		// Create signer, set padding to it, update it and sign
		let mut signer = openssl::sign::Signer::new(
			openssl::hash::MessageDigest::sha256(),
			&pkey,
		)
		.map_err(SignError::SignerFromPkey)?;
		signer
			.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
			.map_err(SignError::SetPadding)?;
		signer
			.update(&self.compute_hash())
			.map_err(SignError::UpdateSigner)?;
		self.signature =
			signer.sign_to_vec().map_err(SignError::Sign)?.into_boxed_slice();

		// Encrypt signature
		self.e_signature = self
			.make_aes_cipher()
			.encrypt(&self.signature)
			.map_err(SignError::EncryptSignature)?
			.into_boxed_slice();

		// Get public key PEM from private key
		self.sender_public_key_pem = sender_private_key
			.public_key_to_pem()
			.map_err(SignError::PrivateKeyToPublicKeyPem)?
			.into_boxed_slice();

		// Encrypt public key PEM
		self.e_sender_public_key_pem = self
			.make_aes_cipher()
			.encrypt(&self.sender_public_key_pem)
			.map_err(SignError::EncryptSignature)?
			.into_boxed_slice();
		Ok(())
	}

	/// Checks what current hash's hex starts with
	/// `self.config().proof_of_work_difficulty()` zeros.
	#[cfg(feature = "proof-of-work")]
	#[must_use]
	pub fn check_proof_of_work(&self) -> bool {
		let difficulty = "0".repeat(self.config.proof_of_work_difficulty());
		hex::encode(self.compute_hash()).starts_with(&difficulty)
	}

	/// Checks that the sender has [signed](Package::sign) current hash with
	/// his private key.
	#[cfg_attr(feature = "tracing", tracing::instrument(skip(self), ret))]
	pub fn check_signature(&self) -> Result<bool, CheckSignatureError> {
		// Convert sender public PEM to PKey
		let sender_public_key = openssl::rsa::Rsa::public_key_from_pem(
			&self.sender_public_key_pem,
		)
		.map_err(CheckSignatureError::PublicKeyFromPem)?;
		let pkey = openssl::pkey::PKey::from_rsa(sender_public_key)
			.map_err(CheckSignatureError::PkeyFromPublicKey)?;

		// Create verifier, set padding to it, update it and verify
		let mut verifier = openssl::sign::Verifier::new(
			openssl::hash::MessageDigest::sha256(),
			&pkey,
		)
		.map_err(CheckSignatureError::VerifierFromPkey)?;
		verifier
			.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
			.map_err(CheckSignatureError::SetPadding)?;
		verifier
			.update(&self.compute_hash())
			.map_err(CheckSignatureError::UpdateVerifier)?;
		verifier.verify(&self.signature).map_err(CheckSignatureError::Verify)
	}

	/// Same as [`bincode::serialize`], but with size limit check.
	#[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
	fn checked_serialize(
		&self,
		size_limit: Option<usize>,
	) -> Result<Vec<u8>, CheckedSerializeError> {
		use bincode::Options as _;

		let options = bincode::DefaultOptions::new()
			.with_fixint_encoding()
			.allow_trailing_bytes();
		if let Some(l) = size_limit {
			Ok(options.with_limit(l as u64).serialize(self)?)
		} else {
			Ok(options.serialize(self)?)
		}
	}

	/// Calculates the current hash of the package.
	#[must_use]
	fn compute_hash(&self) -> [u8; 32] {
		let parts = [
			&*self.e_session,
			&*self.e_data_bytes,
			#[cfg(feature = "proof-of-work")]
			&self.nonce.to_be_bytes(),
		];
		openssl::sha::sha256(&parts.concat())
	}

	/// Creates `aes::Cipher`.
	#[inline]
	#[must_use]
	fn make_aes_cipher(&self) -> crate::aes::Cipher<'_> {
		crate::aes::Cipher::new(
			&self.session,
			self.config.aes_iv(),
			self.config.aes_aad(),
		)
	}
}
