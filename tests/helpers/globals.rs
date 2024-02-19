lazy_static::lazy_static! {
	pub static ref DATA: super::data::Data
		= super::data::Data("Hello, world".to_owned());
	pub static ref PUBLIC_DATA: super::data::PublicData
		= super::data::PublicData(10);

	pub static ref SENDER_PRIVATE_KEY: openssl::rsa::Rsa<openssl::pkey::Private> =
		openssl::rsa::Rsa::private_key_from_pem(include_bytes!(
			"../keys/sender-private.pem"
		))
		.unwrap();
	pub static ref RECIPIENT_PRIVATE_KEY:
		openssl::rsa::Rsa<openssl::pkey::Private> =
			openssl::rsa::Rsa::private_key_from_pem(include_bytes!(
				"../keys/recipient-private.pem"
			))
			.unwrap();
	pub static ref RECIPIENT_PUBLIC_KEY:
		openssl::rsa::Rsa<openssl::pkey::Public> =
			openssl::rsa::Rsa::public_key_from_pem(
				&RECIPIENT_PRIVATE_KEY.public_key_to_pem().unwrap()
			)
			.unwrap();
}

#[cfg(feature = "tracing")]
pub const LOG_LEVEL: &str = "TRACE";

#[cfg(feature = "proof-of-work")]
pub const VALID_SIZE: usize = 1982;
#[cfg(not(feature = "proof-of-work"))]
pub const VALID_SIZE: usize = 1966;
pub const INVALID_SIZE: usize = VALID_SIZE - 1;
