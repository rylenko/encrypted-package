/*!
A library that helps you send data in encrypted form.

# Features

### async

Adds [asend](Package::asend) and
[areceive](Package::areceive) for asynchronous sending and receiving.

### proof-of-work

Adds the ability to [generate](Package::generate_proof_of_work) and
[check](Package::check_proof_of_work) proof of work.

Depending on the difficulty of the proof, it takes time. It is better to
use this in conjunction with async blocking code spawner.

In addition, it increases the size of data transmitted by 8 bytes.

### tracing

Adds basic tracing with instrumentation. Example how to create a subscriber:

```no_run
# use anyhow::{Context as _, Result};
# fn main() -> Result<()> {
#     use tracing_subscriber::layer::SubscriberExt as _;
let subscriber = tracing_subscriber::Registry::default()
	.with(tracing_subscriber::EnvFilter::new("INFO"))
	.with(tracing_bunyan_formatter::JsonStorageLayer)
	.with(tracing_bunyan_formatter::BunyanFormattingLayer::new(
		"test".to_owned(),
		std::io::stdout,
	));
tracing::subscriber::set_global_default(subscriber).context("Failed to set.")
# }
```

# Algorithm

First it sends a data with a size of 8 bytes, which contains the size of
the [encrypted package](Package). Then it sends the
[encrypted package](Package) bytes.

# Specifications

- Encryption: RSA-PKCS1-OAEP, AES-GCM-256
- Signing: RSA-PKCS1-PSS
- Hashing: SHA-256

# Example (synchronous)

Sending [`Package`]:

```no_run
# fn main() -> anyhow::Result<()> {
#     let recipient_private_key = openssl::rsa::Rsa::generate(2048)?;
#     let recipient_public_key_pem =
#         recipient_private_key.public_key_to_pem()?;
#     let recipient_public_key =
#         openssl::rsa::Rsa::public_key_from_pem(&recipient_public_key_pem)?;
#     let sender_private_key = openssl::rsa::Rsa::generate(2048)?;
#     let mut stream = std::net::TcpStream::connect("127.0.0.1:8888")?;
let config = encrypted_package::DefaultConfig::try_default()?;
let mut package = encrypted_package::Package::new(
	&recipient_public_key, None::<Vec<u8>>, vec![1, 2, 3], config,
)?;
// If "proof-of-work" feature is enabled
// package.generate_proof_of_work();
package.sign(&sender_private_key)?;
package.send(&mut stream, None)?;
#     Ok(())
# }
```

Receiving [`Package`] (without decrypting):

```no_run
# fn main() -> anyhow::Result<()> {
#     let mut stream = std::net::TcpStream::connect("127.0.0.1:8888")?;
let package = encrypted_package::Package::<
	Vec<u8>, Vec<u8>, encrypted_package::DefaultConfig,
>::receive(&mut stream, None)?;
// If "proof-of-work" feature is enabled
// assert!(package.check_proof_of_work(), "Invalid proof of work.");
println!("{:?}", package.public_data());
#     Ok(())
# }
```

Receiving [`Package`] (with decrypting):

```no_run
# fn main() -> anyhow::Result<()> {
#     let private_key = openssl::rsa::Rsa::generate(2048)?;
#     let mut stream = std::net::TcpStream::connect("127.0.0.1:8888")?;
let mut package = encrypted_package::Package::
	<Vec<u8>, Vec<u8>, encrypted_package::DefaultConfig,
>::receive(&mut stream, None)?;
// If "proof-of-work" feature is enabled
// assert!(package.check_proof_of_work(), "Invalid proof of work.");
package.decrypt(&private_key)?;
assert!(package.check_signature()?, "Invalid signature.");
println!("{:?}\n{:?}", package.public_data(), package.data());
# Ok(())
# }
```
*/
#![allow(clippy::tabs_in_doc_comments)]
#![cfg_attr(doc, feature(doc_cfg))]
#![forbid(
	missing_docs,
	rustdoc::broken_intra_doc_links,
	unsafe_code,
	unstable_features
)]

mod aes;
pub mod config;
pub mod consts;
mod error;
mod helpers;
mod package;

pub use config::{Config, DefaultConfig};
pub use error::*;
pub use package::Package;
