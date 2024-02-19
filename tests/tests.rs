mod helpers;

use anyhow::{Context as _, Result};

#[test]
fn test_sync() -> Result<()> {
	#[cfg(feature = "tracing")]
	helpers::tracing_subscriber::set_global_default()
		.context("Set tracing subscriber.")?;

	let mut buf = helpers::rw_buf::RwBuf::new();

	// Create and send
	let package = helpers::package::create().context("Create.")?;
	assert!(package
		.send(&mut buf, Some(helpers::globals::INVALID_SIZE))
		.is_err());
	package
		.send(&mut buf, Some(helpers::globals::VALID_SIZE))
		.context("Send.")?;
	assert!(helpers::package::Package::receive(
		&mut buf.clone(),
		Some(helpers::globals::INVALID_SIZE),
	)
	.is_err());

	// Receive and assert
	let mut package = encrypted_package::Package::receive(
		&mut buf,
		Some(helpers::globals::VALID_SIZE),
	)
	.context("Receive.")?;
	helpers::package::assert(&mut package).context("Assert.")?;
	Ok(())
}

#[cfg(feature = "async")]
#[tokio::test]
async fn test_async() -> Result<()> {
	let mut buf = helpers::rw_buf::RwBuf::new();

	// Create and send
	let package = helpers::package::create().context("Create.")?;
	assert!(package
		.asend(&mut buf, Some(helpers::globals::INVALID_SIZE))
		.await
		.is_err());
	package
		.asend(&mut buf, Some(helpers::globals::VALID_SIZE))
		.await
		.context("Send.")?;
	assert!(helpers::package::Package::areceive(
		&mut buf.clone(),
		Some(helpers::globals::INVALID_SIZE)
	)
	.await
	.is_err());

	// Receive and assert
	let mut package = encrypted_package::Package::areceive(
		&mut buf,
		Some(helpers::globals::VALID_SIZE),
	)
	.await
	.context("Async receive.")?;
	helpers::package::assert(&mut package).context("Assert.")?;
	Ok(())
}
