use anyhow::{Context as _, Result};

pub type Package = encrypted_package::Package<
	super::data::PublicData,
	super::data::Data,
	encrypted_package::DefaultConfig,
>;

pub fn create() -> Result<Package> {
	let mut package = Package::new(
		&super::globals::RECIPIENT_PUBLIC_KEY,
		Some(super::globals::PUBLIC_DATA.clone()),
		super::globals::DATA.clone(),
		encrypted_package::DefaultConfig::try_default()
			.context("Default config.")?,
	)
	.context("New package.")?;
	#[cfg(feature = "proof-of-work")]
	package.generate_proof_of_work();
	package.sign(&super::globals::SENDER_PRIVATE_KEY).context("Sign.")?;
	Ok(package)
}

pub fn assert(package: &mut Package) -> Result<()> {
	#[cfg(feature = "proof-of-work")]
	assert!(package.check_proof_of_work());
	assert_eq!(package.public_data(), Some(&*super::globals::PUBLIC_DATA));
	package
		.decrypt(&super::globals::RECIPIENT_PRIVATE_KEY)
		.context("Decrypt.")?;
	assert!(package.check_signature().context("Check signature.")?);
	assert_eq!(package.data(), Some(&*super::globals::DATA));
	Ok(())
}
