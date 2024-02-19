use anyhow::{Context as _, Result};

pub fn set_global_default() -> Result<()> {
	use tracing_subscriber::layer::SubscriberExt;

	let subscriber = tracing_subscriber::Registry::default()
		.with(tracing_subscriber::EnvFilter::new(super::globals::LOG_LEVEL))
		.with(tracing_bunyan_formatter::JsonStorageLayer)
		.with(tracing_bunyan_formatter::BunyanFormattingLayer::new(
			"test".to_owned(),
			|| std::io::stdout(),
		));
	tracing::subscriber::set_global_default(subscriber)
		.context("Failed to set.")
}
