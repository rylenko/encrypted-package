use std::io::Result;

#[derive(Clone, Default)]
pub struct RwBuf {
	inner: Vec<u8>,
}

impl RwBuf {
	#[inline]
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}
}

impl std::io::Read for RwBuf {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
		let size = std::cmp::min(self.inner.len(), buf.len());
		buf[..size].copy_from_slice(self.inner.drain(..size).as_slice());
		Ok(size)
	}
}

impl std::io::Write for RwBuf {
	fn write(&mut self, buf: &[u8]) -> Result<usize> {
		self.inner.extend_from_slice(buf);
		Ok(buf.len())
	}

	#[inline]
	fn flush(&mut self) -> Result<()> {
		Ok(())
	}
}

#[cfg(feature = "async")]
impl tokio::io::AsyncRead for RwBuf {
	fn poll_read(
		mut self: std::pin::Pin<&mut Self>,
		_: &mut std::task::Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<Result<()>> {
		let size = std::cmp::min(self.inner.len(), buf.capacity());
		buf.put_slice(self.inner.drain(..size).as_slice());
		std::task::Poll::Ready(Ok(()))
	}
}

#[cfg(feature = "async")]
impl tokio::io::AsyncWrite for RwBuf {
	fn poll_write(
		mut self: std::pin::Pin<&mut Self>,
		_: &mut std::task::Context<'_>,
		buf: &[u8],
	) -> std::task::Poll<Result<usize>> {
		self.inner.extend_from_slice(buf);
		std::task::Poll::Ready(Ok(buf.len()))
	}

	#[inline]
	fn poll_flush(
		self: std::pin::Pin<&mut Self>,
		_: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<()>> {
		std::task::Poll::Ready(Ok(()))
	}

	#[inline]
	fn poll_shutdown(
		self: std::pin::Pin<&mut Self>,
		_: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<()>> {
		std::task::Poll::Ready(Ok(()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_read_and_write() -> Result<()> {
		let mut rwbuf = RwBuf::new();

		assert_eq!(std::io::Write::write(&mut rwbuf, &[1, 3, 5, 7, 9])?, 5);
		assert_eq!(rwbuf.inner, [1, 3, 5, 7, 9]);
		assert_eq!(std::io::Write::write(&mut rwbuf, &[11])?, 1);
		assert_eq!(rwbuf.inner, [1, 3, 5, 7, 9, 11]);

		let mut buf = [0u8; 6];
		assert_eq!(std::io::Read::read(&mut rwbuf, &mut buf)?, 6);
		assert_eq!(buf, [1, 3, 5, 7, 9, 11]);
		assert!(rwbuf.inner.is_empty());
		Ok(())
	}

	#[cfg(feature = "async")]
	#[tokio::test]
	async fn test_async_read_and_write() -> Result<()> {
		let mut rwbuf = RwBuf::new();

		assert_eq!(
			tokio::io::AsyncWriteExt::write(&mut rwbuf, &[1, 3, 5, 7, 9])
				.await?,
			5,
		);
		assert_eq!(rwbuf.inner, [1, 3, 5, 7, 9]);
		assert_eq!(
			tokio::io::AsyncWriteExt::write(&mut rwbuf, &[11]).await?,
			1
		);
		assert_eq!(rwbuf.inner, [1, 3, 5, 7, 9, 11]);

		let mut buf = [0u8; 6];
		assert_eq!(
			tokio::io::AsyncReadExt::read(&mut rwbuf, &mut buf).await?,
			6
		);
		assert_eq!(buf, [1, 3, 5, 7, 9, 11]);
		assert!(rwbuf.inner.is_empty());
		Ok(())
	}
}
