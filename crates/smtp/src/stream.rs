//! Plain or TLS SMTP byte stream, plus a type-erased duplex used after STARTTLS.
use pin_project_lite::pin_project;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::server::TlsStream;

pin_project! {
    #[project = SmtpStreamProj]
    pub enum SmtpStream {
        Plain { #[pin] inner: TcpStream },
        Tls { #[pin] inner: TlsStream<TcpStream> },
    }
}

impl SmtpStream {
    pub fn plain(stream: TcpStream) -> Self {
        Self::Plain { inner: stream }
    }

    pub fn tls(stream: TlsStream<TcpStream>) -> Self {
        Self::Tls { inner: stream }
    }
}

impl AsyncRead for SmtpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.project() {
            SmtpStreamProj::Plain { inner } => AsyncRead::poll_read(inner, cx, buf),
            SmtpStreamProj::Tls { inner } => AsyncRead::poll_read(inner, cx, buf),
        }
    }
}

impl AsyncWrite for SmtpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.project() {
            SmtpStreamProj::Plain { inner } => AsyncWrite::poll_write(inner, cx, buf),
            SmtpStreamProj::Tls { inner } => AsyncWrite::poll_write(inner, cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            SmtpStreamProj::Plain { inner } => AsyncWrite::poll_flush(inner, cx),
            SmtpStreamProj::Tls { inner } => AsyncWrite::poll_flush(inner, cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            SmtpStreamProj::Plain { inner } => AsyncWrite::poll_shutdown(inner, cx),
            SmtpStreamProj::Tls { inner } => AsyncWrite::poll_shutdown(inner, cx),
        }
    }
}

/// Erases `AsyncRead + AsyncWrite` so STARTTLS can replace the transport.
pub struct BoxIo {
    inner: Pin<Box<dyn Erased>>,
}

trait Erased: Send {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>;
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>>;
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

impl<T> Erased for T
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, buf)
    }

    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(self, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(self, cx)
    }
}

impl BoxIo {
    pub fn new<T>(io: T) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self {
            inner: Box::pin(io),
        }
    }
}

impl AsyncRead for BoxIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().inner.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for BoxIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().inner.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().inner.as_mut().poll_shutdown(cx)
    }
}
