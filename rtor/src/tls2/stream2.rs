
use std::fmt;
use std::io;
use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context, Poll};
use hyper::client::connect::{Connected, Connection};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};


pub enum Stream2<T1, T2> {
    S1(T1),
    S2(T2),
}

// ===== impl MaybeHttpsStream =====

impl<T1: fmt::Debug, T2: fmt::Debug> fmt::Debug for Stream2<T1, T2> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Stream2::S1(s) => f.debug_tuple("Http").field(s).finish(),
            Stream2::S2(s) => f.debug_tuple("Https").field(s).finish(),
        }
    }
}

impl<T> From<T> for Stream2<T, ()> {
    fn from(inner: T) -> Self {
        Stream2::S1(inner)
    }
}

impl<T1, T2> AsyncRead for Stream2<T1, T2> 
where
    T1: AsyncRead + AsyncWrite + Unpin,
    T2: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            Stream2::S1(s) => Pin::new(s).poll_read(cx, buf),
            Stream2::S2(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<T1, T2> AsyncWrite for Stream2<T1, T2> 
where
    T1: AsyncRead + AsyncWrite + Unpin,
    T2: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::get_mut(self) {
            Stream2::S1(s) => Pin::new(s).poll_write(cx, buf),
            Stream2::S2(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::get_mut(self) {
            Stream2::S1(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Stream2::S2(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Stream2::S1(s) => s.is_write_vectored(),
            Stream2::S2(s) => s.is_write_vectored(),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            Stream2::S1(s) => Pin::new(s).poll_flush(cx),
            Stream2::S2(s) => Pin::new(s).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            Stream2::S1(s) => Pin::new(s).poll_shutdown(cx),
            Stream2::S2(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub trait Connection2 {
    fn connected2(&self) -> Connected;
}


impl<T1, T2> Connection for Stream2<T1, T2> 
where
    T1: AsyncRead + AsyncWrite + Connection2 + Unpin,
    T2: AsyncRead + AsyncWrite + Connection2 + Unpin,
{
    fn connected(&self) -> Connected {
        match self {
            Stream2::S1(s) => s.connected2(),
            Stream2::S2(s) => s.connected2(),
        }
    }
}
