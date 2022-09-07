/// TODO: add doc

// refer: arti-client/examples/hook-tcp.rs

use std::{net::SocketAddr, pin::Pin, task::{Context, Poll}};

use std::future::Future;
use std::io::Result as IoResult;


use tor_rtcompat::TcpListener;
use futures::{FutureExt, Stream, AsyncRead, AsyncWrite};

// use rand::{distributions::Alphanumeric, Rng};
// macro_rules! dbgd {
//     ($($arg:tt)* ) => (
//         tracing::info!($($arg)*) // comment out this line to disable log
//     );
// }

/// TODO: add doc
pub trait AsyncStreamTrait: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static> AsyncStreamTrait for T {}

/// TODO: add doc
pub type BoxTcpStream = Box<dyn AsyncStreamTrait>;

/// TODO: add doc
pub fn box_tcp_stream<T>(stream: T) -> BoxTcpStream 
where
    T: AsyncStreamTrait
{
    Box::new(stream)
}

/// A wrapper over a `TcpListener`.
pub struct BoxTcpListener<T> {
    inner: T,
}

impl <T> BoxTcpListener<T> {

    /// TODO: add doc
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}


type AcceptResult<T> = IoResult<(T, SocketAddr)>;

impl<T> TcpListener for BoxTcpListener<T>
where
    T: TcpListener,
{
    type TcpStream = BoxTcpStream;
    type Incoming = BoxIncoming<T::Incoming>;

    // This is also an async trait method (see earlier commentary).
    fn accept<'a, 'b>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = AcceptResult<Self::TcpStream>> + Send + 'b>>
    where
        'a: 'b,
        Self: 'b,
    {
        // As with other implementations, we just defer to `self.inner` and wrap the result.
        self.inner
            .accept()
            .inspect(|r| {
                if let Ok((_, addr)) = r {
                    println!("accepted connection from {}", addr)
                }
            })
            .map(|r| {
                r.map(|(stream, addr)| {
                    (
                        // CustomTcpStream {
                        //     inner: stream,
                        //     addr,
                        //     state: TcpState::Open,
                        // },
                        box_tcp_stream(stream),
                        addr,
                    )
                })
            })
            .boxed()
    }

    fn incoming(self) -> Self::Incoming {
        BoxIncoming {
            inner: self.inner.incoming(),
        }
    }

    fn local_addr(&self) -> IoResult<SocketAddr> {
        self.inner.local_addr()
    }
}

/// TODO: add doc
pub struct BoxIncoming<T> {
    inner: T,
}

impl<T, S> Stream for BoxIncoming<T>
where
    T: Stream<Item = IoResult<(S, SocketAddr)>> + Unpin,
    S: AsyncStreamTrait
{
    type Item = IoResult<(BoxTcpStream, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok((stream, addr)))) => Poll::Ready(Some(Ok((
                // CustomTcpStream {
                //     inner: stream,
                //     addr,
                //     state: TcpState::Open,
                // },
                box_tcp_stream(stream),
                addr,
            )))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}



// pub struct TcpDebug<S>(S, String);

// impl<S> TcpDebug<S> {
//     pub fn new(inner: S) -> Self {
//         let txid: String = rand::thread_rng()
//         .sample_iter(&Alphanumeric)
//         .take(7)
//         .map(char::from)
//         .collect();

//         let self0 = Self(inner, txid);
//         debug_tcp(&self0, "new", &());
//         self0
//     }
// }

// impl<S> Drop for TcpDebug<S> {
//     fn drop(&mut self) {
//         debug_tcp(&self, "drop", &());
//     }
// }


// impl<S> AsyncRead for TcpDebug<S> 
// where
//     S: AsyncRead + Unpin
// {
//     fn poll_read(
//             mut self: Pin<&mut Self>,
//             cx: &mut Context<'_>,
//             buf: &mut [u8],
//         ) -> Poll<IoResult<usize>> {
//         let r = Pin::new(&mut self.0).poll_read(cx, buf);
//         debug_tcp(&self.pointer, "poll_read", &r);
//         r
//     }
// }

// impl<S> AsyncWrite for TcpDebug<S> 
// where
//     S: AsyncWrite + Unpin
// {
//     fn poll_write(
//             mut self: Pin<&mut Self>,
//             cx: &mut Context<'_>,
//             buf: &[u8],
//         ) -> Poll<IoResult<usize>> {
//         let r = Pin::new(&mut self.0).poll_write(cx, buf);
//         debug_tcp(&self.pointer, "poll_close", &r);
//         r
//     }

//     fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
//         let r = Pin::new(&mut self.0).poll_flush(cx);
//         dbgd!("poll_flush {:?}", r);
//         debug_tcp(&self.pointer, "poll_close", &r);
//         r
//     }

//     fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
//         let r = Pin::new(&mut self.0).poll_close(cx);
//         debug_tcp(&self.pointer, "poll_close", &r);
//         r
//     }
// }

// fn debug_tcp<S, V: std::fmt::Debug>(obj: &TcpDebug<S>, func_name: &str, value: &V) {
//     debug_obj("TcpDebug", &obj.1, func_name, value);
// }

// fn debug_obj<T, V: std::fmt::Debug>(type_name: &str, obj: &T, func_name: &str, value: &V) 
// where
//     T: std::fmt::Display,
// {
//     // let type_name = std::any::type_name::<T>();
//     // let type_name = "TcpDebug";
//     dbgd!("[{}]-{}::{} [{:?}]", obj, type_name, func_name, value);
// }
