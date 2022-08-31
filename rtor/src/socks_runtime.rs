// refer: arti-client/examples/hook-tcp.rs

use std::{net::SocketAddr, pin::Pin, task::{Context, Poll}, marker::PhantomData};
use fast_socks5::client::{Socks5Stream, Config as Socks5Config};
use std::future::Future;
use std::io::Result as IoResult;
use tokio::{
    net::TcpStream as TokioStream, 
    // io::{AsyncRead as TokioAsyncRead, AsyncReadExt as TokioAsyncReadExt, AsyncWrite as TokioAsyncWrite, AsyncWriteExt as TokioAsyncWriteExt}
};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use tor_rtcompat::{CompoundRuntime, PreferredRuntime, TcpProvider, TcpListener};
use futures::{FutureExt, Stream, TryFutureExt};

pub type SocksRuntime = CompoundRuntime<PreferredRuntime, PreferredRuntime, SocksTcpProvider, PreferredRuntime, PreferredRuntime>;

pub fn create(socks_server: String, username: Option<String>, password: Option<String>,) -> std::io::Result<SocksRuntime> {
    let rt = PreferredRuntime::current()?;

    let tcp_rt = SocksTcpProvider { socks_server, username, password };

    let rt = CompoundRuntime::new(rt.clone(), rt.clone(), tcp_rt, rt.clone(), rt);

    Ok(rt)
}

#[derive(Clone)]
pub struct SocksTcpProvider {
    pub socks_server: String, // eg. `127.0.0.1:1080`

    pub username: Option<String>,

    pub password: Option<String>,
}

impl SocksTcpProvider {
    pub fn new(socks_server: String, username: Option<String>, password: Option<String>,) -> Self {
        Self { socks_server, username, password }
    }
}

type SocksTcpStream = Compat<Socks5Stream<TokioStream>>;

impl TcpProvider for SocksTcpProvider
{
    type TcpStream = SocksTcpStream;
    type TcpListener = SocksTcpListener;

    fn connect<'a, 'b, 'c>(
        &'a self,
        addr: &'b SocketAddr,
    ) -> Pin<Box<dyn Future<Output = IoResult<Self::TcpStream>> + Send + 'c>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        println!("====== try tcp connecting to {}", addr);
        let target_addr = addr.ip().to_string();
        let target_port = addr.port();
        let r = if let Some(username) = &self.username {
            let password = self.password.as_deref().unwrap_or_else(||"").to_owned();
            Socks5Stream::connect_with_password(
                &self.socks_server,
                target_addr,
                target_port,
                username.clone(),
                password,
                Socks5Config::default(),
            )
            .map_ok(|v|v.compat())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            .boxed()
        } else {
            Socks5Stream::connect(&self.socks_server, target_addr, target_port, Socks5Config::default())
            .map_ok(|v|v.compat())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            .boxed()
        };

        r
    }

    // This is also an async trait method (see above).
    fn listen<'a, 'b, 'c>(
        &'a self,
        addr: &'b SocketAddr,
    ) -> Pin<Box<dyn Future<Output = IoResult<Self::TcpListener>> + Send + 'c>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        println!("====== try tcp listening on {}", addr);
        PendingForever(PhantomData::default()).boxed()
    }
}

pub struct SocksTcpListener {
    addr: SocketAddr
}

type AcceptResult<T> = IoResult<(T, SocketAddr)>;

impl TcpListener for SocksTcpListener
{
    type TcpStream = SocksTcpStream;
    type Incoming = SocksTcpIncoming;

    fn accept<'a, 'b>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = AcceptResult<Self::TcpStream>> + Send + 'b>>
    where
        'a: 'b,
        Self: 'b,
    {
        PendingForever(PhantomData::default()).boxed()
    }

    fn incoming(self) -> Self::Incoming {
        SocksTcpIncoming {}
    }

    fn local_addr(&self) -> IoResult<SocketAddr> {
        Ok(self.addr.clone())
    }
}

pub struct SocksTcpIncoming { }

impl Stream for SocksTcpIncoming

{
    type Item = IoResult<(SocksTcpStream, SocketAddr)>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}

struct PendingForever<T>(PhantomData<T>);

impl<T> Future for PendingForever<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}
