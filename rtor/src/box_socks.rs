// refer: arti-client/examples/hook-tcp.rs

use std::{net::SocketAddr, pin::Pin};
use fast_socks5::client::{Socks5Stream, Config as Socks5Config};
use tokio_util::compat::TokioAsyncReadCompatExt;
use std::future::Future;
use std::io::Result as IoResult;
// use tokio::{
//     net::TcpStream as TokioStream, 
//     // io::{AsyncRead as TokioAsyncRead, AsyncReadExt as TokioAsyncReadExt, AsyncWrite as TokioAsyncWrite, AsyncWriteExt as TokioAsyncWriteExt}
// };
#[cfg(feature = "tokio")]
use tokio_util::compat::TokioAsyncReadCompatExt;
use tor_rtcompat::{CompoundRuntime, TcpProvider, Runtime};
use futures::{FutureExt, TryFutureExt};

use crate::box_tcp::{BoxTcpStream, box_tcp_stream, BoxTcpListener};

/// TODO: add doc
pub type SocksRuntime<R> = CompoundRuntime<R, R, SocksTcpProvider<R>, R, R>;

/// TODO: add doc
pub fn create(socks_server: String, username: Option<String>, password: Option<String>,) -> std::io::Result<SocksRuntime<tor_rtcompat::PreferredRuntime>> 
{

    // 不推荐用这种方式创建runtime，因为如果tokio 还没初始化会失败
    let rt = tor_rtcompat::PreferredRuntime::current()?;

    // 推荐用这种方式，但是编译出错
    // TODO: fix compile
    // let rt = create_runtime()?;

    create_with_runtime(socks_server, username, password, rt)
}

/// TODO: add doc
pub fn create_with_runtime<R>(socks_server: String, username: Option<String>, password: Option<String>, rt: R) -> std::io::Result<CompoundRuntime<R, R, SocksTcpProvider<R>, R, R>> 
where
    R: Runtime
{
    let tcp_rt = SocksTcpProvider { socks_server, username, password, rt: rt.clone() };

    let rt = CompoundRuntime::new(rt.clone(), rt.clone(), tcp_rt, rt.clone(), rt);

    Ok(rt)
}

// fn create_runtime() -> std::io::Result<impl Runtime> {
//     // cfg_if::cfg_if! {
//     //     if #[cfg(all(feature="tokio", feature="native-tls"))] {
//     //     use tor_rtcompat::tokio::TokioNativeTlsRuntime as ChosenRuntime;
//     //     } else if #[cfg(all(feature="tokio", feature="rustls"))] {
//     //         use tor_rtcompat::tokio::TokioRustlsRuntime as ChosenRuntime;
//     //     } else if #[cfg(all(feature="async-std", feature="native-tls"))] {
//     //         use tor_rtcompat::async_std::AsyncStdNativeTlsRuntime as ChosenRuntime;
//     //     } else if #[cfg(all(feature="async-std", feature="rustls"))] {
//     //         use tor_rtcompat::async_std::AsyncStdRustlsRuntime as ChosenRuntime;
//     //     } else {
//     //         compile_error!("You must configure both an async runtime and a TLS stack. See doc/TROUBLESHOOTING.md for more.");
//     //     }
//     // }
//     // ChosenRuntime::create()
//     use tor_rtcompat::tokio::TokioNativeTlsRuntime as ChosenRuntime;
//     create_with_runtime("127.0.0.1:7890".to_owned(), None, None, ChosenRuntime::create()?)
// }






/// TODO: add doc
#[derive(Clone)]
pub struct SocksTcpProvider<R> {
    socks_server: String, // eg. `127.0.0.1:1080`

    username: Option<String>,

    password: Option<String>,

    rt: R,
}


type SocksTcpStream = BoxTcpStream;

impl<R> TcpProvider for SocksTcpProvider<R>
where 
    R: Runtime,
{
    type TcpStream = SocksTcpStream;
    type TcpListener = BoxTcpListener<R::TcpListener>;

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
            .map_ok(|v|box_tcp_stream(v.compat()))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            .boxed()
        } else {
            Socks5Stream::connect(&self.socks_server, target_addr, target_port, Socks5Config::default())
            .map_ok(|v|box_tcp_stream(v.compat()))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            .boxed()
        };

        r
    }


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
        // PendingForever(PhantomData::default()).boxed()
        self.rt
        .listen(addr)
        .map(|l| l.map(|listener| BoxTcpListener::new(listener)))
        .boxed()
    }
}



