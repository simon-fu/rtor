
use anyhow::Context as AnyContext;
use anyhow::Result;
use anyhow::bail;
use futures::Future;
use hyper::client::connect::Connection;
use hyper::{service::Service, Uri};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls;
use tokio_rustls::rustls::OwnedTrustAnchor;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use hyper::client::connect::Connected;
use tokio::io::{AsyncRead, AsyncWrite};

use super::stream2::Connection2;
use super::stream2::Stream2;

#[derive(Clone)]
pub struct TlsConnector2<T>(pub T);


impl <T> Service<Uri> for TlsConnector2<T> 
where
    T: Service<Uri> + Clone + Send + 'static,
    T::Error: Into<anyhow::Error> + Send + Sync + 'static,
    T::Response: AsyncRead + AsyncWrite + Unpin + Send,
    T::Future: Send,
{
    type Response = Stream2<T::Response, TlsStream<T::Response>>;
    type Error = anyhow::Error;
    type Future = Pin<Box<
        dyn Future<Output = Result<Self::Response, Self::Error>> + Send
    >>;

    fn poll_ready(&mut self, _: &mut core::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        // This connector is always ready, but others might not be.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        Box::pin( maybe_ssl_connecting2(self.0.clone(), uri) )
    }
}


async fn maybe_ssl_connecting2<T>(mut inner: T, uri: Uri) -> Result<Stream2<T::Response, TlsStream<T::Response>>> 
where
    T: Service<Uri>,
    T::Error: Into<anyhow::Error> + Send + Sync + 'static,
    T::Response: AsyncRead + AsyncWrite + Unpin,
{

    let scheme = uri.scheme_str().with_context(||"uri has no scheme")?;
    if scheme.eq_ignore_ascii_case("http") { 
        let stream = inner.call(uri.clone()).await.map_err(|v|v.into())?;
        Ok(Stream2::S1(stream))

    } else if scheme.eq_ignore_ascii_case("https") {
        let domain = uri.host().with_context(||"uri has no host")?.to_owned();
        let socket = inner.call(uri.clone()).await.map_err(|v|v.into())?;
        let stream = client_ssl_domain(domain.as_str(), socket).await?;
        Ok(Stream2::S2(stream))

    } else {
        bail!("unknown scheme [{}]", scheme)
    }
}

async fn client_ssl_domain<IO>(domain: &str, socket: IO) -> Result<TlsStream<IO>> 
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
        |ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        },
    ));

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth(); // i guess this was previously the default?
    let connector = TlsConnector::from(Arc::new(config));


    let domain = rustls::ServerName::try_from(domain)?;

    let tls_stream = connector.connect(domain, socket).await?;

    Ok(tls_stream)
}


impl Connection2 for TlsStream<TcpStream> {
    fn connected2(&self) -> Connected {
        self.get_ref().0.connected()
    }
}

impl Connection2 for TcpStream {
    fn connected2(&self) -> Connected {
        self.connected()
    }
}

