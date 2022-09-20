
use std::{sync::Arc, time::Duration, convert::{TryInto}, collections::HashMap, path::PathBuf};

use anyhow::{Result, Context, bail};
use arti_client::{config::{TorClientConfigBuilder}, TorClient, DataStream};
use futures::Future;

use socks5_proto::{HandshakeRequest, HandshakeMethod, HandshakeResponse, Request, Reply, Address, Command};
use tor_chanmgr::{ChannelConfig, Dormancy};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_netdir::{params::NetParameters};
use tor_proto::circuit::ClientCirc;
use tor_rtcompat::Runtime;
use tracing::{info, debug};
use crate::{scan::{self, HashRelay, ScanResult, OwnedRelay, tcp_scan::{TcpScanner, Connector}}, proxy::{ProxyConfig, Args, proxy_ch2::circs::CircPool, relay_pool::{RelaysWatcher, PoolAction}, buildin_relays}, box_socks::{SocksArgs, self} };

use tokio::net::{TcpListener, TcpStream};

use super::relay_pool::RelayPool;


macro_rules! dbgd {
    ($($arg:tt)* ) => (
        tracing::debug!($($arg)*) // comment out this line to disable log
    );
}


const NUM_TRY_SETUP_CIRC:  usize = 5;
const NUM_TRY_CONNECT_TARGET: usize = 5;


pub async fn run_proxy() -> Result<()> {  
    // run_download().await?;

    let args = Args::default();
    let args: Arc<ProxyConfig> = Arc::new((&args).try_into()?);
    
    let reachable_ids = {
        let file = &args.reachable_relays_file;
        if tokio::fs::metadata(file).await.is_ok() { 
            let relays = scan::load_ids_from_file(file).await
            .with_context(||format!("fail to load file [{:?}]", file))?;
            info!("loaded relays [{}] from [{:?}]", relays.len(), file);
            relays
        } else {
            Default::default()
        }
    };


    {
        let file = &args.all_relays_file;
        if tokio::fs::metadata(file).await.is_ok() {
            let relays: HashMap<Ed25519Identity, Arc<OwnedRelay>> = scan::load_relays_to_collect(file).await
            .with_context(||format!("fail to load file [{:?}]", file))?;
            info!("loaded relays [{}] from [{:?}]", relays.len(), file);
        } 
    }

    let (all_relays, _tor_client) = {
        let file = &args.all_relays_file;
        if tokio::fs::metadata(file).await.is_ok() {
            let relays: HashMap<Ed25519Identity, Arc<OwnedRelay>> = scan::load_relays_to_collect(file).await
            .with_context(||format!("fail to load file [{:?}]", file))?;
            info!("loaded relays [{}] from [{:?}]", relays.len(), file);

            if relays.len() > 0 {
                (relays, None)
            } else {
                let (relays, tor_client) = tor_bootstrap(&args).await?;
                (relays, Some(tor_client))
            }
            
        } else {
            let (relays, tor_client) = tor_bootstrap(&args).await?;
            (relays, Some(tor_client))
        }
    };


    if all_relays.len() == 0 { 
        bail!("empty relays")
    }

    let num_reachables = reachable_ids.len();

    let relays_pool = Arc::new(RelayPool::new(
        all_relays, 
        Some(reachable_ids),
    ));

    if num_reachables == 0 { 
        {
            let pool = relays_pool.clone();
            let args = args.clone();
            tokio::spawn(async move {
                info!("kicked write_reachables");
                let r = write_reachables(pool, args.override_min_guards, &args.reachable_relays_file).await;
                info!("write_reachables finished with [{:?}]", r)
            });
        }

        {
            let pool = relays_pool.clone();
            let scan_timeout = args.scan_timeout;
            let scan_concurrency = args.scan_concurrency;
            let socks_addr = args.out_socks.clone();
            tokio::spawn(async move {
                info!("kicked scan_reachables");
                let r = scan_reachables(pool, scan_timeout, scan_concurrency, socks_addr).await;
                info!("scan_relays_to_pool finished with [{:?}]", r)
            });
        }
    }

    let rt = box_socks::create_runtime(args.out_socks.as_ref().map(|v| SocksArgs {
        server: v.clone(),
        username: None,
        password: None,
        max_targets: None,
    }))?;
    // let rt = tor_rtcompat::PreferredRuntime::current()?;
    let ch_cfg = ChannelConfig::default();
    let dormant = Dormancy::default();
    let netparams = NetParameters::default();
    
    let chmgr = Arc::new(tor_chanmgr::ChanMgr::new(
        rt.clone(),
        &ch_cfg,
        dormant,
        &netparams,
    ));

    // let mut watcher = RelaysWatcher::new(relays_pool.clone());
    let circ_pool = Arc::new(CircPool::new(relays_pool));

    let mut num_circs = 0;

    for n in 0..NUM_TRY_SETUP_CIRC {
        info!("No.{} try setup circ ...", n);
        let r = circ_pool.scan(&chmgr).await;
        match r {
            Ok(v) => {
                num_circs = v;
                info!("No.{} setup circ ok,  circs [{}]", n, v);
            },
            Err(e) => {
                info!("No.{} setup circ fail with [{:?}]", n, e);
            },
        }
        // watcher.watch_next().await?;
    }

    if num_circs == 0 {
        bail!("can't setup circs")
    }

    info!("available circs [{}]", num_circs);

    run_socks5_bridge(&args, circ_pool).await?;
    
    // tokio::time::sleep(Duration::from_secs(9999999)).await;
    
    Ok(())
}

async fn run_socks5_bridge(args: &Arc<ProxyConfig>, pool: Arc<CircPool>) -> Result<()> {
    let listener = TcpListener::bind(args.socks_listen.as_str()).await
        .with_context(||format!("fail to listen at [{}]", args.socks_listen))?;
    info!("socks5 listening at [{}]", args.socks_listen);

    loop {
        let (mut socket, addr) = listener.accept().await?;
        debug!("socks5 client connected from [{}]", addr);

        {
            let pool = pool.clone();
            tokio::spawn(async move {
                let r = conn_task(&mut socket, pool).await;
                debug!("conn finished with [{:?}]", r);
            });
        }
    }
    
}

async fn conn_task(src: &mut TcpStream, pool: Arc<CircPool>) -> Result<()> { 
    use tokio::io::AsyncWriteExt;
    
    let hs_req = HandshakeRequest::read_from(src).await?;

    if hs_req.methods.contains(&HandshakeMethod::None) {
        let hs_resp = HandshakeResponse::new(HandshakeMethod::None);
        hs_resp.write_to(src).await?;
    } else {
        let hs_resp = HandshakeResponse::new(HandshakeMethod::Unacceptable);
        hs_resp.write_to(src).await?;
        let _ = src.shutdown().await;
        bail!("unsupported client methods [{:?}]", hs_req.methods);
    }

    let req = {
        let r = Request::read_from(src).await;
        match r {
            Ok(req) => req,
            Err(err) => {
                let resp = socks5_proto::Response::new(Reply::GeneralFailure, Address::unspecified());
                resp.write_to(src).await?;
                let _ = src.shutdown().await;
                return Err(err.into());
            }
        }
    };


    match &req.command {
        Command::Connect => {},
        _ => {
            let resp = socks5_proto::Response::new(Reply::CommandNotSupported, Address::unspecified());
            resp.write_to(src).await?;
            let _ = src.shutdown().await;
            bail!("unsupported client commnad [{:?}]", req.command);
        }
    }

    let r = try_circ_connect(&pool, &req.address, NUM_TRY_CONNECT_TARGET).await;

    let (mut dst, _circ) = match r {
        Ok(dst) => dst,
        Err(e) => {
            let resp = socks5_proto::Response::new(Reply::HostUnreachable, Address::unspecified());
            resp.write_to(src).await?;
            let _ = src.shutdown().await;
            return Err(e)
            // bail!("fail to connect target [{:?}] error [{:?}]", req.address, e);
        },
    };

    info!("connected to target [{:?}]", req.address);

    {
        let resp = socks5_proto::Response::new(Reply::Succeeded, Address::unspecified());
        resp.write_to(src).await?;
    }
    
    tokio::io::copy_bidirectional(&mut dst, src).await?;

    Ok(())
}

async fn try_circ_connect(pool: &Arc<CircPool>, addr: &Address, num_try: usize) -> Result<(DataStream, ClientCirc)> {
    for n in 0..num_try {
        let circ = pool.pick_circ().with_context(||"no circ")?;
        dbgd!("No.{} try connecting to target [{:?}]", n, addr);
        let r = match addr {
            Address::SocketAddress(addr) => circ.begin_stream(&addr.ip().to_string(), addr.port(), None).await,
            Address::DomainAddress(host, port) => circ.begin_stream(host, *port, None).await,
        };

        match r {
            Ok(stream) => {
                return Ok((stream, circ))
            },
            Err(e) => {
                dbgd!("No.{} fail to connect to [{:?}], with [{:?}]", n, addr, e);
            },
        }
    }
    bail!("unable to connect to [{:?}]", addr)
}

async fn tor_bootstrap(args: &Arc<ProxyConfig>) -> Result<(HashMap<Ed25519Identity, Arc<OwnedRelay>>, TorClient<impl Runtime>)> {

    let fallback_caches = buildin_relays::relays().iter().map(|v|(&v.0).as_ref().into()).collect();

    let mut builder = TorClientConfigBuilder::from_directories(
        &args.state_dir, 
        &args.cache_dir,
    );
    builder.tor_network().set_fallback_caches(fallback_caches);
    let config = builder.build()?;

    let builder = TorClient::builder()
    .config(config);

    
    let tor_client = builder.create_unbootstrapped()?;
    
    info!("bootstrapping...");
    tor_client.bootstrap().await?;
    info!("bootstrapped ok");

    let netdir = tor_client.dirmgr().timely_netdir()?;
    let mut all_relays = HashMap::new();
    for relay in netdir.relays() {
        let id = relay.id().clone();
        let relay: Arc<OwnedRelay> = Arc::new(relay.try_into()?);
        all_relays.insert(id, relay);
    }

    let iter = all_relays.iter().map(|v| v.1.as_ref());
    scan::write_relays_to_filepath(iter, &args.all_relays_file).await?;
    info!("wrote all relays [{}] to [{:?}]", all_relays.len(), args.all_relays_file);

    Ok((all_relays, tor_client))
}

async fn scan_reachables(pool: Arc<RelayPool>, timeout: Duration, concurrency: usize, socks_addr: Option<String>) -> Result<()> { 
    struct Ctx {
        pool: Arc<RelayPool>,
    }

    async fn insert_to_pool(ctx: &mut Ctx, (relay, r): ScanResult) -> Result<()> {
        if r.is_ok() {
            info!("insert reachable [{:?}]", relay);
            ctx.pool.update_relay(HashRelay(relay))?;
        }
        Ok(())
    }

    let relays = pool.relays().iter().map(|v|v.1.clone());
    let mut ctx = Ctx{
        pool: pool.clone(), 
    };

    pool.scan_beging()?;


    match socks_addr {
        Some(s) => {
            let socks_args = SocksArgs {
                server: s,
                username: None,
                password: None,
                max_targets: None,
            };
            let connector = SocksConnector(Arc::new(socks_args));
            let mut scanner = TcpScanner::with_connector(timeout, concurrency, connector);
            scan::scan_relays2(&mut scanner, relays, &mut ctx, &insert_to_pool ).await?;

        },
        None => {
            let mut scanner = TcpScanner::new(timeout, concurrency);
            scan::scan_relays2(&mut scanner, relays, &mut ctx, &insert_to_pool ).await?;
        },
    }

    pool.scan_done()?;

    Ok(())
}

async fn write_reachables(pool: Arc<RelayPool>, override_min_guards: usize, reachable_relays_file: &PathBuf) -> Result<()> { 
    let mut watcher = RelaysWatcher::new(pool.clone());
    
    loop {
        let action = watcher.watch_next().await?;
        info!("got action [{:?}]", action);
        match action {
            PoolAction::None => {},
            PoolAction::Scanning => {},
            PoolAction::AddRelays(_delta, _num) => {},
            PoolAction::AddGuards(_delta, num) => {
                if num > 0 && num % override_min_guards == 0 { 
                    let ids = pool.reachable_ids();
                    info!("write reachable ids [{}] to [{:?}]", ids.len(), reachable_relays_file);
                    scan::write_ids_to_filepath(ids.iter(), reachable_relays_file).await?;
                }
            },
            
            PoolAction::ScanDone => { 
                let (all, guards) = pool.num_reachables();
                info!("got scan-done, guards/reachables [{}/{}]", guards, all);
                
                let ids = pool.reachable_ids();
                if ids.len() >= override_min_guards {
                    info!("write final reachable ids [{}] to [{:?}]", ids.len(), reachable_relays_file);
                    scan::write_ids_to_filepath(ids.iter(), reachable_relays_file).await?;
                }
                break
            },
        }
    }
    
    Ok(())
}

#[derive(Debug, Clone)]
struct SocksConnector(pub Arc<SocksArgs>);

impl Connector for SocksConnector {
    type ConnectFuture<'a> = impl Future<Output = Result<()>> where Self: 'a;

    fn connect<'a>(&'a mut self, addr: &'a str) -> Self::ConnectFuture<'_> {
        async move {
            box_socks::connect_to_with_socks(&self.0, addr).await?;
            Ok(())
        }
    }
}




// pub mod download {
//     use std::{sync::Arc, time::Duration};
//     use anyhow::{Result, bail};
//     use hyper::{client::HttpConnector, Body, body::HttpBody, Uri, Response};
//     use tor_proto::circuit::ClientCirc;
//     use crate::{proxy::proxy_ch2::{circ_connector::CircConnector}, tls2::TlsConnector2 };
//     use tokio::time::Instant;
    

    
//     pub async fn run_download() -> Result<()> { 
//         // let uri: Uri = "http://ipv4.download.thinkbroadband.com:81/1GB.zip".parse()?;
//         let uri: Uri = "https://node-223-111-192-62.speedtest.cn:51090/download?size=25000000&r=0.8831805926565437".parse()?;
//         // let uri: Uri = "http://www.baidu.com".parse()?;
    
        
//         // let client: hyper::Client<HttpConnector> = hyper::Client::builder()
//         // .build_http();
    
//         let mut cc = HttpConnector::new();
//         cc.enforce_http(false);
    
//         let cc = TlsConnector2(cc);
//         let client: hyper::Client<_> = hyper::Client::builder()
//         .build(cc);
    
        
//         let res = client.get(uri).await?;
    
//         // let authority = uri.authority().with_context(||"uri has no authority")?.clone();
//         // let req = Request::builder()
//         //     .uri(uri)
//         //     .header(hyper::header::HOST, authority.as_str())
//         //     .header(hyper::header::USER_AGENT, "curl/7.79.1")
//         //     .header(hyper::header::ACCEPT, "*/*")
//         //     .body(Body::empty())?;
    
//         // let mut res = client.request(req).await?;
    
    
//         estimate_http_download_bw(res).await?;
        
    
//         bail!("download ok")
//     }
    
    
    
//     async fn estimate_http_download_bw(mut res: Response<Body>) -> Result<()> { 
//         println!("Response: {}", res.status());
//         println!("Headers: {:#?}\n", res.headers());
    
//         const DURATION: Duration = Duration::from_millis(5000);
//         let mut recv_bytes = 0;
//         let start = Instant::now();
//         while let Some(next) = res.data().await {
//             let chunk = next?;
//             println!("got bytes {}", chunk.len());
//             recv_bytes += chunk.len() as u64;
//             if start.elapsed() >= DURATION {
//                 break;
//             }
//         }
    
//         let elapsed = start.elapsed();
//         let bitrate = if elapsed.as_millis() > 0 {
//             recv_bytes * 8 * 1000 / (elapsed.as_millis() as u64)
//         } else {
//             0
//         };
    
//         println!("\n\nDone!, recv bytes {}, elapsed {:?}, bps {}", recv_bytes, elapsed, bitrate);
    
//         Ok(())
//     }
    
//     pub async fn run_circ_download(circ: Arc<ClientCirc>) -> Result<()> { 
//         // let uri: Uri = "http://ipv4.download.thinkbroadband.com:81/1GB.zip".parse()?;
//         let uri: Uri = "https://node-223-111-192-62.speedtest.cn:51090/download?size=25000000&r=0.8831805926565437".parse()?;
//         // let uri: Uri = "http://www.baidu.com".parse()?;
    
//         let cc = CircConnector(circ);
//         let cc2 = TlsConnector2(cc);
//         let client: hyper::Client<_> = hyper::Client::builder()
//         .build(cc2);
    
        
//         let res = client.get(uri).await?;
    
//         estimate_http_download_bw(res).await?;
    
//         bail!("download ok")
//     }
// }




pub mod circs {
    use std::{collections::{BTreeSet, HashMap}, sync::Arc};

    use anyhow::Result;
    use parking_lot::Mutex;
    use serde::{Serialize, Deserialize};
    use tor_chanmgr::{ChanMgr, ChannelUsage};
    use tor_llcrypto::pk::ed25519::Ed25519Identity;
    use tor_proto::circuit::{ClientCirc, CircParameters};
    use tor_rtcompat::Runtime;
    use tracing::info;

    use crate::proxy::relay_pool::RelayPool;


    #[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
    pub struct PathId(Vec<Ed25519Identity>);
    
    pub struct Circ {
        circ: ClientCirc, 
        _score: u64,
    }

    pub struct CircPool { 
        relay_pool: Arc<RelayPool>,
        data: Mutex<Data>,
    }

    const MIN_ACTIVE_CIRCS: usize = 2;


    impl CircPool 
    {
        pub fn new(relay_pool: Arc<RelayPool>) -> Self {
            Self { relay_pool, data: Default::default()}
        }

        // pub fn relay_pool(&self) -> &Arc<RelayPool> {
        //     &self.relay_pool
        // }

        // pub fn num_circs(&self) -> usize {
        //     self.data.lock().circs.len()
        // }

        pub fn pick_circ(&self) -> Option<ClientCirc> {
            self.data.lock().circs.iter().next().map(|v|v.1.circ.clone())
        }


        const TRY_CIRCID_NUM: usize = 5;
        pub async fn scan<R>(&self, chmgr: &Arc<ChanMgr<R>>) -> Result<usize> 
        where
            R: Runtime,
        { 
            let mut new_circ = None;
            let mut num_circs;

            {
                let data = self.data.lock(); 
    
                num_circs = data.circs.len();

                if num_circs < MIN_ACTIVE_CIRCS { 
                    let mut rng = rand::thread_rng();

                    for _ in 0..Self::TRY_CIRCID_NUM {
                        let r1 = self.relay_pool.pick_active_guard(&mut rng);
                        let r2 = self.relay_pool.pick_exit(&mut rng);
                        
                        if let (Some(r1), Some(r2)) = (r1, r2) { 
                            let path = PathId(vec![r1.own_id()?, r2.own_id()?]);
                            if !data.circs.contains_key(&path) {
                                new_circ = Some((path, r1.clone(), r2.clone()));
                                break;
                            }   
                        } else {
                            break;
                        }
                    }

                }
            }

            if let Some((path, guard, exit)) = new_circ {

                let (ch, _provenance) = chmgr.get_or_launch(guard.as_ref(), ChannelUsage::UserTraffic).await?;

                let (pending_circ, reactor) = ch.new_circ().await?;
                
                tokio::spawn(async {
                    let _ = reactor.run().await;
                });

                let circ = pending_circ.create_firsthop_ntor(guard.as_ref(), CircParameters::default()).await?;
                circ.extend_ntor(exit.as_ref(), &CircParameters::default()).await?;

                let mut data = self.data.lock(); 
                if !data.circs.contains_key(&path) {
                    info!("new circ {:?}", path);
                    data.circs.insert(path.clone(), Circ { circ, _score: 0 });
                    num_circs = data.circs.len();

                    data.rank.insert(CircScore { path, score: 0 });
                }

            }

            Ok(num_circs)
        }
        
    }


    #[derive(Default)]
    struct Data {
        circs: HashMap<PathId, Circ>,
        rank: BTreeSet<CircScore>,
    }


    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
    struct CircScore {
        path: PathId,
        score: u64,
    }

    impl core::hash::Hash for CircScore {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.score.hash(state)
        }
    }
}


mod circ_connector {
    use anyhow::Context as AnyContext;
    use anyhow::Result;
    use anyhow::bail;
    use futures::Future;
    use hyper::client::connect::Connected;
    use hyper::{service::Service, Uri};
    use tokio_rustls::client::TlsStream;
    use tor_proto::circuit::ClientCirc;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::Poll;
    use tor_proto::stream::DataStream;
    use crate::tls2::Connection2;



    #[derive(Clone)]
    pub struct CircConnector<T>(pub T);

    impl<T> Service<Uri> for CircConnector<T> 
    where 
        T: AsCirc + Clone + Send + Sync + 'static,
    {
        type Response = DataStream;
        type Error = anyhow::Error;
        type Future = Pin<Box<
            dyn Future<Output = Result<Self::Response, Self::Error>> + Send
        >>;

        fn poll_ready(&mut self, _: &mut core::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, uri: Uri) -> Self::Future {
            Box::pin( circ_connect(self.0.clone(), uri) )
        }
    }

    async fn circ_connect<T>(circ: T, uri: Uri) -> Result<DataStream> 
    where 
        T: AsCirc,
    {
        let (host, port) = get_http_host_port(&uri)?;
        let stream = circ.as_circ().begin_stream(host, port, None).await?;
        Ok(stream)
    }

    impl Connection2 for DataStream {
        fn connected2(&self) -> Connected {
            Connected::new()
        }
    }

    impl Connection2 for TlsStream<DataStream> {
        fn connected2(&self) -> Connected {
            Connected::new()
        }
    }

    pub trait AsCirc {
        fn as_circ(&self) -> &ClientCirc;
    }

    impl AsCirc for Arc<ClientCirc> {
        fn as_circ(&self) -> &ClientCirc {
            self.as_ref()
        }
    }

    impl AsCirc for Box<ClientCirc> {
        fn as_circ(&self) -> &ClientCirc {
            self.as_ref()
        }
    }

    fn get_http_host_port<'u>(uri: &'u Uri) -> Result<(&'u str, u16)> { 
        let host = uri.host().with_context(||"uri has no host")?;
        if let Some(port) = uri.port_u16() {
            return Ok((host, port))
        }

        if let Some(scheme) =  uri.scheme_str() { 
            if scheme.eq_ignore_ascii_case("http") {
                return Ok((host, 80))
            } else if scheme.eq_ignore_ascii_case("https") {
                return Ok((host, 443))
            } else {
                bail!("unknown scheme [{}]", scheme)
            }
        }

        bail!("uri has no scheme")
    }

}





