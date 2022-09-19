
use std::{sync::Arc, time::Duration, convert::{TryInto}, collections::{HashMap, HashSet}, path::PathBuf};


use anyhow::{Result, Context, bail, Ok};
use arti_client::{config::{TorClientConfigBuilder}, TorClient};
use hyper::{client::HttpConnector, Body, body::HttpBody, Uri, Response};


use tor_chanmgr::{ChannelConfig, Dormancy};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_netdir::{NetDir, params::NetParameters};
use tor_proto::circuit::ClientCirc;
use tor_rtcompat::Runtime;
use tracing::{info, debug};
use crate::{scan::{self, HashRelay, ScanResult, OwnedRelay}, proxy::{scan_bootstraps, ProxyConfig, Args, proxy_ch2::{circ_connector::CircConnector, circs::CircPool}, relay_pool::{RelaysWatcher, PoolAction}, buildin_relays}, tls2::TlsConnector2 };

use tokio::time::Instant;

use super::relay_pool::RelayPool;





pub async fn run_proxy() -> Result<()> {  
    // run_download().await?;

    let args = Args::default();
    let args: Arc<ProxyConfig> = Arc::new((&args).try_into()?);
    
    let reachable_relays = {
        let file = &args.reachable_relays_file;
        if tokio::fs::metadata(file).await.is_ok() { 
            let relays:HashSet<Ed25519Identity> = scan::load_items_from_file::<_, Ed25519Identity>(file).await
            .with_context(||format!("fail to load file [{:?}]", file))?;
            info!("loaded relays [{}] from [{:?}]", relays.len(), file);
            relays
        } else {
            Default::default()
        }
    };

    // {
    //     let file = &args.all_relays_file;
    //     if tokio::fs::metadata(file).await.is_ok() {
    //         let relays: HashMap<Ed25519Identity, Arc<OwnedRelay>> = scan::load_relays_to_collect(file).await
    //         .with_context(||format!("fail to load file [{:?}]", file))?;
    //         info!("loaded relays [{}] from [{:?}]", relays.len(), file);
    //     } 
    // }

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

    let relays_pool = Arc::new(RelayPool::new(all_relays));

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
        tokio::spawn(async move {
            info!("kicked scan_reachables");
            let r = scan_reachables(pool, scan_timeout, scan_concurrency).await;
            info!("scan_relays_to_pool finished with [{:?}]", r)
        });
    }



    // let rt = tor_rtcompat::PreferredRuntime::current()?;
    // let ch_cfg = ChannelConfig::default();
    // let dormant = Dormancy::default();
    // let netparams = NetParameters::default();
    
    // let chmgr = Arc::new(tor_chanmgr::ChanMgr::new(
    //     rt.clone(),
    //     &ch_cfg,
    //     dormant,
    //     &netparams,
    // ));

    // let mut watcher = RelaysWatcher::new(relays_pool.clone());
    // let circ_pool = CircPool::new(relays_pool);

    // let mut num_circs = circ_pool.scan(&chmgr).await?;

    // while num_circs == 0 {
    //     num_circs = circ_pool.scan(&chmgr).await?;
    //     watcher.watch_next().await?;
    // }

    // info!("available circs [{}]", circ_pool.num_circs());

    





    // let mut first_active_guards = 0;

    // let config = {    

    //     let relays = if let Some(bootstrap_relays_file) = &args.bootstrap_file {
    //         info!("scan bootstraps by [From [{}]]", bootstrap_relays_file);
    //         scan_bootstraps(&args, Some(bootstrap_relays_file),).await?

    //     } else if args.bootstrap_buildin {
    //         info!("scan bootstraps by [Force build-in]");
    //         scan_bootstraps(&args, None).await?

    //     } else if tokio::fs::metadata(&args.reachable_relays_file).await.is_err() {
    //         info!("scan bootstraps by [Not exist [{:?}]]", args.reachable_relays_file);
    //         scan_bootstraps(&args, None).await?

    //     } else {
    //         // let relays = load_and_set_relays(&args.work_relays_file).await?;
    //         let file = &args.reachable_relays_file;
    //         let set = scan::load_result_filepath(file).await
    //         .with_context(||format!("fail to load bootstrap file [{:?}]", file))?;
    //         info!("loaded relays [{}] from [{:?}]", set.len(), file);

    //         first_active_guards = set.iter().filter(|v|v.0.is_flagged_guard()).count();

    //         if set.len() > 0 {
    //             // is_scan_bootstraps = false;
    //             set
    //         } else { 
    //             info!("scan bootstraps by [Empty [{:?}]]", args.reachable_relays_file);
    //             scan_bootstraps( &args, None).await?
    //         }
    //     };

    //     if relays.len() == 0 {
    //         bail!("empty bootstrap relays")
    //     }

    //     let caches = relays.iter().map(|v|(&v.0).into()).collect();

    //     let mut builder = TorClientConfigBuilder::from_directories(
    //         &args.state_dir, 
    //         &args.cache_dir,
    //     );
    //     builder.tor_network().set_fallback_caches(caches);
    //     builder.build()?
    // };

    // let builder = TorClient::builder()
    // .config(config);

    
    // let tor_client = builder.create_unbootstrapped()?;
    
    // info!("bootstrapping...");
    // tor_client.bootstrap().await?;
    // info!("bootstrapped ok");

    // // channel_raw::run_raw(&tor_client).await?;


    // {
    //     let scan_timeout = args.scan_timeout;
    //     let scan_concurrency = args.scan_concurrency;
    //     let netdir = tor_client.dirmgr().timely_netdir()?;

    //     let mut relays = HashMap::new();
    //     for relay in netdir.relays() {
    //         let id = relay.id().clone();
    //         let relay: Arc<OwnedRelay> = Arc::new(relay.try_into()?);
    //         relays.insert(id, relay);
    //     }

    //     let relays_pool = Arc::new(RelayPool::new(relays));

    //     let pool = relays_pool.clone();
    //     tokio::spawn(async move {
    //         let r = scan_netdir_to_pool(netdir, pool, scan_timeout, scan_concurrency).await;
    //         info!("scan_relays_to_pool finished with [{:?}]", r)
    //     });

    //     let rt = tor_rtcompat::PreferredRuntime::current()?;
    //     let ch_cfg = ChannelConfig::default();
    //     let dormant = Dormancy::default();
    //     let netparams = NetParameters::default();
        
    //     let chmgr = Arc::new(tor_chanmgr::ChanMgr::new(
    //         rt.clone(),
    //         &ch_cfg,
    //         dormant,
    //         &netparams,
    //     ));

    //     let mut watcher = RelaysWatcher::new(relays_pool.clone());
    //     let circ_pool = CircPool::new(relays_pool);

    //     let mut num_circs = circ_pool.scan(&chmgr).await?;

    //     while num_circs == 0 {
    //         num_circs = circ_pool.scan(&chmgr).await?;
    //         watcher.watch_next().await?;
    //     }
        
    // }

    // // {
    // //     let (tx, rx) = oneshot::channel();
    // //     let tor_client = tor_client.clone();
    // //     let args = args.clone();
    // //     // let mut scanner = RelayScanner::new(tor_client, args, first_active_guards);
        
    // //     tokio::spawn(async move { 
    // //         let r = scan_task(tor_client, args, tx, first_active_guards).await; 
    // //         info!("scan_task finished with [{:?}]", r)
    // //     });

    // //     if first_active_guards == 0 {
    // //         let _r = rx.await?;
    // //     }
    // // }



    // run_socks5_bridge(&args, &tor_client).await?;
    tokio::time::sleep(Duration::from_secs(9999999)).await;

    
    Ok(())
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

    Ok((all_relays, tor_client))
}

async fn scan_reachables(pool: Arc<RelayPool>, timeout: Duration, concurrency: usize) -> Result<()> { 
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

    scan::scan_relays(relays, timeout, concurrency, &mut ctx, &insert_to_pool ).await?;

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



// async fn scan_task<R>(tor_client: TorClient<R>, args: Arc<ProxyConfig>, tx: oneshot::Sender<()>, last_guards: usize) -> Result<()> 
// where
//     R: Runtime
// {
//     let mut tx = Some(tx);
//     loop {
//         let netdir = tor_client.dirmgr().timely_netdir()?;
//         let total = netdir.relays().count();
//         let relays = netdir.relays().filter_map(|v|v.try_into().ok());
//         let args0 = args.clone();

//         info!("scanning relays [{}]...", total);
//         let r = scan_relays_to_file(relays, args.scan_timeout, args.scan_concurrency, tx.take(), args.reachable_relays_file.clone(), move |stati, relay| {
//             // r.guards > 0
//             let r = if relay.is_flagged_guard() {
//                 stati.guards > last_guards && stati.guards % args0.override_min_guards == 0
//             } else {
//                 false
//             };
//             if r {
//                 info!("flush relays to file [{:?}], stati [{:?}]", args0.reachable_relays_file, stati); 
//             }
//             r
//         }).await;


//         match r {
//             Ok((set, stati)) => {
//                 if stati.guards > last_guards {
//                     write_relays_to_filepath(set.iter().map(|v|&v.0), &args.reachable_relays_file).await?;
//                 }

//                 info!("scanning result: ok [{}/{}]", set.len(), total);
//             },
//             Err(e) => info!("scanning result: error [{:?}]", e),
//         }

//         tokio::time::sleep(args.scan_interval).await;
//     }
// }



async fn run_download() -> Result<()> { 
    // let uri: Uri = "http://ipv4.download.thinkbroadband.com:81/1GB.zip".parse()?;
    let uri: Uri = "https://node-223-111-192-62.speedtest.cn:51090/download?size=25000000&r=0.8831805926565437".parse()?;
    // let uri: Uri = "http://www.baidu.com".parse()?;

    
    // let client: hyper::Client<HttpConnector> = hyper::Client::builder()
    // .build_http();

    // let cc = TlsConnector2{};
    let mut cc = HttpConnector::new();
    cc.enforce_http(false);
    let cc2 = TlsConnector2(cc);
    let client: hyper::Client<_> = hyper::Client::builder()
    .build(cc2);

    
    let res = client.get(uri).await?;

    // let authority = uri.authority().with_context(||"uri has no authority")?.clone();
    // let req = Request::builder()
    //     .uri(uri)
    //     .header(hyper::header::HOST, authority.as_str())
    //     .header(hyper::header::USER_AGENT, "curl/7.79.1")
    //     .header(hyper::header::ACCEPT, "*/*")
    //     .body(Body::empty())?;

    // let mut res = client.request(req).await?;


    estimate_http_download_bw(res).await?;
    

    bail!("download ok")
}



async fn estimate_http_download_bw(mut res: Response<Body>) -> Result<()> { 
    println!("Response: {}", res.status());
    println!("Headers: {:#?}\n", res.headers());

    const DURATION: Duration = Duration::from_millis(5000);
    let mut recv_bytes = 0;
    let start = Instant::now();
    while let Some(next) = res.data().await {
        let chunk = next?;
        println!("got bytes {}", chunk.len());
        recv_bytes += chunk.len() as u64;
        if start.elapsed() >= DURATION {
            break;
        }
    }

    let elapsed = start.elapsed();
    let bitrate = if elapsed.as_millis() > 0 {
        recv_bytes * 8 * 1000 / (elapsed.as_millis() as u64)
    } else {
        0
    };

    println!("\n\nDone!, recv bytes {}, elapsed {:?}, bps {}", recv_bytes, elapsed, bitrate);

    Ok(())
}

async fn run_circ_download(circ: Arc<ClientCirc>) -> Result<()> { 
    // let uri: Uri = "http://ipv4.download.thinkbroadband.com:81/1GB.zip".parse()?;
    let uri: Uri = "https://node-223-111-192-62.speedtest.cn:51090/download?size=25000000&r=0.8831805926565437".parse()?;
    // let uri: Uri = "http://www.baidu.com".parse()?;

    let cc = CircConnector(circ);
    let cc2 = TlsConnector2(cc);
    let client: hyper::Client<_> = hyper::Client::builder()
    .build(cc2);

    
    let res = client.get(uri).await?;

    estimate_http_download_bw(res).await?;

    bail!("download ok")
}



mod circs {
    use std::{collections::{BTreeSet, BTreeMap, HashMap}, sync::Arc, path::Path, ops::Range};

    use anyhow::Result;
    use arti_client::TorClient;
    use parking_lot::Mutex;
    use rand::{RngCore, Rng};
    use serde::{Serialize, Deserialize};
    use tokio::sync::oneshot;
    use tor_chanmgr::{ChanMgr, ChannelUsage};
    use tor_llcrypto::pk::ed25519::Ed25519Identity;
    use tor_proto::{circuit::{ClientCirc, CircParameters}, channel::Channel};
    use tor_rtcompat::Runtime;
    use tracing::info;

    use crate::{proxy::{ProxyConfig, relay_pool::{ArcRelays, RelayPool}}, scan::OwnedRelay};


    #[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
    pub struct PathId(Vec<Ed25519Identity>);
    
    pub struct Circ {
        circ: ClientCirc, 
        score: u64,
    }

    pub struct CircPool { 
        relay_pool: Arc<RelayPool>,
        data: Mutex<Data>,
    }

    const MIN_ACTIVE_CIRCS: usize = 2;

    enum PickType {
        Exist,
        New,
    }

    impl CircPool 
    {
        pub fn new(relay_pool: Arc<RelayPool>) -> Self {
            Self { relay_pool, data: Default::default()}
        }

        pub fn relay_pool(&self) -> &Arc<RelayPool> {
            &self.relay_pool
        }

        pub fn num_circs(&self) -> usize {
            self.data.lock().circs.len()
        }

        // pub async fn pick_or_wait(&self) -> Result<Arc<Circ>> {
        //     let mut rng = rand::thread_rng();
        //     let r: usize = rng.gen_range(0..3);
        //     self.data.lock().circs.get(id).is_some()
        // }

        const TRY_CIRCID_NUM: usize = 5;
        pub async fn scan<R>(&self, chmgr: &Arc<ChanMgr<R>>) -> Result<usize> 
        where
            R: Runtime,
        { 
            let mut new_circ = None;
            let mut num_circs = 0;

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
                    data.circs.insert(path.clone(), Circ { circ, score: 0 });
                    num_circs = data.circs.len();

                    data.rank.insert(CircScore { path, score: 0 });
                }

            }

            Ok(num_circs)
        }



        
    }

    pub async fn load(file: impl AsRef<Path>) -> Result<()> {
        Ok(())
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



mod channel_raw {
    macro_rules! dbgd {
        ($($arg:tt)* ) => (
            tracing::info!($($arg)*) // comment out this line to disable log
        );
    }

    use std::{sync::Arc, time::Duration, convert::TryFrom};

    use anyhow::{Result, bail};
    use arti_client::TorClient;
    use futures::{AsyncWriteExt, AsyncReadExt};
    use tokio::time::timeout;
    use tor_chanmgr::{ChannelConfig, Dormancy, ChannelUsage, ChanMgr};
    use tor_linkspec::OwnedCircTarget;
    use tor_netdir::{params::NetParameters, NetDir, Relay, hack_netdir::make_ed25519_id};
    use tor_proto::{channel::Channel, stream::StreamParameters, circuit::CircParameters};
    use tor_rtcompat::Runtime;

    use crate::scan::{self, RelayInfo, ToDebug, OwnedRelay};

    pub async fn run_raw<R>(tor_client: &TorClient<R>)-> Result<()> 
    where
        R: Runtime,
    { 
        let relays_file = "/Users/simon/.rtor-proxy/storage/rtor/work_relays.txt";

        let rt = tor_rtcompat::PreferredRuntime::current()?;
        let ch_cfg = ChannelConfig::default();
        let dormant = Dormancy::default();
        let netparams = NetParameters::default();
        
        let chanmgr = Arc::new(tor_chanmgr::ChanMgr::new(
            rt.clone(),
            &ch_cfg,
            dormant,
            &netparams,
        ));

        
        let netdir = tor_client.dirmgr().clone().upcast_arc();
        let task_h = chanmgr.launch_background_tasks(&rt, netdir)?;

        let netdir = tor_client.dirmgr().timely_netdir()?;

        // let relays: Vec<RelayInfo> = scan::load_to_collect(relays_file).await?;
        // dbgd!("loaded relays [{}]", relays.len());
 
        // let iter = relays.iter().filter_map(|v|{
        //     if v.is_flagged_exit() {
        //         netdir.by_id(&v.id)
        //     } else {
        //         None
        //     }
        // });

        {
            
            let r2 = netdir.by_id(&make_ed25519_id("FK7SwWET47+2UjP1b03TqGbGo4uJnjhomp4CnH7Ntv8")?);

            let r1 = netdir.by_id(&make_ed25519_id("w2j7gp0fAqDOsHt8ruIJM6wdFZz3/UEMiH4MGw3behE")?);

            if let (Some(relay1), Some(relay2)) = (r1, r2) {
                dbgd!("testing run_ch");
                // let (mut ch, provenance) = chanmgr.get_or_launch(&relay1, ChannelUsage::UserTraffic).await?;

                // run_ch1(&mut ch, &relay1).await?;
                // dbgd!("run_ch1 ok");
                // std::process::exit(0);

                run_ch2(&chanmgr, &relay1, &relay2).await?;
                dbgd!("run_ch2 ok");
                std::process::exit(0);
            }
        }




        let ids = vec![
            "FK7SwWET47+2UjP1b03TqGbGo4uJnjhomp4CnH7Ntv8",
            "w2j7gp0fAqDOsHt8ruIJM6wdFZz3/UEMiH4MGw3behE",
        ];

        let iter = ids.iter().filter_map(|v|{
            let r = make_ed25519_id(v);
            if let Ok(id) = r {
                netdir.by_id(&id)
            } else {
                None
            }
        });

        for relay in iter { 

            dbgd!("try relay [{:?}]", relay.to_debug());
            let r = chanmgr.get_or_launch(&relay, ChannelUsage::UserTraffic).await;
            match r {
                Ok((mut ch, prov)) => {
                    dbgd!("got channel by target [{:?}], provenance [{:?}]", relay.to_debug(), prov);
                    let r = timeout(Duration::from_secs(5), run_ch0(&mut ch, &relay)).await;
                    dbgd!("run_ch result {:?}", r);
                    if r.is_ok() { 
                        let r = r?;
                        if r.is_ok() {
                            std::process::exit(0);
                        // break;
                        }
                    }
                },
                Err(e) => {
                    dbgd!("fail to get channel by target [{:?}], error {:?}", relay.to_debug(), e);
                },
            }
        }
        
        bail!("try all relays but fail");
    }

    async fn run_ch0(ch: &mut Channel, relay: &Relay<'_>) -> Result<()> {

        let (pending_circ, reactor) = ch.new_circ().await?;
        dbgd!("new pending circ");
        tokio::spawn(async {
            let _ = reactor.run().await;
        });

        let mut param = CircParameters::default();
        param.set_extend_by_ed25519_id(false);
        // let circ = pending_circ.create_firsthop_fast(&param).await?;
        let circ = pending_circ.create_firsthop_ntor(relay, param).await?;
        dbgd!("created circ, path [{:?}]", circ.path());

        // let _r = circ.extend_ntor(relay, &CircParameters::default()).await?;

        let param = StreamParameters::default();
        let mut stream = circ.begin_stream("example.com", 80, Some(param)).await?;
        dbgd!("created stream");


        simple_http_get(&mut stream).await?;

        Ok(())
    }

    async fn run_ch2<R>(chanmgr: &Arc<ChanMgr<R>>, relay1: &Relay<'_>, relay2: &Relay<'_>) -> Result<()> 
    where
        R: Runtime
    {
        let owned1 = OwnedCircTarget::from_circ_target(relay1);
        let owned2 = OwnedCircTarget::from_circ_target(relay2);

        
        let owned1 = OwnedRelay::try_from(relay1)?;
        let owned2 = OwnedRelay::try_from(relay2)?;

        let (ch, _provenance) = chanmgr.get_or_launch(&owned1, ChannelUsage::UserTraffic).await?;

        let (pending_circ, reactor) = ch.new_circ().await?;
        dbgd!("new pending circ");
        tokio::spawn(async {
            let _ = reactor.run().await;
        });

        let param = CircParameters::default();
        // param.set_extend_by_ed25519_id(false);
        // let circ = pending_circ.create_firsthop_fast(&param).await?;
        let circ = pending_circ.create_firsthop_ntor(&owned1, param).await?;
        dbgd!("created circ, path [{:?}]", circ.path());

        let _r = circ.extend_ntor(&owned2, &CircParameters::default()).await?;

        let param = StreamParameters::default();
        let mut stream = circ.begin_stream("example.com", 80, Some(param)).await?;
        dbgd!("created stream");


        simple_http_get(&mut stream).await?;

        Ok(())
    }

    async fn simple_http_get(stream: &mut tor_proto::stream::DataStream ) -> Result<()> 
    { 
        eprintln!("connecting to example.com...");
    
        // Initiate a connection over Tor to example.com, port 80.
        // let mut stream = tor_client.connect(addr).await?;
    
        // let mut stream = tor_client.connect_with_prefs(("example.com", 80), StreamPrefs::new().ipv4_only()).await?;
    
    
        eprintln!("sending request...");
    
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            .await?;
    
        // IMPORTANT: Make sure the request was written.
        // Arti buffers data, so flushing the buffer is usually required.
        stream.flush().await?;
    
        eprintln!("reading response...");
    
        // Read and print the result.
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
    
        println!("{}", String::from_utf8_lossy(&buf));
    
        Ok(())
    }

}


