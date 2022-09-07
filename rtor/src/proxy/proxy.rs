use std::{sync::Arc, time::Duration, collections::HashSet, convert::{TryInto, TryFrom}};
use std::path::PathBuf;

use anyhow::{Result, Context, bail};
use arti_client::{config::{TorClientConfigBuilder, CfgPath}, TorClient, StreamPrefs, DangerouslyIntoTorAddr};
use crate::scan::{self, HashRelay};

use socks5_proto::{HandshakeRequest, HandshakeMethod, HandshakeResponse, Request, Response, Reply, Address, Command};
use tokio::net::{TcpListener, TcpStream};
use tor_netdir::NetDir;
use tor_rtcompat::Runtime;


use crate::scan::{BuilInRelays, ScanResult};


macro_rules! dbgd {
    ($($arg:tt)* ) => (
        tracing::info!($($arg)*) // comment out this line to disable log
    );
}


#[derive(Debug, Clone, Default)]
pub struct Args {
    storage_dir: Option<String>,
    config_dir: Option<String>,
    bootstrap_file: Option<String>,
    bootstrap_buildin: bool,
    socks_listen: Option<String>,
    scan_timeout_secs: Option<u64>,
    scan_concurrency: Option<usize>,
    override_min_guards: Option<usize>,
    override_normal_guards: Option<usize>,
    scan_interval_secs: Option<u64>,
}

impl Args {
    pub fn storage_dir(&self) -> &str {
        self.storage_dir.as_deref().unwrap_or_else(||"~/.rtor-proxy/storage")
    }

    pub fn config_dir(&self) -> &str {
        self.config_dir.as_deref().unwrap_or_else(||"~/.rtor-proxy/config")
    }

    pub fn state_dir(&self) -> String {
        format!("{}/state", self.storage_dir())
    }

    pub fn cache_dir(&self) -> String {
        format!("{}/cache", self.storage_dir())
    }

    pub fn work_relays_file(&self) -> String {
        format!("{}/rtor/work_relays.txt", self.storage_dir())
    }

    // pub fn temp_relays_file(&self) -> String {
    //     format!("{}/rtor/temp_relays.txt", self.storage_dir())
    // }

    pub fn socks_listen(&self) -> &str {
        self.socks_listen.as_deref().unwrap_or_else(||"127.0.0.1:9150")
    }

    pub fn scan_timeout(&self) -> Duration { 
        let secs = self.scan_timeout_secs.unwrap_or_else(||3);
        Duration::from_secs(secs)
    }

    pub fn scan_concurrency(&self) -> usize { 
        self.scan_concurrency.unwrap_or_else(||50)
    }

    pub fn override_min_guards(&self) -> usize {
        self.override_min_guards.unwrap_or_else(||5)
    }

    pub fn override_normal_guards(&self) -> usize {
        self.override_normal_guards.unwrap_or_else(||20)
    }

    pub fn scan_interval(&self) -> Duration {
        let secs = self.scan_interval_secs.unwrap_or_else(|| 60*10);
        Duration::from_secs(secs)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProxyConfig {
    pub storage_dir: String,
    pub config_dir: String,
    pub bootstrap_file: Option<String>,
    pub bootstrap_buildin: bool,
    pub socks_listen: String,
    pub scan_timeout: Duration,
    pub scan_concurrency: usize,
    pub override_min_guards: usize,
    pub override_normal_guards: usize,
    pub scan_interval: Duration,

    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub work_relays_file: PathBuf,
}

impl TryFrom<&Args> for ProxyConfig {
    type Error = anyhow::Error;
    fn try_from(src: &Args) -> Result<Self, Self::Error> { 
        Ok(Self {
            storage_dir: src.storage_dir().to_owned(),
            config_dir: src.config_dir().to_owned(),
            bootstrap_file: src.bootstrap_file.clone(),
            bootstrap_buildin: src.bootstrap_buildin,
            socks_listen: src.socks_listen().to_owned(),
            scan_timeout: src.scan_timeout(),
            scan_concurrency: src.scan_concurrency(),
            override_min_guards: src.override_min_guards(),
            override_normal_guards: src.override_normal_guards(),
            scan_interval: src.scan_interval(),

            state_dir: CfgPath::new(src.state_dir()).path()?,
            cache_dir: CfgPath::new(src.cache_dir()).path()?,
            work_relays_file:  CfgPath::new(src.work_relays_file()).path()?,
        })
    }
}



pub async fn run_proxy() -> Result<()> {  
    let args = Args::default();
    let args: Arc<ProxyConfig> = Arc::new((&args).try_into()?);
    

    {
        *tor_netdir::hack_netdir::hack().data().planb_guards_mut() = Some(Vec::with_capacity(1));
    }
    
    let mut first_active_guards = 0;

    let config = {    

        let relays = if let Some(bootstrap_relays_file) = &args.bootstrap_file {
            dbgd!("scan bootstraps by [From [{}]]", bootstrap_relays_file);
            scan_bootstraps(&args, Some(bootstrap_relays_file),).await?

        } else if args.bootstrap_buildin {
            dbgd!("scan bootstraps by [Force build-in]");
            scan_bootstraps(&args, None).await?

        } else if tokio::fs::metadata(&args.work_relays_file).await.is_err() {
            dbgd!("scan bootstraps by [Not exist [{:?}]]", args.work_relays_file);
            scan_bootstraps(&args, None).await?

        } else {
            // let relays = load_and_set_relays(&args.work_relays_file).await?;
            let file = &args.work_relays_file;
            let set = scan::load_result_filepath(file).await
            .with_context(||format!("fail to load bootstrap file [{:?}]", file))?;
            dbgd!("loaded relays [{}] from [{:?}]", set.len(), file);

            first_active_guards = set_active_guards("load relays", &set);

            if set.len() > 0 {
                // is_scan_bootstraps = false;
                set
            } else { 
                dbgd!("scan bootstraps by [Empty [{:?}]]", args.work_relays_file);
                scan_bootstraps( &args, None).await?
            }
        };

        if relays.len() == 0 {
            bail!("empty bootstrap relays")
        }

        let caches = relays.iter().map(|v|(&v.0).into()).collect();

        let mut builder = TorClientConfigBuilder::from_directories(
            &args.state_dir, 
            &args.cache_dir,
        );
        builder.tor_network().set_fallback_caches(caches);
        builder.build()?
    };

    let builder = TorClient::builder()
    .config(config);

    let tor_client = builder.create_bootstrapped().await?;
    dbgd!("bootstrapped ok");

    // let netdir = tor_client.dirmgr().timely_netdir().with_context(||"no timely netdir")?;
    // dbgd!("bootstrapped ok, relays {}", netdir.relays().count());

    {
        let tor_client = tor_client.clone();
        let args = args.clone();
        let mut scanner = RelayScanner::new(tor_client, args, first_active_guards);
        tokio::spawn(async move {
            loop {
                let r = scanner.scan_and_set_relays().await; 
                dbgd!("scan result: [{:?}]", r);
                scanner.wait_for_next().await
            }
        });
    }

    // if is_scan_bootstraps {
    //     dbgd!("scanning active guards...");

    //     let relays = netdir.relays().filter_map(|v|v.try_into().ok());
        
    //     let active_relays = scan::scan_relays_min_to_file(relays, args.scan_timeout(), args.scan_concurrency(), 10, &work_relays_file).await?;

    //     let ids: Vec<_> = active_relays.into_iter()
    //     .filter(|v|v.0.is_flagged_guard())
    //     .map(|v|v.0.id)
    //     .collect();
        
    //     dbgd!("bootstrapped active guards {}", ids.len());
    //     if ids.len() > 0 { 
    //         dbgd!("set active guards {}", ids.len());
    //         *tor_netdir::hack_netdir::hack().data().guards_mut() = Some(ids.into());
    //         // guards_ids = Some(ids);
    //     }
        
    // } else {
    //     dbgd!("bootstrapped ok, relays {}", netdir.relays().count());
    // }


    // simple_http_get(&tor_client, ("example.com", 80)).await?;
    run_socks5_bridge(&args, &tor_client).await?;
    
    Ok(())
}


pub struct RelayScanner<R:Runtime> { 
    tor_client: TorClient<R>,
    args: Arc<ProxyConfig>,
    last_guards: usize,
}

impl<R> RelayScanner<R> 
where
    R: Runtime,
{
    pub fn new(tor_client: TorClient<R>, args: Arc<ProxyConfig>, last_guards: usize) -> Self {
        Self { tor_client, args, last_guards}
    }

    // pub async fn load_and_set_relays(&mut self) -> Result<HashSet<HashRelay>> {
    //     let file = &self.args.work_relays_file;

    //     let set = scan::load_result_filepath(file).await
    //     .with_context(||format!("fail to load bootstrap file [{:?}]", file))?;
    
    //     {
    //         // let ids: Vec<_> = set.iter().filter(|v|v.0.is_flagged_guard()).map(|v|v.0.id.clone()).collect();
    //         // self.set_active_guards(ids);
    //         let num = set_active_guards("load relays", set.iter().map(|v|&v.0));
    //     }
    //     Ok(set)
    // }

    pub async fn wait_for_next(&self) {
        tokio::time::sleep(self.args.scan_interval).await;
    }

    pub async fn scan_and_set_relays(&mut self) -> Result<()> {
        let netdir = self.tor_client.dirmgr().timely_netdir()?;
        
        let set = scan_and_set_relays(netdir, self.args.clone(), self.last_guards).await?;
        
        // let ids: Vec<_> = set.iter().filter(|v|v.0.is_flagged_guard()).map(|v|v.0.id.clone()).collect();

        let num = set_active_guards("scan result", &set);

        if num >= self.args.override_normal_guards 
        || num >= self.last_guards {
            scan::write_relays_to_filepath(set.iter().map(|v|&v.0), &self.args.work_relays_file).await?;    
        }

        Ok(())
    }

}

pub async fn scan_and_set_relays(netdir: Arc<NetDir>, args: Arc<ProxyConfig>, last_guards: usize) -> Result<HashSet<HashRelay>> {
    // let netdir = self.tor_client.dirmgr().timely_netdir()?;
    
    struct Ctx {
        set: HashSet<HashRelay>,
        last_guards: usize,
        args: Arc<ProxyConfig>,
        active_guards: usize,
    }

    let mut ctx = Ctx {
        set: HashSet::new(),
        last_guards,
        args,
        active_guards: 0,
    };

    async fn insert_to_set(ctx: &mut Ctx, (relay, r): ScanResult) -> Result<()> {
        if r.is_ok() {
            let is_flagged_guard = relay.is_flagged_guard();
            if is_flagged_guard {
                ctx.active_guards += 1;
            }
            dbgd!("insert relay [{:?}], guards [{}/{}]", relay, ctx.active_guards, ctx.set.len()+1);
            ctx.set.insert(HashRelay(relay));

            if is_flagged_guard && ctx.active_guards > ctx.last_guards { 
                
                
                // 如果在扫描过程中，每隔一段时间保存结果
                // if ctx.active_guards == ctx.args.override_min_guards 
                // || ctx.active_guards == ctx.args.override_normal_guards 
                if ctx.active_guards % ctx.args.override_min_guards == 0
                {
                    // let ids: Vec<_> = ctx.set.iter().filter(|v|v.0.is_flagged_guard()).map(|v|v.0.id.clone()).collect();
                    set_active_guards("scan in-progress", &ctx.set);
                    scan::write_relays_to_filepath(ctx.set.iter().map(|v|&v.0), &ctx.args.work_relays_file).await?;
                    // ctx.last_guards = ctx.active_guards;
                }
            }
        }
        Ok(())
    }

    let relays = netdir.relays().filter_map(|v|v.try_into().ok());
    scan::scan_relays(relays, ctx.args.scan_timeout, ctx.args.scan_concurrency, &mut ctx, &insert_to_set).await?;

    Ok(ctx.set)
}

// async fn load_and_set_relays(file: impl AsRef<Path>) -> Result<HashSet<HashRelay>> {
//     let set = scan::load_result_filepath(&file).await
//     .with_context(||format!("fail to load bootstrap file [{:?}]", file.as_ref()))?;

//     {
//         // let ids: Vec<_> = set.iter().filter(|v|v.0.is_flagged_guard()).map(|v|v.0.id.clone()).collect();
//         set_active_guards("load relays", &set );
//     }
//     Ok(set)
// }

// pub async fn scan_relays<I, C, F>(mut relays: I, timeout: Duration, concurrency: usize, ctx: &mut C, func: &F) -> Result<()>
// where
//     I: Iterator<Item = RelayInfo>,
//     F: for<'local> AsyncHandler<'local, C, ScanResult>
// {

// }
// fn set_active_guards(prefix: &str, ids: Vec<Ed25519Identity>) -> bool 

// fn set_active_guards<'a, I>(prefix: &str, relays: I) -> usize 
// where
//     I: Iterator<Item = &'a RelayInfo>,
fn set_active_guards(prefix: &str, set: &HashSet<HashRelay>) -> usize 
{
    let ids: Vec<_> = set.iter()
    .filter(|v|v.0.is_flagged_guard())
    .map(|v|v.0.id.clone())
    .collect();

    let num = ids.len();
    if ids.len() > 0 {
        dbgd!("{}: set active guards {}", prefix, ids.len());
        *tor_netdir::hack_netdir::hack().data().guards_mut() = Some(ids.into());
    }
    num
}



async fn run_socks5_bridge<R>(args: &Arc<ProxyConfig>, tor_client: &TorClient<R>) -> Result<()> 
where
    R: Runtime,
{
    let listener = TcpListener::bind(args.socks_listen.as_str()).await
        .with_context(||format!("fail to listen at [{}]", args.socks_listen))?;
    dbgd!("socks5 listening at [{}]", args.socks_listen);

    loop {
        let (mut socket, addr) = listener.accept().await?;
        dbgd!("socks5 client connected from [{}]", addr);

        let tor_client0 = tor_client.clone();
        tokio::spawn(async move {
            let r = conn_task(&mut socket, &tor_client0).await;
            dbgd!("conn finished with [{:?}]", r);
        });
    }
    
}

async fn conn_task<R>(src: &mut TcpStream, tor_client: &TorClient<R>) -> Result<()> 
where
    R: Runtime,
{ 
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
                let resp = Response::new(Reply::GeneralFailure, Address::unspecified());
                resp.write_to(src).await?;
                let _ = src.shutdown().await;
                return Err(err.into());
            }
        }
    };


    match &req.command {
        Command::Connect => {},
        _ => {
            let resp = Response::new(Reply::CommandNotSupported, Address::unspecified());
            resp.write_to(src).await?;
            let _ = src.shutdown().await;
            bail!("unsupported client commnad [{:?}]", req.command);
        }
    }

    dbgd!("connecting to target [{:?}]", req.address);
    let r = match &req.address {
        Address::SocketAddress(addr) => tor_client.connect_with_prefs(addr.into_tor_addr_dangerously()?, StreamPrefs::new().ipv4_only()).await,
        Address::DomainAddress(host, port) => tor_client.connect_with_prefs((host.as_str(), *port), StreamPrefs::new().ipv4_only()).await,
    };

    dbgd!("connecting is ok [{:?}]", r.is_ok());

    let mut dst = match r {
        Ok(dst) => dst,
        Err(e) => {
            let resp = Response::new(Reply::HostUnreachable, Address::unspecified());
            resp.write_to(src).await?;
            let _ = src.shutdown().await;
            bail!("fail to connect target [{:?}] error [{:?}]", req.address, e);
        },
    };

    dbgd!("connected to target [{:?}]", req.address);

    {
        let resp = Response::new(Reply::Succeeded, Address::unspecified());
        resp.write_to(src).await?;
    }
    
    tokio::io::copy_bidirectional(&mut dst, src).await?;

    Ok(())
}

async fn scan_bootstraps(
    args: &ProxyConfig,
    bootstrap_relays_file: Option<&str>,
) -> Result<HashSet<HashRelay>> {

    let bootstrap_relays = if let Some(bootstrap_relays_file) = bootstrap_relays_file {
        let r = scan::load_result_filepath(bootstrap_relays_file).await;
        match r {
            Ok(relays) => { 
                dbgd!("loaded bootstrap relays [{}] from [{}]", relays.len(), bootstrap_relays_file);
                if relays.len() > 0 {
                    Some(relays)
                } else {
                    None
                }
            },
            Err(_e) => { 
                dbgd!("fail to load bootstrap relays from [{}]", bootstrap_relays_file);
                None
            },
        }
    } else {
        None
    };


    let timeout = args.scan_timeout;
    let concurrency = args.scan_concurrency;

    let mut active_relays = HashSet::new();
    if let Some(relays) = bootstrap_relays {
        let relays = relays.into_iter().map(|v|v.0);
        scan::scan_relays_to_set(relays, timeout, concurrency, &mut active_relays).await?;
    } else {
        let fallbacks = BuilInRelays::default();
        dbgd!("use build-in bootstrap relays [{}]", fallbacks.len());
        scan::scan_relays_to_set(fallbacks.relays_iter(), timeout, concurrency, &mut active_relays).await?;
    }

    // {
    //     let file_path = &work_relays_file;
    //     scan::write_relays_to_file(active_relays.iter().map(|v|&v.0), file_path).await
    //     .with_context(||format!("fail to write file [{}]", file_path))?;
    //     dbgd!("wrote active bootstrap relays [{}] to [{}]", active_relays.len(), file_path);
    // }

    Ok(active_relays)
}
