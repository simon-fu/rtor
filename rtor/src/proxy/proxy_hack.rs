use std::{sync::Arc, collections::HashSet, convert::TryInto};

use anyhow::{Result, Context, bail};
use arti_client::{config::{TorClientConfigBuilder}, TorClient, StreamPrefs, DangerouslyIntoTorAddr};
use tor_linkspec::HasRelayIds;
use tracing::{debug, info};
use crate::{scan::{self, HashRelay}, proxy::{scan_bootstraps, ProxyConfig, Args} };

use socks5_proto::{HandshakeRequest, HandshakeMethod, HandshakeResponse, Request, Response, Reply, Address, Command};
use tokio::{net::{TcpListener, TcpStream}, sync::oneshot};
use tor_netdir::{NetDir, hack_netdir};
use tor_rtcompat::Runtime;


use crate::scan::ScanResult;




pub async fn run_proxy() -> Result<()> {  
    let args = Args::default();
    let args: Arc<ProxyConfig> = Arc::new((&args).try_into()?);
    
    {
        *hack_netdir::hack().data().planb_guards_mut() = Some(Vec::with_capacity(1));
    }
    
    let mut first_active_guards = 0;

    let config = {    

        let relays = if let Some(bootstrap_relays_file) = &args.bootstrap_file {
            info!("scan bootstraps by [From [{}]]", bootstrap_relays_file);
            scan_bootstraps(&args, Some(bootstrap_relays_file),).await?

        } else if args.bootstrap_buildin {
            info!("scan bootstraps by [Force build-in]");
            scan_bootstraps(&args, None).await?

        } else if tokio::fs::metadata(&args.reachable_relays_file).await.is_err() {
            info!("scan bootstraps by [Not exist [{:?}]]", args.reachable_relays_file);
            scan_bootstraps(&args, None).await?

        } else {
            // let relays = load_and_set_relays(&args.work_relays_file).await?;
            let file = &args.reachable_relays_file;
            let set = scan::load_result_filepath(file).await
            .with_context(||format!("fail to load bootstrap file [{:?}]", file))?;
            info!("loaded relays [{}] from [{:?}]", set.len(), file);

            first_active_guards = set_active_guards("load relays", &set);

            if set.len() > 0 {
                // is_scan_bootstraps = false;
                set
            } else { 
                info!("scan bootstraps by [Empty [{:?}]]", args.reachable_relays_file);
                scan_bootstraps( &args, None).await?
            }
        };

        if relays.len() == 0 {
            bail!("empty bootstrap relays")
        }

        let caches = relays.iter().map(|v|v.0.as_ref().into()).collect();

        let mut builder = TorClientConfigBuilder::from_directories(
            &args.state_dir, 
            &args.cache_dir,
        );
        builder.tor_network().set_fallback_caches(caches);
        builder.build()?
    };

    let builder = TorClient::builder()
    .config(config);

    info!("bootstrapping...");
    let tor_client = builder.create_bootstrapped().await?;
    info!("bootstrapped ok");

    // {
    //     channel_raw::run_raw(&tor_client).await?;
    // }

    {
        let (tx, rx) = oneshot::channel();
        let tor_client = tor_client.clone();
        let args = args.clone();
        let mut scanner = RelayScanner::new(tor_client, args, first_active_guards, Some(tx));
        
        tokio::spawn(async move {
            loop {
                let r = scanner.scan_and_set_relays().await; 
                info!("scan result: [{:?}]", r);
                scanner.wait_for_next().await
            }
        });

        let no_guards = {
            hack_netdir::hack().data().guards_mut().is_none()
        };

        if no_guards {
            let _r = rx.await;
        }
    }


    run_socks5_bridge(&args, &tor_client).await?;
    
    Ok(())
}



pub struct RelayScanner<R:Runtime> { 
    tor_client: TorClient<R>,
    args: Arc<ProxyConfig>,
    last_guards: usize,
    tx: Option<oneshot::Sender<()>>,
}

impl<R> RelayScanner<R> 
where
    R: Runtime,
{
    pub fn new(tor_client: TorClient<R>, args: Arc<ProxyConfig>, last_guards: usize, tx: Option<oneshot::Sender<()>>) -> Self {
        Self { tor_client, args, last_guards, tx}
    }

    pub async fn wait_for_next(&self) {
        tokio::time::sleep(self.args.scan_interval).await;
    }

    pub async fn scan_and_set_relays(&mut self) -> Result<()> {
        let netdir = self.tor_client.dirmgr().timely_netdir()?;
        
        let set = scan_and_set_relays(netdir, self.args.clone(), self.last_guards, self.tx.take()).await?;
        
        // let ids: Vec<_> = set.iter().filter(|v|v.0.is_flagged_guard()).map(|v|v.0.id.clone()).collect();

        let num = set_active_guards("scan result", &set);

        if num >= self.args.override_normal_guards 
        || num >= self.last_guards {
            scan::write_relays_to_filepath(set.iter().map(|v|v.0.as_ref()), &self.args.reachable_relays_file).await?;    
        }

        Ok(())
    }

}

pub async fn scan_and_set_relays(netdir: Arc<NetDir>, args: Arc<ProxyConfig>, last_guards: usize, tx: Option<oneshot::Sender<()>>) -> Result<HashSet<HashRelay>> {
    // let netdir = self.tor_client.dirmgr().timely_netdir()?;
    
    struct Ctx {
        set: HashSet<HashRelay>,
        last_guards: usize,
        args: Arc<ProxyConfig>,
        active_guards: usize,
        tx: Option<oneshot::Sender<()>>,
    }

    let mut ctx = Ctx {
        set: HashSet::new(),
        last_guards,
        args,
        active_guards: 0,
        tx,
    };

    async fn insert_to_set(ctx: &mut Ctx, (relay, r): ScanResult) -> Result<()> {
        if r.is_ok() {
            let is_flagged_guard = relay.is_flagged_guard();
            if is_flagged_guard {
                ctx.active_guards += 1;
            }
            debug!("insert relay [{:?}], guards [{}/{}]", relay, ctx.active_guards, ctx.set.len()+1);
            ctx.set.insert(HashRelay(relay));

            if is_flagged_guard && ctx.active_guards > ctx.last_guards { 
                
                
                // 如果在扫描过程中，每隔一段时间保存结果
                // if ctx.active_guards == ctx.args.override_min_guards 
                // || ctx.active_guards == ctx.args.override_normal_guards 
                if ctx.active_guards % ctx.args.override_min_guards == 0
                {
                    // let ids: Vec<_> = ctx.set.iter().filter(|v|v.0.is_flagged_guard()).map(|v|v.0.id.clone()).collect();
                    set_active_guards("scan in-progress", &ctx.set);
                    scan::write_relays_to_filepath(ctx.set.iter().map(|v|v.0.as_ref()), &ctx.args.reachable_relays_file).await?;
                    if let Some(tx) = ctx.tx.take() {
                        let _r = tx.send(());
                    }
                    // ctx.last_guards = ctx.active_guards;
                }
            }
        }
        Ok(())
    }

    let total = netdir.relays().count();
    info!("scanning relays [{}]...", total);
    let relays = netdir.relays()
    .filter_map(|v|v.try_into().ok().map(|v|Arc::new(v)));
    scan::scan_relays(relays, ctx.args.scan_timeout, ctx.args.scan_concurrency, &mut ctx, &insert_to_set).await?;
    info!("scanning result [{}/{}]...", ctx.set.len(), total);

    Ok(ctx.set)
}


fn set_active_guards(prefix: &str, set: &HashSet<HashRelay>) -> usize 
{
    // let ids: Vec<_> = set.iter()
    // .filter(|v|v.0.is_flagged_guard())
    // .map(|v|v.0.id.clone())
    // .collect();

    let ids: Vec<_> = set.iter()
    .filter(|v|v.0.is_flagged_guard())
    .filter_map(|v|v.0.ed_identity().map(|v|*v))
    .collect();

    // .filter_map(|v|v.try_into().ok())

    let num = ids.len();
    if ids.len() > 0 {
        info!("{}: set active guards {}", prefix, ids.len());
        *hack_netdir::hack().data().guards_mut() = Some(ids.into());
    }
    num
}



async fn run_socks5_bridge<R>(args: &Arc<ProxyConfig>, tor_client: &TorClient<R>) -> Result<()> 
where
    R: Runtime,
{
    let listener = TcpListener::bind(args.socks_listen.as_str()).await
        .with_context(||format!("fail to listen at [{}]", args.socks_listen))?;
    info!("socks5 listening at [{}]", args.socks_listen);

    loop {
        let (mut socket, addr) = listener.accept().await?;
        debug!("socks5 client connected from [{}]", addr);

        let tor_client0 = tor_client.clone();
        tokio::spawn(async move {
            let r = conn_task(&mut socket, &tor_client0).await;
            debug!("conn finished with [{:?}]", r);
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

    debug!("connecting to target [{:?}]", req.address);
    let r = match &req.address {
        Address::SocketAddress(addr) => tor_client.connect_with_prefs(addr.into_tor_addr_dangerously()?, StreamPrefs::new().ipv4_only()).await,
        Address::DomainAddress(host, port) => tor_client.connect_with_prefs((host.as_str(), *port), StreamPrefs::new().ipv4_only()).await,
    };

    debug!("connecting is ok [{:?}]", r.is_ok());

    let mut dst = match r {
        Ok(dst) => dst,
        Err(e) => {
            let resp = Response::new(Reply::HostUnreachable, Address::unspecified());
            resp.write_to(src).await?;
            let _ = src.shutdown().await;
            bail!("fail to connect target [{:?}] error [{:?}]", req.address, e);
        },
    };

    debug!("connected to target [{:?}]", req.address);

    {
        let resp = Response::new(Reply::Succeeded, Address::unspecified());
        resp.write_to(src).await?;
    }
    
    tokio::io::copy_bidirectional(&mut dst, src).await?;

    Ok(())
}
