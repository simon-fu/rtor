#![feature(type_alias_impl_trait)]

/// - curl -vv  -x socks5h://localhost:9150 http://wtfismyip.com/json
/// - 申请bridge https://bridges.torproject.org/
/// - run_periodic_events 会被每隔1秒调用一次，层层会调用到 pick_n_relays
/// - TODO: curl客户端结束后，过一段时间conn bridge 才断开
/// - TODO: 使用github 的 arti/simon-hack1，而不是本地目录
/// - TODO: 支持命令行参数
/// - TODO: 支持 socks4
/// - TODO: socks5-proto 改成 socks5-server
/// - TODO: 直接用 exit relay 做代理，
///     使用 [client] -> [socks5 proxy] -> [exit] -> [target], 
///     代替 [client] -> [socks5 proxy] -> [gurad] -> [middle] -> [exit] -> [target]
/// - TODO: 官方计划支持 bridge 和 socks 等 outbound proxy，
///     详见：
///     https://gitlab.torproject.org/tpo/core/arti/-/issues/69
///     https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/686
///     https://gitlab.torproject.org/tpo/core/arti/-/milestones/10#tab-issues
/// 
/// - 超大文件用于测试下载速度 
///     https://www.thinkbroadband.com/download 
///     https://www.zhujizixun.com/4113.html


/// - issue
///     dropping TorClient will stuck in tor_rtcompat::scheduler::TaskSchedule::sleep_until_wallclock() and burning cpu
///     已提交 https://gitlab.torproject.org/tpo/core/arti/-/issues/572


/*

bootstrap process
=================
- TorClientBuilder::create_bootstrapped()
- TorClientBuilder::create_unbootstrapped()
- TorClient<R>::bootstrap()
- TorClient<R>::bootstrap_inner()
    self.dirmgr: Arc<dyn tor_dirmgr::DirProvider>
    self.dirmgr.bootstrap() 
- DirMgr::bootstrap()
- DirMgr::download_forever()
- bootstrap::download(Weak<DirMgr<R>>)
- bootstrap::download_attempt(&Arc<DirMgr<R>>,)
- bootstrap::fetch_multiple(Arc<DirMgr<R>>)
    let circmgr = dirmgr.circmgr()?;
    let netdir = dirmgr.netdir(tor_netdir::Timeliness::Timely).ok();
- bootstrap::fetch_single(Arc<CircMgr<R>>)
- tor_dirclient::get_resource()
- Arc<CircMgr<R>>::get_or_launch_dir()


connect process
===============
- TorClient::connect_with_prefs()
- TorClient::get_or_launch_exit_circ()
- Arc<CircMgr<R>>::get_or_launch_exit()

- CircuitBuilder<R>::plan_circuit()
- TargetCircUsage::build_path()

AbstractCircMgr::prepare_action  // action 是指circuit 是已经open，还是pending， 还是
AbstractCircMgr::plan_by_usage 
*/


// #![feature(unsafe_pin_internals)]


use std::str::FromStr;
use anyhow::Result;
use strum::EnumString;
use tracing_subscriber::EnvFilter;
use crate::{proxy::run_proxy, simple::simple_tor_client};


pub mod box_socks;
pub mod box_tcp;
pub mod util;
pub mod scan;
pub mod simple;
pub mod proxy;
pub mod tls2;



macro_rules! dbgd {
    ($($arg:tt)* ) => (
        tracing::info!($($arg)*) // comment out this line to disable log
    );
}

#[derive(Debug, PartialEq, EnumString)]
enum Cmd {
    Simple,
    Proxy,
    // ChRaw,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
// #[tokio::main]
async fn main() -> Result<()> {
    // const FILTER: &str = "info,rtor=info,tor_netdir::hack_netdir=debug";
    const FILTER: &str = "warn,rtor=info"; 

    let env_filter = match std::env::var_os(EnvFilter::DEFAULT_ENV) {
        Some(_v) => EnvFilter::from_default_env(),
        None => EnvFilter::from_str(FILTER)?,
    };

    tracing_subscriber::fmt()
    .with_env_filter(env_filter)
    .init();
    
    // let cmd = Cmd::from_str("Simple")?;
    let cmd = Cmd::from_str("Proxy")?;
    // let cmd = Cmd::from_str("ChRaw")?;

    let r = match cmd {
        Cmd::Simple => simple_tor_client().await,
        Cmd::Proxy => run_proxy().await,
        // Cmd::ChRaw => channel_raw::run_raw().await,
    };
    dbgd!("all finished with {:?}", r);

    r
}










