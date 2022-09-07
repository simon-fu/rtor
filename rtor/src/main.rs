/// - curl -vv  -x socks5h://localhost:9150 http://wtfismyip.com/json
/// - 申请bridge https://bridges.torproject.org/
/// - run_periodic_events 会被每隔1秒调用一次，层层会调用到 pick_n_relays
/// - TODO： 直接用 exit relay 做代理，
///    使用 [client] -> [socks5 proxy] -> [exit] -> [target], 
///    代替 [client] -> [socks5 proxy] -> [gurad] -> [middle] -> [exit] -> [target]
/// 

/* 
/// - issue
///   dropping TorClient will stuck in tor_rtcompat::scheduler::TaskSchedule::sleep_until_wallclock() and burning cpu

/// readme.rs
#[tokio::main]
async fn main() -> Result<()> { 
    old_main().await?;
    println!("sleep forever");
    tokio::time::sleep(std::time::Duration::from_secs(999999)).await; // burning cpu here
    Ok(())
}

async fn old_main() -> Result<()> {
    ...
}
*/



// #![feature(unsafe_pin_internals)]

use std::{str::FromStr, sync::Arc, time::Duration};
use anyhow::{Result, Context};
use arti_client::{config::{TorClientConfigBuilder}, TorClient, StreamPrefs, TorClientConfig, IntoTorAddr};
use box_socks::SocksPrefRuntime;
use futures::{AsyncWriteExt, AsyncReadExt};
use strum::EnumString;


use tor_netdir::NetDir;
use tor_rtcompat::Runtime;
use tracing_subscriber::EnvFilter;

use crate::proxy::run_proxy;


pub mod box_socks;
pub mod box_tcp;
pub mod util;
pub mod scan;
// pub mod socks5;
pub mod proxy;

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

macro_rules! dbgd {
    ($($arg:tt)* ) => (
        tracing::info!($($arg)*) // comment out this line to disable log
    );
}

#[derive(Debug, PartialEq, EnumString)]
enum Cmd {
    Simple,
    Manual,
    Proxy,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
// #[tokio::main]
async fn main() -> Result<()> {
    // const FILTER: &str = "info,rtor=info,tor_netdir::hack_netdir=debug";
    const FILTER: &str = "info"; 

    let env_filter = match std::env::var_os(EnvFilter::DEFAULT_ENV) {
        Some(_v) => EnvFilter::from_default_env(),
        None => EnvFilter::from_str(FILTER)?,
    };

    tracing_subscriber::fmt()
    .with_env_filter(env_filter)
    .init();
    
    // let cmd = Cmd::from_str("Simple")?;
    // let cmd = Cmd::from_str("Manual")?;
    let cmd = Cmd::from_str("Proxy")?;
    let r = match cmd {
        Cmd::Simple => simple_proxy().await,
        Cmd::Manual => manual_download_dir().await,
        Cmd::Proxy => run_proxy().await,
    };
    dbgd!("all finished with {:?}", r);
    // tokio::time::sleep(Duration::from_secs(5000000)).await;
    r
}



// async fn run_socks5_bridge0<R>(args: &Args, tor_client: &TorClient<R>) -> Result<()> 
// where
//     R: Runtime,
// {
//     // let opt: Opt = Opt::from_args();
//     let mut config = fast_socks5::server::Config::default();
//     let request_timeout_secs = 10;
//     config.set_request_timeout(request_timeout_secs);
//     // config.set_skip_auth(false);
//     // config.set_authentication(fast_socks5::server::SimpleUserPassword { 
//     //     username: "username".into(), 
//     //     password: "password".into() 
//     // });

//     let mut listener = Socks5Server::bind(args.socks_listen()).await?;
//     listener.set_config(config);

//     let mut incoming = listener.incoming();

//     dbgd!("socks server listening at [{}]", args.socks_listen());

//     while let Some(socket_res) = incoming.next().await {
//         match socket_res {
//             Ok(socket) => { 
//                 tokio::spawn(async move {
//                     let r = conn_task0(socket).await;
//                 });
//                 // spawn_and_log_error(socket.upgrade_to_socks5());
//             }
//             Err(err) => {
//                 bail!("accept error = {:?}", err);
//             }
//         }
//     }
//     Ok(())
// }

// async fn conn_task0<T>(socket: Socks5Socket<T>) -> Result<()> 
// where
//     T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
// {
//     let mut socket = socket.upgrade_to_socks5().await?; 

//     Ok(())
// }






async fn manual_download_dir() -> Result<()> { 
    
    let guard_ids = vec![
        "FK7SwWET47+2UjP1b03TqGbGo4uJnjhomp4CnH7Ntv8",
        "ciWaq9i2Xj4qVPcx9pLfRP9b6J9T1ZwEnC83blSpUcc",
        "5nHccFo2jQ2b7PDxEdY5vNcPn++nHZJRW32SbLJMqnQ",
        "w2j7gp0fAqDOsHt8ruIJM6wdFZz3/UEMiH4MGw3behE",
        "TipUY3Pag9HRNflLHLlXaePDfaCMUVLOMHabRN3nU6g",
    ];

    // for id in &guard_ids {
    //     // let r = netdir.by_id(id);
    //     // dbgd!("search guard [{}] -> [{}]", id, r.is_some());
    //     print_relay(&netdir, id);
    // }

    // netdir.filter_guards(guard_ids);
    let ids = tor_netdir::hack_netdir::make_ids(guard_ids)?;
    *tor_netdir::hack_netdir::hack().data().guards_mut() = Some(ids);


    let (tor_client, client_config) = create_client_with_socks(Some(2)).with_context(||"create client with socks fail")?;

    tor_client.bootstrap().await?;

    tokio::time::sleep(Duration::from_secs(5)).await;

    // dbgd!("start scanning relays...");
    // let concurrency = 50;
    // const FILE_PATH1: &str = "/tmp/scan_relays_1.txt";
    // const FILE_PATH_FINAL: &str = "/tmp/scan_relays_final.txt";

    // // let relays = netdir.relays()
    // // .filter(|v|v.is_flagged_guard())
    // // .map(|v|v.into());
    // // scan::scan_relays_to_file(relays, Duration::from_secs(3), 10, FILE_PATH1).await?;

    // let netdir = tor_client.dirmgr().timely_netdir()?;
    // let relays = netdir.relays()
    // // .filter(|v|v.is_flagged_guard())
    // .take(concurrency * 3 + 1)
    // .filter_map(|v|v.try_into().ok());
    
    // // scan::scan_relays_to_file(relays, Duration::from_secs(3), concurrency, FILE_PATH1).await?;
    // // let relays = scan::open_result_file(FILE_PATH1).await?
    // // .read_all_to_hash_set().await?;
    // // dbgd!("first scan done with relays [{}]", relays.len());
    // // let relays = relays.into_iter()
    // // .map(|v|v.0);

    // scan::scan_relays_to_file(relays, Duration::from_secs(3), concurrency, FILE_PATH_FINAL).await?;

    // let guard_ids = vec![
    //     fallback::make_ed25519_id("FK7SwWET47+2UjP1b03TqGbGo4uJnjhomp4CnH7Ntv8"),
    //     fallback::make_ed25519_id("ciWaq9i2Xj4qVPcx9pLfRP9b6J9T1ZwEnC83blSpUcc"),
    //     fallback::make_ed25519_id("5nHccFo2jQ2b7PDxEdY5vNcPn++nHZJRW32SbLJMqnQ"),
    //     fallback::make_ed25519_id("w2j7gp0fAqDOsHt8ruIJM6wdFZz3/UEMiH4MGw3behE"),
    //     fallback::make_ed25519_id("TipUY3Pag9HRNflLHLlXaePDfaCMUVLOMHabRN3nU6g"),
    // ];

    
    
    simple_http_get(&tor_client, ("example.com", 80)).await?;
    tokio::time::sleep(Duration::from_secs(5000000)).await;

    // let total_relays = netdir.relays().count();
    // let mut relay_works = Vec::new();
    // for (index, relay) in netdir.relays().enumerate() {
    //     let index = index + 1;
    //     // let r = netdir.by_id(relay.id());

    //     // dbgd!("realy => {:?}, {:?}\n", relay.rs(), relay.md());
    //     if !relay.rs().is_flagged_guard() {
    //         dbgd!("relay[{}/{}]: [{}] ignore NOT guard, {:?}", index, total_relays, relay.id(), relay.rs().flags());
    //         continue;
    //     }

    //     let mut connect_able = false;
    //     for addr in relay.rs().addrs() {
    //         dbgd!("relay[{}/{}]: [{}] -> [{}] connecting", index, total_relays, relay.id(), addr);
    //         const TIMEOUT: Duration = Duration::from_secs(5);
    //         let r = connect_with_timeout(addr, TIMEOUT).await;
    //         match r {
    //             Ok(_s) => {
    //                 dbgd!("relay[{}/{}]: [{}] -> [{}] connect ok", index, total_relays, relay.id(), addr);
    //                 connect_able = true;
    //             },
    //             Err(e) => {
    //                 dbgd!("relay[{}/{}]: [{}] -> [{}] connect fail [{:?}]", index, total_relays, relay.id(), addr, e);
    //             },
    //         }
    //     }
    //     if connect_able {
    //         relay_works.push(relay);
    //     }
    //     dbgd!("on-going: connect-able relays {}\n", relay_works.len());
    // }
    // dbgd!("connect attempts done, connect-able relays {}", relay_works.len());

    // dbgd!("sleep forever");
    // tokio::time::sleep(std::time::Duration::from_secs(999999)).await;

    Ok(())
}

// async fn connect_with_timeout(addr: &SocketAddr, timeout: Duration) -> Result<()> {
//     let _s = tokio::time::timeout(timeout, TcpStream::connect(addr)).await??;
//     // .with_context(||"timeout")??;
//     Ok(())
// }

fn create_client_with_socks(max_targets: Option<usize>,) -> Result<(TorClient<SocksPrefRuntime>, TorClientConfig)> {
    let config = {
        let mut builder = TorClientConfigBuilder::from_directories(STATE_DIR, CACHE_DIR);
        
        builder.tor_network().set_fallback_caches(vec![
            fallback::make(
                "160B5805A781D93390D4A2AE05EA9C5B438E7967",
                "eFCu/xAod8SMUmLvtfsibUKYf5HgTT7kylb3lpKp2tA",
                &[
                    "162.200.149.221:9001"
                ],
            ),
    
            // Peer ed25519 id not as expected
            fallback::make(
                "2479ADEEA2FB4B99CB887C962ABBC648B44F7B6F",
                "Rq3RHdRQQdjbpmF4VBgMvi6a3lOHNnXM0K6qwlxHj5Q",
                &[
                    "77.162.68.75:9001"
                ],
            ),
    
            // Doesn't seem to be a tor relay
            fallback::make(
                "EF18418EE9B5E5CCD0BB7546869AC10BA625BAC8",
                "YU12MoJWSmk+4N90lEY1vG9kXLffr80/1Lroeo6Xsvo",
                &[
                    "185.191.127.231:443"
                ],
            ),
        ]);

        builder.build()?
    };
    let config0 = config.clone();
    
    
    let socks_args = Some(box_socks::SocksArgs {
        server: "127.0.0.1:7890".to_owned(),
        username: None,
        password: None,
        max_targets,
    });

    let runtime = box_socks::create_runtime(socks_args)?;

        
    let builder = TorClient::with_runtime(runtime)
    .config(config);
    // let tor_client = builder.create_bootstrapped().await?;
    let tor_client = builder.create_unbootstrapped()?;

    // let netdir = tor_client.dirmgr().timely_netdir()?;
    // dbgd!("pull_netdir done");

    // let relays = netdir.relays()
    // .filter_map(|v|v.try_into().ok());
    // scan::scan_relays_to_file(relays, Duration::from_secs(3), 1, "/tmp/111.txt").await?;


    Ok((tor_client, config0))
}

fn create_client_with_fallbacks() -> Result<(TorClient<impl Runtime>, TorClientConfig)> {
    let config = {
        let mut builder = TorClientConfigBuilder::from_directories(STATE_DIR, CACHE_DIR);
        builder.tor_network().set_fallback_caches(vec![
            fallback::make(
                "160B5805A781D93390D4A2AE05EA9C5B438E7967",
                "eFCu/xAod8SMUmLvtfsibUKYf5HgTT7kylb3lpKp2tA",
                &[
                    "162.200.149.221:9001"
                ],
            ),
    
            // Peer ed25519 id not as expected
            fallback::make(
                "2479ADEEA2FB4B99CB887C962ABBC648B44F7B6F",
                "Rq3RHdRQQdjbpmF4VBgMvi6a3lOHNnXM0K6qwlxHj5Q",
                &[
                    "77.162.68.75:9001"
                ],
            ),
    
            // Doesn't seem to be a tor relay
            fallback::make(
                "EF18418EE9B5E5CCD0BB7546869AC10BA625BAC8",
                "YU12MoJWSmk+4N90lEY1vG9kXLffr80/1Lroeo6Xsvo",
                &[
                    "185.191.127.231:443"
                ],
            ),
        ]);
        builder.build()?
    };
    let config0 = config.clone();
    
    
    // let socks_args = Some(box_socks::SocksArgs {
    //     server: "127.0.0.1:7890".to_owned(),
    //     username: None,
    //     password: None,
    //     max_targets: Some(0),
    // });

    // let runtime = box_socks::create_runtime(socks_args)?;

        
    let builder = TorClient::builder()
    .config(config);
    // let tor_client = builder.create_bootstrapped().await?;
    let tor_client = builder.create_unbootstrapped()?;

    // let netdir = tor_client.dirmgr().timely_netdir()?;

    Ok((tor_client, config0))
}



const STATE_DIR: &str = "/tmp/arti-client/state";
const CACHE_DIR: &str = "/tmp/arti-client/cache";

async fn simple_proxy() -> Result<()> {
    {
        let r =  arti_client::config::default_config_files()?;
        eprintln!("default_config_files: [{:?}]", r);
    }


    let mut builder = TorClientConfigBuilder::from_directories(STATE_DIR, CACHE_DIR);
    
    // builder.tor_network().set_fallback_caches(vec![fallback::make(
    //     "B9208EAD1E688E9EE43A05159ACD4638EB4DFD8A",
    //     "LTbH9g0Ol5jVSUy6GVgRyOSeYVTctU/xyAEwYqh385o",
    //     &[
    //         "140.78.100.16:8443"
    //     ],
    // )]);

    builder.tor_network().set_fallback_caches(vec![
        fallback::make(
            "160B5805A781D93390D4A2AE05EA9C5B438E7967",
            "eFCu/xAod8SMUmLvtfsibUKYf5HgTT7kylb3lpKp2tA",
            &[
                "162.200.149.221:9001"
            ],
        ),

        // Peer ed25519 id not as expected
        fallback::make(
            "2479ADEEA2FB4B99CB887C962ABBC648B44F7B6F",
            "Rq3RHdRQQdjbpmF4VBgMvi6a3lOHNnXM0K6qwlxHj5Q",
            &[
                "77.162.68.75:9001"
            ],
        ),

        // Doesn't seem to be a tor relay
        fallback::make(
            "EF18418EE9B5E5CCD0BB7546869AC10BA625BAC8",
            "YU12MoJWSmk+4N90lEY1vG9kXLffr80/1Lroeo6Xsvo",
            &[
                "185.191.127.231:443"
            ],
        ),
    ]);


    let config = builder.build()?;
    // eprintln!("config: {:?}", config);

    
    eprintln!("connecting to Tor...");

    let socks_args = Some(box_socks::SocksArgs {
        server: "127.0.0.1:7890".to_owned(),
        username: None,
        password: None,
        max_targets: None, // Some(0),
    });
    // let socks_args = None;

    let runtime = box_socks::create_runtime(socks_args)?;
    
    let tor_client = TorClient::with_runtime(runtime)
    .config(config)
    .create_bootstrapped()
    .await?;
    eprintln!("====== connected Tor with runtime");

    {
        let netdir = tor_client.dirmgr().timely_netdir()?;
        print_relay(&netdir, "eFCu/xAod8SMUmLvtfsibUKYf5HgTT7kylb3lpKp2tA");
        print_relay(&netdir, "Rq3RHdRQQdjbpmF4VBgMvi6a3lOHNnXM0K6qwlxHj5Q");
        print_relay(&netdir, "YU12MoJWSmk+4N90lEY1vG9kXLffr80/1Lroeo6Xsvo");
    }

    eprintln!("connecting to example.com...");

    // Initiate a connection over Tor to example.com, port 80.
    // let mut stream = tor_client.connect(("example.com", 80)).await?;

    let mut stream = tor_client.connect_with_prefs(("example.com", 80), StreamPrefs::new().ipv4_only()).await?;


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

    println!("done");

    Ok(())
}

async fn simple_http_get<R, A>(tor_client: &TorClient<R>, addr: A, ) -> Result<()> 
where
    R: Runtime,
    A: IntoTorAddr,
{ 
    eprintln!("connecting to example.com...");

    // Initiate a connection over Tor to example.com, port 80.
    let mut stream = tor_client.connect(addr).await?;

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

fn print_relay(netdir: &Arc<NetDir>, ed: &str) {
    let id = fallback::make_ed25519_id(ed);
    let r = netdir.by_id(&id);
    match r {
        Some(relay) => {
            dbgd!("node: [{}] -> {}, {:?}, {:?}", ed, relay.rsa_id(), relay.rs().addrs(), relay.rs().flags());
        },
        None => {
            dbgd!("node: [{}] -> None", ed);
        },
    }
}

pub mod fallback {
    use arti_client::config::dir::{FallbackDirBuilder, FallbackDir};
    use tor_llcrypto::pk::{rsa::RsaIdentity, ed25519::Ed25519Identity};

    pub fn make_ed25519_id(ed: &str) -> Ed25519Identity {
        let ed = base64::decode_config(ed, base64::STANDARD_NO_PAD)
            .expect("Bad hex in built-in fallback list");
        let ed = Ed25519Identity::from_bytes(&ed).expect("Wrong length in built-in fallback list");
        ed
    }

    pub fn make(rsa: &str, ed: &str, ports: &[&str]) -> FallbackDirBuilder {
        let rsa = RsaIdentity::from_hex(rsa).expect("Bad hex in built-in fallback list");
        let ed = base64::decode_config(ed, base64::STANDARD_NO_PAD)
            .expect("Bad hex in built-in fallback list");
        let ed = Ed25519Identity::from_bytes(&ed).expect("Wrong length in built-in fallback list");
        let mut bld = FallbackDir::builder();
        bld.rsa_identity(rsa).ed_identity(ed);

        ports
            .iter()
            .map(|s| s.parse().expect("Bad socket address in fallbacklist"))
            .for_each(|p| {
                bld.orports().push(p);
            });

        bld
    }
}
