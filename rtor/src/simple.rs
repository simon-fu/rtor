use std::sync::Arc;
use anyhow::Result;
use arti_client::{config::{TorClientConfigBuilder}, TorClient, IntoTorAddr};
use crate::box_socks;
use futures::{AsyncWriteExt, AsyncReadExt};

use tor_netdir::NetDir;
use tor_rtcompat::Runtime;



macro_rules! dbgd {
    ($($arg:tt)* ) => (
        tracing::info!($($arg)*) // comment out this line to disable log
    );
}

const STATE_DIR: &str = "/tmp/arti-client/state";
const CACHE_DIR: &str = "/tmp/arti-client/cache";

pub async fn simple_tor_client() -> Result<()> {
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

    simple_http_get(&tor_client, ("example.com", 80)).await?;

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
