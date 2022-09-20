use std::{time::Duration, collections::HashSet, convert::TryFrom};
use std::path::PathBuf;

use anyhow::Result;
use arti_client::config::CfgPath;
use tracing::info;
use crate::{scan::{self, HashRelay}, proxy::buildin_relays};

use crate::scan::FallbackRelays;



// macro_rules! dbgd {
//     ($($arg:tt)* ) => (
//         tracing::info!($($arg)*) // comment out this line to disable log
//     );
// }


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
    pub out_socks: Option<String>,
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

    pub fn reachable_relays_file(&self) -> String {
        format!("{}/rtor/reachable_relays.txt", self.storage_dir())
    }

    pub fn all_relays_file(&self) -> String {
        format!("{}/rtor/all_relays.txt", self.storage_dir())
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
        let secs = self.scan_interval_secs.unwrap_or_else(|| 60*60*24);
        Duration::from_secs(secs)
    }

    pub fn out_socks(&self) -> Option<String> {
        match &self.out_socks {
            Some(s) => Some(s.clone()),
            None => { 
                if cfg!(target_os = "macos") {
                    Some("127.0.0.1:5000".to_owned())
                } else {
                    None
                }
            },
        }
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
    pub out_socks: Option<String>,

    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub reachable_relays_file: PathBuf,
    pub all_relays_file: PathBuf,
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
            out_socks: src.out_socks(),

            state_dir: CfgPath::new(src.state_dir()).path()?,
            cache_dir: CfgPath::new(src.cache_dir()).path()?,
            reachable_relays_file:  CfgPath::new(src.reachable_relays_file()).path()?,
            all_relays_file:  CfgPath::new(src.all_relays_file()).path()?,
        })
    }
}



pub async fn run_proxy() -> Result<()> {  
    cfg_if::cfg_if! {
        if #[cfg(feature="hack")] {
            super::proxy_hack::run_proxy().await
        } else {
            super::proxy_ch2::run_proxy().await
        }
    }
}



pub async fn scan_bootstraps(
    args: &ProxyConfig,
    bootstrap_relays_file: Option<&str>,
) -> Result<HashSet<HashRelay>> {

    let bootstrap_relays = if let Some(bootstrap_relays_file) = bootstrap_relays_file {
        let r = scan::load_result_filepath(bootstrap_relays_file).await;
        match r {
            Ok(relays) => { 
                info!("loaded bootstrap relays [{}] from [{}]", relays.len(), bootstrap_relays_file);
                if relays.len() > 0 {
                    Some(relays)
                } else {
                    None
                }
            },
            Err(_e) => { 
                info!("fail to load bootstrap relays from [{}]", bootstrap_relays_file);
                None
            },
        }
    } else {
        None
    };


    let timeout = args.scan_timeout;
    let concurrency = args.scan_concurrency;

    let mut active_relays = HashSet::new();
    let total = if let Some(relays) = bootstrap_relays {
        let total = relays.len();
        info!("scanning custom bootstrap relays [{}]...", total);
        let relays = relays.into_iter().map(|v|v.0);
        scan::scan_relays_to_set(relays, timeout, concurrency, &mut active_relays).await?;
        total
    } else {
        
        info!("scanning build-in bootstrap relays [{}]...", buildin_relays::relays().len());
        scan::scan_relays_to_set(buildin_relays::into_iter(), timeout, concurrency, &mut active_relays).await?;
        if active_relays.len() >= 10 {
            buildin_relays::relays().len()
        } else {
            let fallbacks = FallbackRelays::default();
            info!("scanning fallback relays [{}]...", fallbacks.len());
            scan::scan_relays_to_set(fallbacks.relays_iter(), timeout, concurrency, &mut active_relays).await?;
            fallbacks.len() + buildin_relays::relays().len()
        }

    };
    info!("scanning bootstrap relays result [{}/{}]", active_relays.len(), total);

    Ok(active_relays)
}



