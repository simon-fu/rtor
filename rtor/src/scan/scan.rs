

use std::{time::Duration, collections::HashSet};
use anyhow::{Result, bail};
use arti_client::{TorClientConfig, TorClient};
use rand::rngs::ThreadRng;
use tor_guardmgr::fallback::{FallbackList, FallbackDir};
use tor_rtcompat::Runtime;

use crate::util::{IntervalLog, AsyncHandler};
use super::{tcp_scan::TcpScanner, RelayInfo, HashRelay};


macro_rules! dbgi {
    ($($arg:tt)* ) => (
        tracing::info!($($arg)*) // comment out this line to disable log
    );
}

pub type ScanResult = (RelayInfo, Result<()>);




pub async fn scan_relays_to_set<I>(relays: I, timeout: Duration, concurrency: usize, output: &mut HashSet<HashRelay>) -> Result<()>

where 
    I: Iterator<Item = RelayInfo>,
{
    async fn insert_to_set(output: &mut HashSet<HashRelay>, (relay, r): ScanResult) -> Result<()> {
        if r.is_ok() {
            dbgi!("insert reachable [{:?}]", relay);
            output.insert(HashRelay(relay));
        }
        Ok(())
    }
    scan_relays(relays, timeout, concurrency, output, &insert_to_set ).await?;
    Ok(())
}


pub async fn scan_relays<I, C, F>(mut relays: I, timeout: Duration, concurrency: usize, ctx: &mut C, func: &F) -> Result<()>
where
    I: Iterator<Item = RelayInfo>,
    F: for<'local> AsyncHandler<'local, C, ScanResult>
{

    let scanner = TcpScanner::new(timeout, concurrency);

    let mut last_relay = relays.next().map(|v|v.into());
    let mut num_sent = 0;

    let mut kick_log = IntervalLog::new(3, |ctx| {
        dbgi!("kick scannings {}", *ctx);
    });

    while last_relay.is_some() {
        // num_sent += try_send_until_full(&mut relays, &scanner, &mut last_relay)?;
        num_sent += scanner.try_send_until_full(&mut relays, &mut last_relay)?;
        kick_log.update(&num_sent);
        
        // recv_until_empty(&rr, ctx, func).await?;
        scanner.recv_until_empty(ctx, func).await?;
    }
    kick_log.finish(&num_sent);
    dbgi!("kicked all scannings {}", num_sent);

    scanner.recv_until_closed(ctx, func).await?;
    dbgi!("scanner closed");



    Ok(())
}


pub async fn check_scan_fallbacks<R>(client_config: &TorClientConfig, tor_client: &TorClient<R>) -> Result<Option<HashSet<HashRelay>>> 
where
    R: Runtime,
{
    {
        let frac = tor_client.bootstrap_status().as_frac();
        if frac > 0.0 {
            dbgi!("bootstrap frac {}, ignore scan fallbacks", frac);
            return Ok(None)
        }
    }

    let fallbacks: &FallbackList = client_config.as_ref();
 
    let set = scan_fallbacks(fallbacks).await?;
    Ok(Some(set))
}


#[derive(Debug, Clone, Default)]
pub struct BuilInRelays {
    config: TorClientConfig,
}

impl BuilInRelays { 
    pub fn len(&self) -> usize {
        let fallbacks: &FallbackList = self.config.as_ref();
        fallbacks.len()
    }

    pub fn relays_iter(&self) -> impl Iterator<Item = RelayInfo> + '_ {
        let fallbacks: &FallbackList = self.config.as_ref();
        let rng = rand::thread_rng();
        let iter = FallbackIter {
            rng,
            fallbacks,
        };
        iter
        .take(fallbacks.len() * 3 /2)
        .filter_map(|v|v.try_into().ok())
    }
}



pub struct FallbackIter<'a> {
    rng: ThreadRng,
    fallbacks: &'a FallbackList,
}

impl <'a> Iterator for FallbackIter<'a> {
    type Item = &'a FallbackDir;

    fn next(&mut self) -> Option<Self::Item> {
        let r = self.fallbacks.choose(&mut self.rng);
        match r {
            Ok(dir) => Some(dir),
            Err(_e) => None,
        }
    }
}


pub async fn scan_fallbacks(fallbacks: &FallbackList) -> Result<HashSet<HashRelay>> {
    if fallbacks.len() == 0 {
        bail!("has no fallbacks, can't scan fallbacks");
    }

    dbgi!("start scan fallbacks {}", fallbacks.len());

    

    let rng = rand::thread_rng();
    let iter = FallbackIter {
        rng,
        fallbacks,
    };

    let mut iter = iter.map(|v| v.into()).take(fallbacks.len()*3/2);

    async fn insert_to_set(output: &mut HashSet<HashRelay>, (relay, r): ScanResult) -> Result<()> {
        if r.is_ok() {
            dbgi!("insert fallback [{:?}]", relay);
            output.insert(HashRelay(relay));
        }
        Ok(())
    }

    let timeout = Duration::from_secs(3);
    let concurrency = 50;
    let mut ctx = HashSet::new();
    scan_relays(&mut iter, timeout, concurrency, &mut ctx, &insert_to_set ).await?;

    dbgi!("scan fallbacks done, got relays {}", ctx.len());

    Ok(ctx)
}




