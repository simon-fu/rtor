use std::{sync::Arc, collections::{HashSet, HashMap}};
use parking_lot::Mutex;
use rand::seq::SliceRandom;
use tokio::sync::watch;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use anyhow::{Result, Context, bail};
use crate::scan::{HashRelay, OwnedRelay};

#[derive(Debug, Clone)]
pub enum PoolAction {
    None,
    Scanning,
    AddGuards(usize, usize), // (delta, num guards)
    AddRelays(usize, usize), // (delta, all)
    ScanDone,
}

struct Watcher {
    n_guards: usize,
    n_reachables: usize,
    state: PoolState,
    rx: watch::Receiver<u64>,
}
pub struct RelaysWatcher { 
    pool: Arc<RelayPool>,
    inner: Watcher,
}

impl RelaysWatcher {
    pub fn new(pool: Arc<RelayPool>) -> Self {
        let inner = pool.new_watcher();
        Self {
            pool,
            inner,
        }
    }

    pub async fn watch_next(&mut self) -> Result<PoolAction> { 
        self.inner.rx.changed().await.with_context(||"relay pool already dropped")?;
        self.pool.diff_action(&mut self.inner)
    }

    pub fn pool(&self) -> &Arc<RelayPool> {
        &self.pool
    }
}

pub type RelayMap = HashMap<Ed25519Identity, Arc<OwnedRelay>>;
pub type ArcRelays = Arc<RelayMap>;

pub struct RelayPool {
    relays: RelayMap,
    exit_ids: Vec<Ed25519Identity>,
    data: Mutex<PoolData> ,
    tx: watch::Sender<u64>,
    rx: watch::Receiver<u64>,
}

impl RelayPool {
    pub fn new(relays: RelayMap) -> Self { 
        let mut exit_ids = Vec::new();
        for (id, relay) in relays.iter() {
            if relay.is_flagged_exit() {
                exit_ids.push(id.clone());
            }
        }

        let (tx, rx) = watch::channel(0);
        Self { 
            relays,
            exit_ids,
            data: Mutex::new(PoolData {
                guards: Vec::new(),
                reachables: HashSet::new(),
                state: PoolState::default(),
                // netdir,
            }),
            tx,
            rx,
        }
    }

    pub fn relays(&self) -> &RelayMap {
        &self.relays
    }

    pub fn get_relay(&self, id: &Ed25519Identity) -> Option<&Arc<OwnedRelay>> {
        self.relays.get(id) 
    }

    pub fn num_reachables(&self) -> (usize, usize) { 
        let data = self.data.lock();
        (data.reachables.len(), data.guards.len())
    }

    pub fn reachable_ids(&self) -> HashSet<Ed25519Identity> { 
        self.data.lock().reachables.clone()
    }

    const PICK_TRY_NUM: usize = 5;

    pub fn pick_active_guard<R>(&self, rng: &mut R,) -> Option<&Arc<OwnedRelay>> 
    where
        R: rand::Rng,
    {
        for _ in 0..Self::PICK_TRY_NUM {
            let data = self.data.lock(); 
            let r = data.guards.choose(rng);
            let r = match r {
                Some(id) => self.relays.get(id),
                None => break,
            };
            if r.is_some() {
                return r;
            }
        }
        None
    }

    pub fn pick_exit<R>(&self, rng: &mut R,) -> Option<&Arc<OwnedRelay>> 
    where
        R: rand::Rng,
    {
        for _ in 0..Self::PICK_TRY_NUM {
            let r = self.exit_ids.choose(rng);
            let r = match r {
                Some(id) => self.relays.get(id),
                None => break,
            };
            if r.is_some() {
                return r;
            }
        }
        None
    }

    // pub fn netdir(&self) -> Arc<NetDir> {
    //     self.data.lock().netdir.clone()
    // }

    // pub fn set_netdir(&self, netdir: Arc<NetDir>) {
    //     self.data.lock().netdir = netdir;
    // }

    pub fn scan_beging(&self) -> Result<()>{
        let seq = {
            let mut data = self.data.lock();
            data.state.epoch += 1;
            
            data.state.state = ScanState::Doing;
            data.state.seq += 1;
            data.state.seq
        };
        self.send_watching(seq)
    }

    pub fn scan_done(&self) -> Result<()>{
        let seq = {
            let mut data = self.data.lock();

            data.state.state = ScanState::Done;
            data.state.seq += 1;
            data.state.seq
        };
        self.send_watching(seq)
    }

    pub fn update_relay(&self, relay: HashRelay) -> Result<()> { 
        let seq = {
            let mut data = self.data.lock();
            
            if data.reachables.contains(relay.0.get_id()?) {
                return Ok(())
            }
    
            if relay.0.is_flagged_guard() {
                data.guards.push(relay.0.get_id()?.clone());
            }

            data.reachables.insert(relay.0.own_id()?); 
            data.state.seq += 1;
            data.state.seq
        };

        self.send_watching(seq)
    }

    fn send_watching(&self, seq: u64) -> Result<()> {
        self.tx.send(seq).with_context(||"no one watching relays pool")
    }

    fn new_watcher(&self) -> Watcher {
        let data = self.data.lock();
        Watcher {
            n_guards: data.guards.len(),
            n_reachables: data.reachables.len(),
            state: data.state,
            rx: self.rx.clone(),
        }
    }

    fn diff_action(&self, watcher: &mut Watcher) -> Result<PoolAction> { 
        let mut action = PoolAction::None;
        let data = self.data.lock();
        if data.state.epoch != watcher.state.epoch { 
            if data.state.epoch != (watcher.state.epoch + 1) {
                // 扫描的间隔需要设置长一点，否则epoch连续变化，导致判断不完全正确
                bail!("epoch advance too much, old [{}], new [{}]", watcher.state.epoch, data.state.epoch) 
            }
            match data.state.state {
                ScanState::Doing => action = PoolAction::Scanning,
                _ => bail!("state advance too much") 
            }
        } else if data.state.seq != watcher.state.seq { 
            if data.state.state == ScanState::Done {
                action = PoolAction::ScanDone;
            } else {
                if data.reachables.len() > watcher.n_reachables {
                    let delta_relays = data.reachables.len() - watcher.n_reachables;
                    action = PoolAction::AddRelays(delta_relays, data.reachables.len());

                    if data.guards.len() > watcher.n_guards {
                        let delta_guards = data.guards.len() - watcher.n_guards;
                        action = PoolAction::AddGuards(delta_guards, data.guards.len());
                    }
                } else {
                    bail!("nothing changed but diff seq, old [{}], new [{}]", watcher.state.seq, data.state.seq) 
                }
            }
        } else { 
            match data.state.state {
                ScanState::None => action = PoolAction::None,
                ScanState::Doing => action = PoolAction::Scanning,
                ScanState::Done => action = PoolAction::ScanDone,
            }
        }

        watcher.state = data.state;
        watcher.n_guards = data.guards.len();
        watcher.n_reachables = data.reachables.len();

        Ok(action)
    }

    
    
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScanState {
    None,
    Doing,
    Done,
}

#[derive(Debug, Clone, Copy)]
pub struct PoolState {
    epoch: u64,
    state: ScanState,
    seq: u64,
}

impl Default for PoolState {
    fn default() -> Self {
        Self { epoch: 0, state: ScanState::None, seq: 0 }
    }
}


struct PoolData {
    guards: Vec<Ed25519Identity>,         // reachable guards
    reachables: HashSet<Ed25519Identity>, // all reachable relays
    state: PoolState,
    // netdir: Arc<NetDir>,
}

