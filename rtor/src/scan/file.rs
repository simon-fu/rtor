use std::{time::Duration, collections::HashSet, path::{Path, PathBuf}, sync::Arc};
use anyhow::{Result, Context};
use serde::{Serialize, Deserialize};
use tokio::{fs::File, io::{AsyncWriteExt, BufReader, AsyncBufReadExt, Lines}, sync::oneshot};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use crate::util;

use super::{HashRelay, scan_relays, ScanResult, OwnedRelay};

macro_rules! dbgd {
    ($($arg:tt)* ) => (
        tracing::debug!($($arg)*) // comment out this line to disable log
    );
}

pub async fn open_result_filepath(file: impl AsRef<Path>) -> Result<ScanResultFile> {
    let file = File::open(&file).await.with_context(||format!("Failed to open file [{:?}]", file.as_ref()))?;

    let reader = BufReader::new(file);

    let lines = reader.lines();
    Ok(ScanResultFile{lines})
}

pub async fn load_result_filepath(file: impl AsRef<Path>) -> Result<HashSet<HashRelay>> { 
    open_result_filepath(file).await?
    .read_all_to_hash_set().await
}

pub async fn load_relays_to_collect<B, I>(file: impl AsRef<Path>) -> Result<B> 
where
    B: Extend<I>+Default,
    I: From<OwnedRelay>,
{
    open_result_filepath(file).await?
    .read_to_collect().await
}


pub struct ScanResultFile{
    lines: Lines<BufReader<File>>
}

impl ScanResultFile {
    pub async fn read_next(&mut self) -> Result<Option<OwnedRelay>> {
        let r = self.lines.next_line().await
        .with_context(||"Failed to read scan result file")?;
        match r {
            Some(line) => {
                let relay: OwnedRelay = serde_json::from_str(&line)?;
                Ok(Some(relay))
            },
            None => Ok(None),
        }
    }

    // fn collect<B: FromIterator<Self::Item>>(self) -> B
    // where
    //     Self: Sized,
    

    pub async fn read_to_collect<B, I>(&mut self) -> Result<B> 
    where
        B: Extend<I>+Default,
        I: From<OwnedRelay>,
        // Self: Sized,
    {
        let mut set = B::default();
        loop {
            if let Some(relay) = self.read_next().await? {
                set.extend(Some(relay.into()));
            } else {
                break;
            }
        }
        Ok(set)
    }

    pub async fn read_all_to_hash_set(mut self) -> Result<HashSet<HashRelay>> {
        // self.read_n_to_hash_set(usize::MAX).await
        self.read_to_collect().await
    }

    // pub async fn read_n_to_hash_set(&mut self, num: usize) -> Result<HashSet<HashRelay>> {
    //     // let mut set = HashSet::new();
    //     self.load_to_collect().await
    //     // Ok(set)

    //     // let mut set = HashSet::new();
    //     // while set.len() < num {
    //     //     if let Some(relay) = self.read_next().await? {
    //     //         set.insert(HashRelay(relay));
    //     //     } else {
    //     //         break;
    //     //     }
    //     // }
    //     // Ok(set)
    // }
}

pub async fn write_relays_to_filepath<'a, I>(relays: I, file_path: impl AsRef<Path>) -> Result<()>
where 
    I: Iterator<Item = &'a OwnedRelay>,
{
    // if let Some(dir) = file_path.as_ref().parent() { 
    //     fs::create_dir_all(dir).await? ;
    // }
    
    // let mut file = File::create(file_path).await?;

    // while let Some(relay) = relays.next() {
    //     let s = serde_json::to_string(&relay)?;
    //     file.write_all(s.as_bytes()).await?;
    //     file.write_all("\r\n".as_bytes()).await?;
    // }
    // Ok(())

    let mut file = util::create_file(file_path).await?;
    write_iter_to_file(relays, &mut file).await
}

pub async fn write_ids_to_filepath<'a, I>(iter: I, file_path: impl AsRef<Path>) -> Result<()>
where 
    I: Iterator<Item = &'a Ed25519Identity>,
{

    let mut file = util::create_file(file_path).await?;
    write_iter_to_file(iter, &mut file).await
}


// pub async fn load_relays_from_file<B, I>(file: impl AsRef<Path>) -> Result<B> 
// where
//     B: Extend<I>+Default,
//     I: From<OwnedRelay>,
// {
//     let file = File::open(&file).await.with_context(||format!("Failed to open file [{:?}]", file.as_ref()))?;

//     let reader = BufReader::new(file);

//     let mut lines = reader.lines();

//     let mut set = B::default();

//     loop { 
//         let r = lines.next_line().await
//         .with_context(||"Failed to read scan result file")?;
//         match r {
//             Some(line) => {
//                 let relay: OwnedRelay = serde_json::from_str(&line)?;
//                 set.extend(Some(relay.into()));
//             },
//             None => break,
//         }
//     }
//     Ok(set)
// }

pub async fn load_ids_from_file(file: impl AsRef<Path>) -> Result<HashSet<Ed25519Identity>> {
    load_items_from_file::<_, Ed25519Identity, Ed25519Identity>(file).await
}

pub async fn load_items_from_file<B, I, S>(file: impl AsRef<Path>) -> Result<B> 
where
    B: Extend<S>+Default,
    I: From<S>,
    S: for<'a> Deserialize<'a>,
{
    let file = File::open(&file).await.with_context(||format!("Failed to open file [{:?}]", file.as_ref()))?;

    let reader = BufReader::new(file);

    let mut lines = reader.lines();

    let mut set = B::default();

    loop { 
        let r = lines.next_line().await
        .with_context(||"Failed to read scan result file")?;
        match r {
            Some(line) => {
                let item: S = serde_json::from_str(&line)?;
                set.extend(Some(item.into()));
            },
            None => break,
        }
    }
    Ok(set)
}

pub async fn write_iter_to_file<'a, I, S>(mut iter: I, file: &mut File) -> Result<()>
where 
    I: Iterator<Item = &'a S>,
    S: Serialize + 'a,
{
    while let Some(item) = iter.next() {
        let s = serde_json::to_string(&item)?;
        file.write_all(s.as_bytes()).await?;
        file.write_all("\r\n".as_bytes()).await?;
    }
    file.flush().await?;
    Ok(())
}

// pub async fn write_to_file<'a, I>(mut relays: I, file: &mut File) -> Result<()>
// where 
//     I: Iterator<Item = &'a OwnedRelay>,
// {
//     while let Some(relay) = relays.next() {
//         let s = serde_json::to_string(&relay)?;
//         file.write_all(s.as_bytes()).await?;
//         file.write_all("\r\n".as_bytes()).await?;
//     }
//     file.flush().await?;
//     Ok(())
// }



#[derive(Debug, Default, Clone, Copy)]
pub struct RelaysStati{
    pub guards: usize,
    pub exits: usize,
}

pub async fn scan_relays_to_file<I, F>(relays: I, timeout: Duration, concurrency: usize, tx: Option<oneshot::Sender<()>>, file: PathBuf, func: F) -> Result<(HashSet<HashRelay>, RelaysStati)>
where 
    I: Iterator<Item = Arc<OwnedRelay>>,
    F: Fn(RelaysStati, &Arc<OwnedRelay>) -> bool + 'static 
{
    
    struct Ctx<F> {
        set: HashSet<HashRelay>,
        stati: RelaysStati,
        tx: Option<oneshot::Sender<()>>, 
        func: F,
        file: PathBuf,
    }

    let mut ctx = Ctx {
        set: HashSet::new(),
        stati: RelaysStati::default(),
        tx,
        func,
        file,
    };

    async fn insert_to_set<F>(ctx: &mut Ctx<F>, (relay, r): ScanResult) -> Result<()> 
    where 
        F: Fn(RelaysStati, &Arc<OwnedRelay>) -> bool 
    {
        if r.is_err() {
            return Ok(())
        }

        if relay.is_flagged_guard() {
            ctx.stati.guards += 1;
        }

        if relay.is_flagged_exit() {
            ctx.stati.exits += 1;
        }

        dbgd!("insert relay [{:?}], stati [{:?}/{}]", relay, ctx.stati, ctx.set.len()+1); 

        let flush = (ctx.func)(ctx.stati, &relay); 

        ctx.set.insert(HashRelay(relay));

        

        
        if flush {
            if let Some(tx) = ctx.tx.take() {
                let _r = tx.send(());
            }

            write_relays_to_filepath(ctx.set.iter().map(|v|v.0.as_ref()), &ctx.file).await?;
        }

        Ok(())
    }

    scan_relays(relays, timeout, concurrency, &mut ctx, &insert_to_set).await?;

    Ok((ctx.set, ctx.stati))
}
