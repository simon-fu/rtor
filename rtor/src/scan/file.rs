use std::{time::Duration, collections::HashSet, path::Path};
use anyhow::{Result, Context};
use tokio::{fs::File, io::{AsyncWriteExt, BufReader, AsyncBufReadExt, Lines}};
use crate::util;

use super::{RelayInfo, HashRelay, scan_relays, ScanResult};

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

pub struct ScanResultFile{
    lines: Lines<BufReader<File>>
}

impl ScanResultFile {
    pub async fn read_next(&mut self) -> Result<Option<RelayInfo>> {
        let r = self.lines.next_line().await
        .with_context(||"Failed to read scan result file")?;
        match r {
            Some(line) => {
                let relay: RelayInfo = serde_json::from_str(&line)?;
                Ok(Some(relay))
            },
            None => Ok(None),
        }
    }

    pub async fn read_all_to_hash_set(mut self) -> Result<HashSet<HashRelay>> {
        self.read_n_to_hash_set(usize::MAX).await
    }

    pub async fn read_n_to_hash_set(&mut self, num: usize) -> Result<HashSet<HashRelay>> {
        let mut set = HashSet::new();
        while set.len() < num {
            if let Some(relay) = self.read_next().await? {
                set.insert(HashRelay(relay));
            } else {
                break;
            }
        }
        Ok(set)
    }
}

pub async fn write_relays_to_filepath<'a, I>(relays: I, file_path: impl AsRef<Path>) -> Result<()>
where 
    I: Iterator<Item = &'a RelayInfo>,
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
    write_to_file(relays, &mut file).await
}



pub async fn scan_relays_to_file<I>(relays: I, timeout: Duration, concurrency: usize, file: &str) -> Result<()>

where 
    I: Iterator<Item = RelayInfo>,
{
    async fn write_relay_to_file(file: &mut File, (relay, r): ScanResult) -> Result<()> {
        if r.is_ok() {
            // let s = format!("{}\r\n", relay.id);
            let s = serde_json::to_string(&relay)?;
            dbgd!("got reachable [{}]", s);
            file.write_all(s.as_bytes()).await?;
            file.write_all("\r\n".as_bytes()).await?;
        }
        Ok(())
    }

    let mut file = File::create(file).await?;

    scan_relays(relays, timeout, concurrency, &mut file, &write_relay_to_file ).await?;
    Ok(())
}

// pub async fn scan_relays_min_to_file<I>(
//     relays: I, 
//     timeout: Duration, 
//     concurrency: usize, 
//     min_active: usize, 
//     file: &str
// ) -> Result<HashSet<HashRelay>>
// where 
//     I: Iterator<Item = RelayInfo>,
// {

//     struct Ctx {
//         set: HashSet<HashRelay>,
//         min_active: usize,
//         file: File,
//     }
//     let mut ctx = Ctx {
//         set: HashSet::new(),
//         min_active,
//         file: do_open_file(file).await?,
//     };

//     async fn insert_to_set(ctx: &mut Ctx, (relay, r): ScanResult) -> Result<()> {
//         if r.is_ok() {
//             dbgi!("insert reachable [{:?}]", relay);
//             ctx.set.insert(HashRelay(relay));
//             if ctx.set.len() == ctx.min_active {
//                 let relays = ctx.set.iter().map(|v|&v.0);
//                 do_write_relays_to_file(relays, &mut ctx.file).await?;
//                 dbgi!("wrote min relays [{}]", ctx.min_active);
//             }
//         }
//         Ok(())
//     }

//     scan_relays(relays, timeout, concurrency, &mut ctx, &insert_to_set ).await?;

//     let relays = ctx.set.iter().map(|v|&v.0);
//     do_write_relays_to_file(relays, &mut ctx.file).await?;

//     Ok(ctx.set)
// }


// pub async fn create_file(file_path: impl AsRef<Path>) -> Result<File>
// {
//     if let Some(dir) = file_path.as_ref().parent() { 
//         fs::create_dir_all(dir).await? ;
//     }
    
//     let file = File::create(file_path).await?;
//     Ok(file)
// }

pub async fn write_to_file<'a, I>(mut relays: I, file: &mut File) -> Result<()>
where 
    I: Iterator<Item = &'a RelayInfo>,
{
    while let Some(relay) = relays.next() {
        let s = serde_json::to_string(&relay)?;
        file.write_all(s.as_bytes()).await?;
        file.write_all("\r\n".as_bytes()).await?;
    }
    file.flush().await?;
    Ok(())
}



