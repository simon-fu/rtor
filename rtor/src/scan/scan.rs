

use std::{time::Duration, collections::HashSet, marker::PhantomData};

use anyhow::{Result, bail};
use async_channel::{TrySendError, TryRecvError};
use futures::Future;
use tokio::{fs::File, io::AsyncWriteExt, time::Instant};


use super::{tcp_scan::{ResultReceiver, TcpScanner}, RelayInfo, HashRelay};


macro_rules! dbgi {
    ($($arg:tt)* ) => (
        tracing::info!($($arg)*) // comment out this line to disable log
    );
}

type ScanResult = (RelayInfo, Result<()>);


/// refer from https://users.rust-lang.org/t/function-that-takes-an-async-closure/61663
/// To be used with as a HRTB: `for<'local> Handler<'local>`.
pub trait Handler<'local, C> {
    type Fut : Future<Output = Result<()>>;
    fn call (
        self: &'_ Self, // Fn
        _: &'local mut C,
        r: ScanResult,
    ) -> Self::Fut;
}


impl<'local, F, Fut, C:'local> Handler<'local, C> for F
where
    F : Fn(&'local mut C, ScanResult) -> Fut,
    Fut : Future<Output = Result<()>>,
{
    type Fut = Fut;
    fn call (
        self: &'_ Self, // Fn
        ctx: &'local mut C,
        r: ScanResult,
    ) -> Fut
    {
        self(ctx, r)
    }
}


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

pub async fn write_relays_to_file<'a, I>(mut relays: I, file: &str) -> Result<()>
where 
    I: Iterator<Item = &'a RelayInfo>,
{
    let mut file = File::create(file).await?;
    while let Some(relay) = relays.next() {
        let s = serde_json::to_string(&relay)?;
        file.write_all(s.as_bytes()).await?;
        file.write_all("\r\n".as_bytes()).await?;
    }
    Ok(())
}

pub async fn scan_relays_to_file<I>(relays: I, timeout: Duration, concurrency: usize, file: &str) -> Result<()>

where 
    I: Iterator<Item = RelayInfo>,
{
    async fn write_relay_to_file(file: &mut File, (relay, r): ScanResult) -> Result<()> {
        if r.is_ok() {
            // let s = format!("{}\r\n", relay.id);
            let s = serde_json::to_string(&relay)?;
            dbgi!("got reachable [{}]", s);
            file.write_all(s.as_bytes()).await?;
            file.write_all("\r\n".as_bytes()).await?;
        }
        Ok(())
    }

    let mut file = File::create(file).await?;
    // let file = &mut file;
    scan_relays(relays, timeout, concurrency, &mut file, &write_relay_to_file ).await?;
    Ok(())
}

// async fn write_relay_result0(file: &mut File, (relay, r): ScanResult) -> Result<()> { 
//     Ok(())
// }

// // async fn scan_relays0<I, C>(relays: I, timeout: Duration, concurrency: usize, ctx: &mut C, func: impl for<'local> Handler<'local, C>) -> Result<()>
// async fn scan_relays0<I, C, F>(relays: I, timeout: Duration, concurrency: usize, ctx: &mut C, func: F) -> Result<()>
// where
//     F: for<'local> Handler<'local, C>
// {
//     // let mut foo = Foo {};

//     let relay = crate::scan::make_test_relay_info();
//     let r = (relay, Ok(()));
//     func.call(ctx, r).await
// }



// #[derive(Debug)]
// struct Foo {}

// /// To be used with as a HRTB: `for<'local> MyAsyncFn<'local>`.
// trait MyAsyncFn<'foo, C> {
//     type Fut : Future<Output = Result<()>>;
//     fn call (
//         self: &'_ Self, // Fn
//         _: &'foo mut C,
//     ) -> Self::Fut;
// }

// /// The trick is that, here, the lifetime is not higher-order
// /// so as not to confuse the trait solver.
// impl<'foo, F, Fut, C:'foo> MyAsyncFn<'foo, C> for F
// where
//     F : Fn(&'foo mut C) -> Fut,
//     Fut : Future<Output = Result<()>>,
// {
//     type Fut = Fut;
//     fn call (
//         self: &'_ Self, // Fn
//         foo: &'foo mut C,
//     ) -> Fut
//     {
//         self(foo)
//     }
// }

// async fn takes_closure<C> (f: impl for<'local> MyAsyncFn<'local, C>, foo: &mut C) -> Result<()>
// {
//     // let mut foo = Foo {};
//     f.call(foo).await
// }


// async fn fn_main() -> Result<()>
// {
//     async fn fun (foo: &'_ mut Foo) -> Result<()>
//     {
//         tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
//         println!("hello {:?}", foo);
//         Ok(())
//     }
    
//     let mut foo = Foo {};
//     takes_closure(fun, &mut foo).await
// }


async fn scan_relays<I, C, F>(mut relays: I, timeout: Duration, concurrency: usize, ctx: &mut C, func: &F) -> Result<()>
where
    I: Iterator<Item = RelayInfo>,
    F: for<'local> Handler<'local, C>
{


    let mut scanner = TcpScanner::new(timeout, concurrency);

    let rr = scanner.result_recver()?;


    let mut last_relay = relays.next().map(|v|v.into());
    let mut num_sent = 0;
    // let mut last_print = (Instant::now(), num_sent);
    let mut last_print = IntervalLog::new(3, |ctx| {
        dbgi!("kick scannings {}", *ctx);
    });
    while last_relay.is_some() {
        num_sent += try_send_until_full(&mut relays, &scanner, &mut last_relay)?;
        last_print.update(&num_sent);

        // if last_print.0.elapsed() >= Duration::from_secs(3) && last_print.1 < num_sent {
        //     dbgi!("kick scannings {}", num_sent);
        //     last_print = (Instant::now(), num_sent);
        // }
        
        recv_until_empty(&rr, ctx, func).await?;
    }
    last_print.finish(&num_sent);
    dbgi!("kick all scannings {}", num_sent);

    try_recv_until_empty(&rr, ctx, func).await?;
    dbgi!("recv until empty done");

    scanner.wait_for_finished().await;
    dbgi!("scanner finished");

    try_recv_until_closed(&rr, ctx, func).await?;
    dbgi!("recv until closed done");

    Ok(())
}

pub struct IntervalLog<C, F> {
    interval: Duration,
    time: Instant,
    updated: bool,
    func: F,
    none: PhantomData<C>,
}

impl <C, F> IntervalLog<C, F> 
where
    F: Fn(&C),
{
    pub fn new(milli: u64, func: F) -> Self {
        Self { 
            interval: Duration::from_millis(milli),
            time: Instant::now(),
            updated: false, 
            func,
            none: PhantomData::default(),
        }
    }

    pub fn update(&mut self, ctx: &C) {
        self.updated = true;
        if self.updated && self.time.elapsed() >= self.interval {
            self.log(ctx);
        }
    }

    pub fn finish(&mut self, ctx: &C) {
        if self.updated {
            self.log(ctx);
        }
    }

    fn log(&mut self, ctx: &C) {
        (self.func)(ctx);
        self.updated = false;
        self.time = Instant::now();
    }

}


async fn recv_until_empty<C, F>(rr: &ResultReceiver<RelayInfo>, ctx: &mut C, func: &F) -> Result<()> 
where
    F: for<'local> Handler<'local, C>

{ 
    let r = rr.recv().await?;
    // write_relay_result(&r, file).await?;
    func.call(ctx, r).await?;

    try_recv_until_empty(rr, ctx, func).await
}

async fn try_recv_until_empty<C, F>(rr: &ResultReceiver<RelayInfo>, ctx: &mut C, func: &F) -> Result<()> 
where
    F: for<'local> Handler<'local, C>,
{ 

    loop {
        let r = rr.try_recv();
        match r {
            Ok(r) => {
                // write_relay_result(&r, file).await?;
                func.call(ctx, r).await?;

            },
            Err(e) => {
                match e {
                    TryRecvError::Empty => return Ok(()),
                    TryRecvError::Closed => bail!("try recv until empty but closed"),
                }
            },
        }
    }
}

async fn try_recv_until_closed<C, F>(rr: &ResultReceiver<RelayInfo>, ctx: &mut C, func: &F) -> Result<()> 
where
    F: for<'local> Handler<'local, C>,
{ 

    loop {
        let r = rr.try_recv();
        match r {
            Ok(r) => {
                func.call(ctx, r).await?;

            },
            Err(e) => {
                match e {
                    TryRecvError::Empty => {
                        bail!("try recv until closed but empty")
                    },
                    TryRecvError::Closed => {
                        return Ok(())
                    },
                }
            },
        }
    }
}


fn try_send_until_full<I>(relays: &mut I, scanner: &TcpScanner<RelayInfo>, last: &mut Option<RelayInfo>) -> Result<usize>
where 
    I: Iterator<Item = RelayInfo>
{
    let mut num = 0;
    while let Some(target) = last.take() {
        let r = scanner.try_add(target);
        match r {
            Ok(_r) => {
                num += 1;
                *last = relays.next();
                continue;
            },
            Err(e) => match e {
                TrySendError::Full(target) => {
                    *last = Some(target);
                    break;
                },
                TrySendError::Closed(_target) => bail!("try add but closed"),
            },
        }
    }
    Ok(num)
}




