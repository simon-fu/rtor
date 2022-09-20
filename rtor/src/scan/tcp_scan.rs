
use std::{net::SocketAddr, time::Duration};
use futures::Future;
// use async_channel::{self, RecvError, TryRecvError};
use tokio::{net::TcpStream, task::JoinHandle};
use anyhow::{Result, bail};
use tracing::Instrument;

use crate::{util::{AsyncHandler, async_ch_util}};


macro_rules! dbgd {
    ($($arg:tt)* ) => (
        // tracing::debug!($($arg)*) // comment out this line to disable log
    );
}

// #[derive(Clone)]
// pub struct ResultReceiver<T>{
//     rx:async_channel::Receiver<(T, Result<()>)>,
// }

// impl<T> ResultReceiver<T> {
//     pub async fn recv(&self) -> Result<(T, Result<()>), RecvError> {
//         self.rx.recv().await
//     }

//     pub fn try_recv(&self) -> Result<(T, Result<()>), TryRecvError> {
//         self.rx.try_recv()
//     }
// }

pub trait Connector: Clone + Send {
    type ConnectFuture<'a>: Future<Output = Result<()>> + Send where Self: 'a;

    fn connect<'a>(&'a mut self, addr: &'a str) -> Self::ConnectFuture<'_>;
}

#[derive(Debug, Clone)]
pub struct TcpConnector;

impl Connector for TcpConnector {
    type ConnectFuture<'a> = impl Future<Output = Result<()>> where Self: 'a;

    fn connect<'a>(&'a mut self, addr: &'a str) -> Self::ConnectFuture<'_> {
        async move {
            TcpStream::connect(addr).await?;
            Ok(())
        }
    }
}



/// Scan Result 
type SResult<T> = (T, Result<()>);

#[derive(Debug, Clone, Default)]
pub struct Progress {
    pub num_sent: usize,
    pub num_recv: usize,
}

pub struct TcpScanner<T> {
    tasks: Vec<JoinHandle<Result<()>>>,
    tx: Option<async_channel::Sender<T>>,
    rx: Option<async_channel::Receiver<SResult<T>>>,
    progress: Progress,
}

impl<T> TcpScanner<T> 
where 
    for<'a> T: AddrsIter<'a> + Send + Sync + 'static,
{
    pub fn new(timeout: Duration, concurrency: usize ) -> Self {
        Self::with_connector(timeout, concurrency, TcpConnector{})
    }

    pub fn with_connector<C: Connector+'static>(timeout: Duration, concurrency: usize, connector: C ) -> Self {
        let (tx0, rx0) = async_channel::bounded(concurrency * 2);
        let (tx1, rx1) = async_channel::bounded(concurrency * 2);
        // let socks_args = socks_args.map(|v|Arc::new(v));
        
        let mut tasks = Vec::with_capacity(concurrency);
        for n in 0..concurrency {
            let tx = tx1.clone();
            let rx = rx0.clone();
            // let socks_args = socks_args.clone();
            let mut connector = connector.clone();

            let name = format!("task{}", n + 1);
            let span = tracing::span!(parent:None, tracing::Level::INFO, "", s = &name[..]);
            let task = tokio::spawn(async move {
                let r = scan_task(&mut connector, tx, rx, timeout).await;
                dbgd!("finished with {:?}", r);
                r
            }.instrument(span));
            tasks.push(task);
        }

        Self { tasks, tx: Some(tx0), rx: Some(rx1), progress: Progress::default(), } 
    }

    pub fn progress(&self) -> &Progress {
        &self.progress
    }

    // pub fn result_recver(&self) -> Result<ResultReceiver<T>> {
    //     match &self.rx {
    //         Some(rx) => Ok(ResultReceiver{rx: rx.clone()}),
    //         None => bail!("result_recver but closed"),
    //     }
    // }

    pub fn close_send(&mut self) { 
        if let Some(tx) = self.tx.take() {
            tx.close();
        }
    }

    pub async fn wait_for_finished(&mut self) {         
        while let Some(task) = self.tasks.pop() {
            // dbgd!("remains tasks [{}]", self.tasks.len());
            let _r = task.await;
        }
    }

    // pub fn try_send(&self, target: T) -> Result<(), async_channel::TrySendError<T>> {
    //     match &self.tx {
    //         Some(tx) => tx.try_send(target),
    //         None => Err(async_channel::TrySendError::Closed(target)),
    //     }
    // }


    pub async fn send(&self, target: T) -> Result<(), async_channel::SendError<T>> {
        if let Some(tx) = &self.tx {
            tx.send(target).await
        } else {
            Err(async_channel::SendError(target))
        }
    }

    pub fn try_send_until_full<I>(&mut self, relays: &mut I, last: &mut Option<T>) -> Result<usize>
    where 
        I: Iterator<Item = T>
    {
        let tx = match &self.tx {
            Some(tx) => tx,
            None => bail!("try_send_until_full but closed"),
        };

        let n = async_ch_util::try_send_until_full(tx, relays, last)?;
        self.progress.num_sent += n;
        Ok(n)
    }

    pub async fn recv_until_empty<C, F>(&mut self, ctx: &mut C, func: &F) -> Result<usize> 
    where
        F: for<'local> AsyncHandler<'local, C, SResult<T>>

    { 
        let rx = match &self.rx {
            Some(rx) => rx,
            None => bail!("recv_until_empty but closed"),
        };

        let n = async_ch_util::recv_until_empty(rx, ctx, func).await?;
        self.progress.num_recv += n;
        Ok(n)
    }

    pub async fn recv_until_closed<C, F>(&mut self, ctx: &mut C, func: &F) -> Result<usize> 
    where
        F: for<'local> AsyncHandler<'local, C, SResult<T>>,
    {
        self.close_send();

        let rx = match &self.rx {
            Some(rx) => rx,
            None => bail!("recv_until_closed but closed"),
        };
        let num = async_ch_util::recv_until_closed(rx, ctx, func).await?;
        self.progress.num_recv += num;
        self.wait_for_finished().await;
        Ok(num)
    }


}




pub trait AddrsIter<'a> {
    type Iter: Iterator<Item = &'a SocketAddr> + Send;
    fn addrs_iter(&'a self) -> Self::Iter;
}



async fn scan_task<T, C>(
    // socks_args: Option<Arc<SocksArgs>>,
    connector: &mut C,
    tx: async_channel::Sender<SResult<T>>, 
    rx: async_channel::Receiver<T>,
    timeout: Duration,
) -> Result<()> 
where 
    for<'a> T: AddrsIter<'a> + Send + Sync + 'static,
    C: Connector,
{ 
    let mut _try_targets = 0;
    loop {
        let r = rx.recv().await;
        match r {
            Ok(next) => {
                let mut result = Ok(());
                for addr in next.addrs_iter() {
                    let r = connect_with_timeout(connector, addr, timeout).await;
                    // let r = match &socks_args {
                    //     Some(socks_args) => connect_with_socks_timeout(socks_args, addr, timeout).await,
                    //     None => connect_with_timeout(addr, timeout).await,
                    // };

                    _try_targets += 1;
                    dbgd!("No.{} connect result: [{}] -> [{:?}]", _try_targets, addr, r);
                    if r.is_ok() {
                        break;
                    }
                    result = r;
                }
                tx.send((next, result)).await?;
            },
            Err(_) => return Ok(()),
        }
    }
}

async fn connect_with_timeout<C>(connector: &mut C, addr: &SocketAddr, timeout: Duration) -> Result<()> 
where
    C: Connector,
{
    let _s = tokio::time::timeout(timeout, connector.connect(&addr.to_string())).await??;    
    Ok(())
}



// async fn connect_with_socks_timeout(socks_args: &SocksArgs, addr: &SocketAddr, timeout: Duration) -> Result<()> {
//     let _s = tokio::time::timeout(timeout, socks::connect_to_with_socks(socks_args, addr)).await??;    
//     Ok(())
// }
