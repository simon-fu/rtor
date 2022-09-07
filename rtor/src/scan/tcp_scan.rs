
use std::{net::SocketAddr, time::Duration};
// use async_channel::{self, RecvError, TryRecvError};
use tokio::{net::TcpStream, task::JoinHandle};
use anyhow::{Result, bail};
use tracing::Instrument;

use crate::util::{AsyncHandler, recv_until_empty, try_send_until_full, recv_until_closed};

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

pub struct TcpScanner<T> {
    tasks: Vec<JoinHandle<Result<()>>>,
    tx: Option<async_channel::Sender<T>>,
    rx: Option<async_channel::Receiver<(T, Result<()>)>>,
}

impl<T> TcpScanner<T> 
where 
    for<'a> T: GetAddrs<'a> + Send + Sync + 'static,
{
    pub fn new(timeout: Duration, concurrency: usize) -> Self {
        let (tx0, rx0) = async_channel::bounded(concurrency * 2);
        let (tx1, rx1) = async_channel::bounded(concurrency * 2);
        let mut tasks = Vec::with_capacity(concurrency);
        for n in 0..concurrency {
            let tx = tx1.clone();
            let rx = rx0.clone();
            let name = format!("task{}", n + 1);
            let span = tracing::span!(parent:None, tracing::Level::INFO, "", s = &name[..]);
            let task = tokio::spawn(async move {
                let r = scan_task(tx, rx, timeout).await;
                dbgd!("finished with {:?}", r);
                r
            }.instrument(span));
            tasks.push(task);
        }

        Self { tasks, tx: Some(tx0), rx: Some(rx1) } 
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

    pub fn try_send_until_full<I>(&self, relays: &mut I, last: &mut Option<T>) -> Result<usize>
    where 
        I: Iterator<Item = T>
    {
        let tx = match &self.tx {
            Some(tx) => tx,
            None => bail!("try_send_until_full but closed"),
        };

        try_send_until_full(tx, relays, last)

    }

    pub async fn recv_until_empty<C, F>(&self, ctx: &mut C, func: &F) -> Result<()> 
    where
        F: for<'local> AsyncHandler<'local, C, (T, Result<()>)>

    { 
        let rx = match &self.rx {
            Some(rx) => rx,
            None => bail!("recv_until_empty but closed"),
        };

        recv_until_empty(rx, ctx, func).await
    }

    pub async fn recv_until_closed<C, F>(mut self, ctx: &mut C, func: &F) -> Result<()> 
    where
        F: for<'local> AsyncHandler<'local, C, (T, Result<()>)>,
    {
        self.close_send();

        let rx = match &self.rx {
            Some(rx) => rx,
            None => bail!("recv_until_closed but closed"),
        };
        recv_until_closed(rx, ctx, func).await?;

        self.wait_for_finished().await;
        Ok(())
    }


}




pub trait GetAddrs<'a> {
    type Iter: Iterator<Item = &'a SocketAddr> + Send;
    fn get_addrs(&'a self) -> Self::Iter;
}



async fn scan_task<T>(
    tx: async_channel::Sender<(T, Result<()>)>, 
    rx: async_channel::Receiver<T>,
    timeout: Duration,
) -> Result<()> 
where 
    for<'a> T: GetAddrs<'a> + Send + Sync + 'static,
{ 
    let mut _try_targets = 0;
    loop {
        let r = rx.recv().await;
        match r {
            Ok(next) => {
                let mut result = Ok(());
                for addr in next.get_addrs() {
                    let r = connect_with_timeout(addr, timeout).await;
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

async fn connect_with_timeout(addr: &SocketAddr, timeout: Duration) -> Result<()> {
    let _s = tokio::time::timeout(timeout, TcpStream::connect(addr)).await??;    
    Ok(())
}

