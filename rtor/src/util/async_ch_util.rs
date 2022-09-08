
use async_channel::{self, TryRecvError, TrySendError, Receiver, Sender};

use anyhow::{Result, bail};

use super::AsyncHandler;


pub fn try_send_until_full<T, I>(tx: &Sender<T>, relays: &mut I, last: &mut Option<T>) -> Result<usize>
where 
    I: Iterator<Item = T>
{
    let mut num = 0;
    while let Some(target) = last.take() {
        let r = tx.try_send(target);
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
                TrySendError::Closed(_target) => bail!("try send but closed"),
            },
        }
    }
    Ok(num)
}


pub async fn recv_until_empty<C, F, R>(rx: &Receiver<R>, ctx: &mut C, func: &F) -> Result<usize> 
where
    F: for<'local> AsyncHandler<'local, C, R>

{ 
    let r = rx.recv().await?;
    func.call(ctx, r).await?;

    let n = do_recv_until_empty(rx, ctx, func).await?;
    Ok(n+1)
}

async fn do_recv_until_empty<C, F, R>(rx: &Receiver<R>, ctx: &mut C, func: &F) -> Result<usize> 
where
    F: for<'local> AsyncHandler<'local, C, R>,
{ 
    let mut num = 0;
    loop {
        let r = rx.try_recv();
        match r {
            Ok(r) => {
                num += 1;
                // write_relay_result(&r, file).await?;
                func.call(ctx, r).await?;

            },
            Err(e) => {
                match e {
                    TryRecvError::Empty => return Ok(num),
                    TryRecvError::Closed => bail!("try recv until empty but closed"),
                }
            },
        }
    }
}

pub async fn recv_until_closed<C, F, R>(rx: &Receiver<R>, ctx: &mut C, func: &F) -> Result<usize> 
where
    F: for<'local> AsyncHandler<'local, C, R>,
{ 
    let mut num = 0;
    loop {
        let r = rx.try_recv();
        match r {
            Ok(r) => {
                num += 1;
                func.call(ctx, r).await?;
            },
            Err(e) => {
                match e {
                    TryRecvError::Closed => {
                        return Ok(num)
                    },

                    TryRecvError::Empty => {
                        num += do_recv_until_closed(rx, ctx, func).await?;
                        return Ok(num)
                    },
   
                }
            },
        }
    }
}

async fn do_recv_until_closed<C, F, R>(rx: &Receiver<R>, ctx: &mut C, func: &F) -> Result<usize> 
where
    F: for<'local> AsyncHandler<'local, C, R>,
{
    let mut num = 0;
    loop {
        let r = rx.recv().await;
        match r {
            Ok(r) => {
                num += 1;
                func.call(ctx, r).await?;
            },
            Err(_e) => {
                return Ok(num)
            },
        }
    } 
}

