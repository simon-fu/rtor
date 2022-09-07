
use std::{pin::Pin, task::{Context, Poll}, marker::PhantomData, time::{Duration, Instant}};
use std::future::Future;
use anyhow::Result;




pub struct PendingForever<T>(PhantomData<T>);

impl<T> Future for PendingForever<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
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


/// refer from https://users.rust-lang.org/t/function-that-takes-an-async-closure/61663
/// To be used with as a HRTB: `for<'local> Handler<'local>`.
pub trait AsyncHandler<'local, C, R> {
    type Fut : Future<Output = Result<()>>;
    fn call (
        self: &'_ Self, // Fn
        _: &'local mut C,
        r: R,
    ) -> Self::Fut;
}


impl<'local, F, Fut, C:'local, R> AsyncHandler<'local, C, R> for F
where
    F : Fn(&'local mut C, R) -> Fut,
    Fut : Future<Output = Result<()>>,
{
    type Fut = Fut;
    fn call (
        self: &'_ Self, // Fn
        ctx: &'local mut C,
        r: R,
    ) -> Fut
    {
        self(ctx, r)
    }
}

