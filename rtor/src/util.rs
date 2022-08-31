
use std::{pin::Pin, task::{Context, Poll}, marker::PhantomData};
use std::future::Future;

pub struct PendingForever<T>(PhantomData<T>);

impl<T> Future for PendingForever<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}
