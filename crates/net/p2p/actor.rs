//! Core Actor traits and types for bitcrab-net.

use tokio::sync::{mpsc, oneshot};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ActorError {
    #[error("Actor task has terminated")]
    Terminated,
    #[error("Response channel dropped before sending")]
    Dropped,
    #[error("Actor internal error: {0}")]
    Internal(String),
}

/// A handle to an actor that can send asynchronous requests.
pub struct ActorRef<M> {
    tx: mpsc::Sender<M>,
}

impl<M> Clone for ActorRef<M> {
    fn clone(&self) -> Self {
        Self { tx: self.tx.clone() }
    }
}

impl<M> ActorRef<M> {
    pub fn new(tx: mpsc::Sender<M>) -> Self {
        Self { tx }
    }

    /// Cast a message without waiting for a response (Fire-and-forget).
    pub async fn cast(&self, msg: M) -> Result<(), ActorError> {
        self.tx.send(msg).await.map_err(|_| ActorError::Terminated)
    }

    /// Send a message and wait for a response using a oneshot channel.
    /// Used for "calls" that return data.
    pub async fn call<F, R>(&self, f: F) -> Result<R, ActorError> 
    where 
        F: FnOnce(oneshot::Sender<R>) -> M,
    {
        let (tx, rx) = oneshot::channel();
        let msg = f(tx);
        self.tx.send(msg).await.map_err(|_| ActorError::Terminated)?;
        rx.await.map_err(|_| ActorError::Dropped)
    }
}
