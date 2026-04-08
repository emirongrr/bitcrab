//! Core Actor traits and types for bitcrab-net.

use std::marker::PhantomData;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

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
        Self {
            tx: self.tx.clone(),
        }
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
    pub async fn call<F, R>(&self, f: F) -> Result<R, ActorError>
    where
        F: FnOnce(oneshot::Sender<R>) -> M,
    {
        let (tx, rx) = oneshot::channel();
        let msg = f(tx);
        self.tx
            .send(msg)
            .await
            .map_err(|_| ActorError::Terminated)?;
        rx.await.map_err(|_| ActorError::Dropped)
    }
}

/// Context passed to every actor message handler.
pub struct Context<A: Actor> {
    handle: ActorRef<A::Message>,
    _phantom: PhantomData<A>,
}

impl<A: Actor> Context<A> {
    pub fn new(handle: ActorRef<A::Message>) -> Self {
        Self {
            handle,
            _phantom: PhantomData,
        }
    }

    /// Returns a handle to the current actor.
    pub fn handle(&self) -> ActorRef<A::Message> {
        self.handle.clone()
    }
}

/// The core trait that all actors must implement.
pub trait Actor: Sized + Send + 'static {
    type Message: Send + 'static;

    /// Handle an incoming message.
    fn handle(&mut self, msg: Self::Message, ctx: &mut Context<Self>) -> impl std::future::Future<Output = Result<(), ActorError>> + Send;

    /// Hook executed when the actor starts.
    fn on_start(&mut self, _ctx: &mut Context<Self>) -> impl std::future::Future<Output = Result<(), ActorError>> + Send {
        async { Ok(()) }
    }

    /// Hook executed when the actor stops.
    fn on_stop(&mut self, _ctx: &mut Context<Self>) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }

    /// Spawn the actor into the background.
    fn spawn(mut self) -> ActorRef<Self::Message> {
        let (tx, mut rx) = mpsc::channel(1024);
        let handle = ActorRef::new(tx);
        let ctx_handle = handle.clone();

        tokio::spawn(async move {
            let mut ctx = Context::new(ctx_handle);
            if let Err(e) = self.on_start(&mut ctx).await {
                tracing::error!("Actor failed to start: {}", e);
                return;
            }

            while let Some(msg) = rx.recv().await {
                if let Err(e) = self.handle(msg, &mut ctx).await {
                    tracing::error!("Actor error during message handling: {}", e);
                    break;
                }
            }

            self.on_stop(&mut ctx).await;
        });

        handle
    }
}

