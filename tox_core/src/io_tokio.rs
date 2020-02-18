//! Defines `IoFuture` and `IoStream`

use std::io::{Error as IoError};

use futures::{Future, Stream};
use futures::sink::SinkExt;

/// A convenience typedef around a `Future` whose error component is `io::Error`
pub type IoFuture<T> = Box<dyn Future<Output = Result<T, IoError>> + Send>;

/// A convenience typedef around a `Stream` whose error component is `io::Error`
pub type IoStream<T> = Box<dyn Stream<Item = Result<T, IoError>> + Send>;

/// Sends a message into `Option<Sender<T>>`
pub async fn maybe_send_bounded<T>(
    chan: Option<futures::channel::mpsc::Sender<T>>,
    value: T
) -> Result<(), futures::channel::mpsc::SendError> {
    match chan {
        Some(mut c) => c.send(value).await,
        None => Ok(())
    }
}

/// Sends a message into `Option<UnboundedSender<T>>`
pub async fn maybe_send_unbounded<T>(
    chan: Option<futures::channel::mpsc::UnboundedSender<T>>,
    value: T
) -> Result<(), futures::channel::mpsc::SendError> {
    match chan {
        Some(mut c) => c.send(value).await,
        None => Ok(())
    }
}
