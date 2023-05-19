//! Defines `IoFuture` and `IoStream`

use futures::sink::SinkExt;

/// Sends a message into `Option<Sender<T>>`
pub async fn maybe_send_bounded<T>(
    chan: Option<futures::channel::mpsc::Sender<T>>,
    value: T,
) -> Result<(), futures::channel::mpsc::SendError> {
    match chan {
        Some(mut c) => c.send(value).await,
        None => Ok(()),
    }
}

/// Sends a message into `Option<UnboundedSender<T>>`
pub async fn maybe_send_unbounded<T>(
    chan: Option<futures::channel::mpsc::UnboundedSender<T>>,
    value: T,
) -> Result<(), futures::channel::mpsc::SendError> {
    match chan {
        Some(mut c) => c.send(value).await,
        None => Ok(()),
    }
}
