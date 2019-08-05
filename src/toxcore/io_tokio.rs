//! Defines `IoFuture` and `IoStream`

use std::fmt::Debug;
use std::io::{Error as IoError};

use futures::{Async, AsyncSink, Future, Poll, Sink, StartSend, Stream};

/// A convenience typedef around a `Future` whose error component is `io::Error`
pub type IoFuture<T> = Box<dyn Future<Item = T, Error = IoError> + Send>;

/// A convenience typedef around a `Stream` whose error component is `io::Error`
pub type IoStream<T> = Box<dyn Stream<Item = T, Error = IoError> + Send>;

/// Send item to a sink using reference
pub fn send_to<T: Send + 'static, Tx, E: Debug>(tx: &Tx, v: T) -> impl Future<Item=(), Error=E> + Send
    where Tx: Sink<SinkItem = T, SinkError = E> + Send + Clone + 'static
{
    tx
        .clone() // clone tx sender for 1 send only
        .send(v)
        .map(|_tx| ()) // ignore tx because it was cloned
}

/// Send item to a sink using reference
pub fn send_all_to<T: Send + 'static, S, Tx, E: Debug>(tx: &Tx, s: S) -> impl Future<Item=(), Error=E> + Send
    where S: Stream<Item = T, Error = E> + Send + 'static,
          Tx: Sink<SinkItem = T, SinkError = E> + Send + Clone + 'static
{
    tx
        .clone() // clone tx sender for 1 send only
        .send_all(s)
        .map(|_tx| ()) // ignore tx because it was cloned
}

/// `Sink` type that can either be empty or store inner `Sink`. When it's empty
/// it drops all sent elements.
#[derive(Debug, Clone)]
pub struct OptionalSink<S: Sink>(Option<S>);

impl<S: Sink> OptionalSink<S> {
    /// Create new `OptionalSink`.
    pub fn new() -> Self {
        OptionalSink(None)
    }

    /// Set a sink to `OptionalSink`.
    pub fn set(&mut self, sink: S) {
        self.0 = Some(sink);
    }
}

impl<S: Sink> Default for OptionalSink<S> {
    fn default() -> Self {
        OptionalSink::new()
    }
}

impl<S: Sink> Sink for OptionalSink<S> {
    type SinkItem = S::SinkItem;
    type SinkError = S::SinkError;
    fn start_send(&mut self, item: S::SinkItem) -> StartSend<S::SinkItem, S::SinkError> {
        if let Some(ref mut sink) = self.0 {
            sink.start_send(item)
        } else {
            Ok(AsyncSink::Ready)
        }
    }
    fn poll_complete(&mut self) -> Poll<(), S::SinkError> {
        if let Some(ref mut sink) = self.0 {
            sink.poll_complete()
        } else {
            Ok(Async::Ready(()))
        }
    }
    fn close(&mut self) -> Poll<(), S::SinkError> {
        if let Some(ref mut sink) = self.0 {
            sink.close()
        } else {
            Ok(Async::Ready(()))
        }
    }
}
