//! Defines `IoFuture` and `IoStream`

use std::fmt::Debug;
use std::io::{Error as IoError};

use futures::{Future, Sink, Stream};

/// A convenience typedef around a `Future` whose error component is `io::Error`
pub type IoFuture<T> = Box<Future<Item = T, Error = IoError> + Send>;

/// A convenience typedef around a `Stream` whose error component is `io::Error`
pub type IoStream<T> = Box<Stream<Item = T, Error = IoError> + Send>;

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

