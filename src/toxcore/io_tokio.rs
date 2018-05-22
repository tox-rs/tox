/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2018 Roman <humbug@deeptown.org>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

//! Defines `IoFuture` and `IoStream`

use std::fmt::Debug;
use std::io::{Error, ErrorKind};

use futures::{Future, Sink, Stream};

/// A convenience typedef around a `Future` whose error component is `io::Error`
pub type IoFuture<T> = Box<Future<Item = T, Error = Error> + Send>;

/// A convenience typedef around a `Stream` whose error component is `io::Error`
pub type IoStream<T> = Box<Stream<Item = T, Error = Error> + Send>;

/// Send item to a sink using reference
pub fn send_to<T: Send + 'static, Tx, E: Debug>(tx: &Tx, v: T) -> IoFuture<()>
    where Tx: Sink<SinkItem = T, SinkError = E> + Send + Clone + 'static
{
    Box::new(tx
        .clone() // clone tx sender for 1 send only
        .send(v)
        .map(|_tx| ()) // ignore tx because it was cloned
        .map_err(|e| {
            // This may only happen if rx is gone
            // So cast SendError<T> to a corresponding std::io::Error
            debug!("Send to a sink error {:?}", e);
            Error::from(ErrorKind::UnexpectedEof)
        })
    )
}
