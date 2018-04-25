/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2018 Roman Proskuryakov <humbug@deeptown.org>

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

/*! The implementation of TCP Relay ClientProcessor
*/

use toxcore::tcp::client::connection::*;
use toxcore::tcp::packet::*;
use toxcore::io_tokio::IoFuture;

use futures::prelude::*;
use futures::sync::mpsc;

use std::io::{Error, ErrorKind};

/** `ClientProcessor` helps you to manage logic for client connection,
    handle packets, send them back, handle ping/pong gracefully
*/
pub struct ClientProcessor {
    /// Send packets of type `OutgoingPacket` to server
    pub from_client_tx: mpsc::UnboundedSender<OutgoingPacket>,
    /// Client is notified with each packets of type `IncomingPacket`
    pub to_client_rx: mpsc::UnboundedReceiver<IncomingPacket>,

    /// Send packets of type `Packet` to server
    pub from_server_tx: mpsc::UnboundedSender<Packet>,
    /// Server is notified with each `Packet`
    pub to_server_rx: mpsc::UnboundedReceiver<Packet>,

    /// Run this future to process connection
    pub processor: IoFuture<()>
}

impl ClientProcessor {
    /** Create a new `ClientProcessor`
    */
    pub fn new() -> ClientProcessor {
        let (from_client_tx, from_client_rx) = mpsc::unbounded();
        let (to_client_tx, to_client_rx) = mpsc::unbounded();

        let (from_server_tx, from_server_rx) = mpsc::unbounded();
        let (to_server_tx, to_server_rx) = mpsc::unbounded();

        let connection = Connection::new(to_server_tx.clone(), to_client_tx.clone());

        let connection_c = connection.clone();
        let process_messages_from_server = from_server_rx
            .map_err(|_| Error::from(ErrorKind::UnexpectedEof))
            .for_each(move |packet| -> IoFuture<()> {
                debug!("Handle packet from server: {:?}", packet);
                connection_c.handle_from_server(packet)
            })
            .then(|res| {
                debug!("process_messages_from_server ended with {:?}", res);
                res
            });

        let connection_c = connection.clone();
        let process_messages_from_client = from_client_rx
            .map_err(|()| Error::from(ErrorKind::UnexpectedEof))
            .for_each(move |packet| -> IoFuture<()> {
                debug!("Handle packet from client: {:?}", packet);
                connection_c.handle_from_client(packet)
            })
            .then(|res| {
                debug!("process_messages_from_client ended with {:?}", res);
                res
            });

        let processor = process_messages_from_server
            .select(process_messages_from_client)
            .map(|_| ())
            .map_err(|(err, _select_next)| err);

        let processor = Box::new(processor);

        ClientProcessor { to_client_rx, from_client_tx, from_server_tx, to_server_rx, processor }
    }
}

#[cfg(test)]
mod tests {
    use toxcore::tcp::client::*;

    use futures::Future;
    use tokio;

    #[test]
    fn client_processor_shutdown_client() {
        // Create ClientProcessor
        let ClientProcessor {
            from_client_tx,
            to_client_rx,
            from_server_tx,
            to_server_rx,
            processor
        } = ClientProcessor::new();
        let client_processor = processor.map_err(|_| ());

        // shutdown client channel = shutdown client
        drop(from_client_tx);
        drop(to_client_rx);

        let _from_server_tx = from_server_tx;
        let _to_server_rx = to_server_rx;

        tokio::run(client_processor);
    }

    #[test]
    fn client_processor_shutdown_server() {
        // Create ClientProcessor
        let ClientProcessor {
            from_client_tx,
            to_client_rx,
            from_server_tx,
            to_server_rx,
            processor
        } = ClientProcessor::new();
        let client_processor = processor.map_err(|_| ());

        // shutdown server channel = shutdown server
        drop(from_server_tx);
        drop(to_server_rx);

        let _from_client_tx = from_client_tx;
        let _to_client_rx = to_client_rx;

        tokio::run(client_processor);
    }
}
