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

/*! The implementation of TCP Relay ServerProcessor
*/

use toxcore::tcp::packet::*;
use toxcore::tcp::server::{Server, Client};
use toxcore::crypto_core::PublicKey;
use toxcore::io_tokio::IoFuture;

use futures::prelude::*;
use futures::sync::mpsc;

use std::net::IpAddr;
use std::io::{Error, ErrorKind};

/** `ServerProcessor` helps you to manage incoming clients, handle packets
    and shutdown the connection gracefully
*/
pub struct ServerProcessor {
    /// Send all `Packet`'s received from client to server
    pub from_client_tx: mpsc::UnboundedSender<Packet>,
    /// Client is notified with each packets of type `Packet`
    pub to_client_rx: mpsc::UnboundedReceiver<Packet>,

    /// Run this future to process connection
    pub processor: IoFuture<()>
}


impl ServerProcessor {
    /** Create `ServerProcessor` for the given server and connection
    */
    pub fn create(server: Server, client_pk: PublicKey, addr: IpAddr, port: u16) -> ServerProcessor {
        let (from_client_tx, from_client_rx) = mpsc::unbounded();
        let (to_client_tx, to_client_rx) = mpsc::unbounded();

        server.insert(Client::new(to_client_tx, &client_pk, addr, port));

        let server_c = server.clone();
        // processor = for each Packet from client process it
        let processor = from_client_rx
            .map_err(|()| Error::from(ErrorKind::UnexpectedEof))
            .for_each(move |packet| {
                debug!("Handle {:?} => {:?}", client_pk, packet);
                server_c.handle_packet(&client_pk, packet)
            });

        // TODO ping request = each 30s send PingRequest to client

        let server_c = server.clone();
        let processor = processor
            .then(move |r_processing| {
                debug!("shutdown PK {:?}", &client_pk);
                server_c.shutdown_client(&client_pk)
                    .then(move |r_shutdown| r_processing.and(r_shutdown))
            });

        let processor = Box::new(processor);
        ServerProcessor { from_client_tx, to_client_rx, processor }
    }
}

#[cfg(test)]
mod tests {
    use toxcore::crypto_core::*;
    use toxcore::tcp::server::*;

    use futures::{Stream, Sink, Future};
    use tokio;

    #[test]
    fn server_processor_shutdown_client() {
        let (client_pk, _sk) = gen_keypair();
        // Create Server with no onion
        let server = Server::new();

        // Create ServerProcessor
        let ServerProcessor {
            from_client_tx,
            to_client_rx,
            processor
        } = ServerProcessor::create(
            server,
            client_pk,
            "0.0.0.0".parse().unwrap(),
            0
        );
        let server_processor = processor.map_err(|_| ());

        // shutdown client channel = shutdown client
        drop(from_client_tx);
        drop(to_client_rx);

        tokio::run(server_processor);
    }
    #[test]
    fn server_processor_handle_packet() {
        use toxcore::tcp::packet::*;

        let (client_pk, _sk) = gen_keypair();
        // Create Server with no onion
        let server = Server::new();

        // Create ServerProcessor
        let ServerProcessor {
            from_client_tx,
            to_client_rx,
            processor
        } = ServerProcessor::create(
            server,
            client_pk,
            "0.0.0.0".parse().unwrap(),
            0
        );
        let server_processor = processor.map(|_| ()).map_err(|_| ());

        let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
                                192, 117, 0, 225, 119, 43, 48, 117,
                                84, 109, 112, 57, 243, 216, 4, 171,
                                185, 111, 33, 146, 221, 31, 77, 118]);

        // send route request to friend
        from_client_tx.send(Packet::RouteRequest(
            RouteRequest { pk: friend_pk }
        )).wait().unwrap();

        // wait for route response
        let receiver = to_client_rx.into_future()
            .and_then(move |(packet, _tail)| {
                let expected_packet = Packet::RouteResponse(RouteResponse {
                    connection_id: 16, pk: friend_pk
                });
                assert_eq!(packet.unwrap(), expected_packet);
                Ok(())
            })
            .map(|_| ()).map_err(|_| ());

        // run server
        let server = server_processor.join(receiver).map(|_| ()).map_err(|_| ());
        tokio::run(server);
    }
}
