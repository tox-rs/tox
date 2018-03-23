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

use futures::prelude::*;
use futures::sync::mpsc;

use tokio_io::IoFuture;

use std::net::IpAddr;
use std::io::{Error, ErrorKind};

/** `ServerProcessor` helps you to manage incoming clients, handle packets
    and shutdown the connection gracefully
*/
pub struct ServerProcessor {
    /// Push all `Packet`'s received via network from client into this channel
    pub to_server_tx: mpsc::UnboundedSender<Packet>,
    /// Send all `Packet`'s from this channel to client via network
    pub to_client_rx: mpsc::UnboundedReceiver<Packet>,
    /// Run this future to process connection
    pub processor: IoFuture<()>
}

impl ServerProcessor {
    /** Create `ServerProcessor` for the given server and connection
    */
    pub fn create(server: Server, client_pk: PublicKey, addr: IpAddr, port: u16) -> ServerProcessor {
        // Push all `Packet`'s received via network from client into this channel
        let (to_server_tx, to_server_rx) = mpsc::unbounded();
        // Send all `Packet`'s from this channel to client via network
        let (to_client_tx, to_client_rx) = mpsc::unbounded();

        server.insert(Client::new(to_client_tx, &client_pk, addr, port));

        let client_pk_c = client_pk.clone();
        let server_c = server.clone();
        // processor = for each Packet from client process it
        let processor = to_server_rx
            .map_err(|()| Error::from(ErrorKind::UnexpectedEof))
            .for_each(move |packet| {
                debug!("Handle {:?} => {:?}", client_pk_c, packet);
                server_c.handle_packet(&client_pk, packet)
            });

        // TODO ping request = each 30s send PingRequest to client

        let client_pk_c = client_pk.clone();
        let server_c = server.clone();
        let processor = processor
            .then(move |r_processing| {
                debug!("shutdown PK {:?}", &client_pk_c);
                server_c.shutdown_client(&client_pk_c)
                    .then(move |r_shutdown| r_processing.and(r_shutdown))
            });

        let processor = Box::new(processor);
        ServerProcessor { to_server_tx, to_client_rx, processor }
    }
}
