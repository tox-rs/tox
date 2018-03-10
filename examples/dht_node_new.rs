/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2018 Namsoo CHO <nscho66@gmail.com>
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

// an example of DHT node with current code
//
extern crate tox;
extern crate futures;
extern crate tokio;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_timer;

#[macro_use]
extern crate log;
extern crate env_logger;

use futures::*;
use futures::sync::mpsc;
use tokio_core::reactor::Core;
use tokio::net::{UdpSocket, UdpFramed};
//use tokio_timer;

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::io::{ErrorKind, Error};
use std::time;

use tox::toxcore::dht::packet::*;
use tox::toxcore::dht::codec::*;
use tox::toxcore::dht::server::*;
use tox::toxcore::crypto_core::*;

fn main() {
    env_logger::init();

    if !crypto_init() {
        error!("Crypto initialization failed.");
        return;
    }

    let (pk, sk) = gen_keypair();

    let local: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let mut core = Core::new().unwrap();

    // Bind a UDP listener to the socket address.
    let socket = UdpSocket::bind(&local).unwrap();

    // Create a channel for this socket
    let (tx, rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
    let server = Rc::new(RefCell::new(Server::new(tx, pk, sk)));

    let (sink, stream) = UdpFramed::new(socket, DhtCodec).split();
    // The server task asynchronously iterates over and processes each
    // incoming packet.
    let handler = stream.for_each(move |(packet, addr)| {
        let _ = server.borrow_mut().handle_packet((packet, addr));
        Ok(())
    })
    .map_err(|err| {
        // All tasks must have an `Error` type of `()`. This forces error
        // handling and helps avoid silencing failures.
        //
        error!("packet receive error = {:?}", err);
        Error::new(ErrorKind::Other, "udp receive error")
    });

    let writer_timer = tokio_timer::wheel()
        .tick_duration(time::Duration::from_secs(1))
        .build()
    ;

    let writer = rx
        .map_err(|_| Error::new(ErrorKind::Other, "rx error"))
        .fold(sink, move |sink, packet| {
            debug!("Send {:?} => {:?}", packet.0, packet.1);
            let sending_future = sink.send(packet);
            let duration = time::Duration::from_secs(30);
            let timeout = writer_timer.timeout(sending_future, duration);
            timeout
        })
        // drop sink when rx stream is exhausted
        .map(|_sink| ())
    ;

    let server = writer.select(handler)
        .map(|_| ())
        .map_err(move |(err, _select_next)| {
            error!("Processing ended with error: {:?}", err);
            err
        });

    info!("server running on localhost:12345");
    core.run(server).unwrap();
}
