/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2018 Namsoo CHO <nscho66@gmail.com>

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

extern crate tox;
extern crate futures;
extern crate tokio_core;
extern crate tokio_io;
extern crate bytes;
#[macro_use]
extern crate log;

use futures::*;
use tokio_core::reactor::{Core, Handle};
use tokio_core::net::UdpSocket;

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::io::{self};

use tox::toxcore::dht_new::codec::*;
use tox::toxcore::dht_new::packet::*;
use tox::toxcore::dht_new::dht_node::*;

struct Shared {
    // udp listening socket
    listener: SocketAddr,
    // tokio core handle
    handle: Handle,
}

/// The state for each connected client.
struct Peer {
    // shared data for operating server.
    state: Rc<RefCell<Shared>>,
    // peer socket address
    addr: SocketAddr,
    // DhtBase packet to send, If DhtNode need to send packet, this field is used.
    to_send: Result<Option<DhtBase>, io::Error>,
}

impl Shared {
    fn new(listener: SocketAddr, handle: Handle) -> Self {
        Shared {
            listener: listener,
            handle: handle,
        }
    }
}

impl Peer {
    fn new( addr : SocketAddr,
            state: Rc<RefCell<Shared>>,
            packet: Result<Option<DhtBase>, io::Error>) -> Peer
    {
        Peer {
            state: state,
            addr: addr,
            to_send: packet,
        }
    }
}

impl Future for Peer {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        if let Ok(Some(ref packet)) = self.to_send {
            let ref peer = self.state.borrow();
            let listener = UdpSocket::bind(&peer.listener, &peer.handle).unwrap();
            let (sink, _) = listener.framed(DhtCodec).split();;
            let to_send = sink.send((self.addr, packet.clone()));
            &peer.handle.spawn(to_send.then(|_| Ok(())));
        } else {};

        self.to_send = Ok(None);

        Ok(Async::NotReady)
    }
}

pub fn main() {

    let addr = "127.0.0.1:12345".parse().unwrap();

    let mut core = Core::new().unwrap();
    let handle = core.handle();

    // Bind a UDP listener to the socket address.
    let listener = UdpSocket::bind(&addr, &handle).unwrap();

    let node = Rc::new(RefCell::new(DhtNode::new().unwrap()));
    let (_, stream) = listener.framed(DhtCodec).split();
    let state = Rc::new(RefCell::new(Shared::new(addr, handle.clone())));
    // The server task asynchronously iterates over and processes each
    // incoming packet.
    let server = stream.for_each(move |(socket, packet)| {
        let packet = node.borrow_mut().handle_packet(&packet.unwrap());
        let peer = Peer::new(
            socket,
            state.clone(),
            packet);
        handle.spawn(peer.then(|_| Ok(())));
        Ok(())
    })
    .map_err(|err| {
        error!("packet receive error = {:?}", err);
    });

    info!("server running on localhost:12345");
    core.run(server).unwrap();
}
