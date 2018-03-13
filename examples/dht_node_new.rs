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
use tokio_timer::*;

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::io::{ErrorKind, Error};
use std::time::{self,*};

use tox::toxcore::dht::packet::*;
use tox::toxcore::dht::codec::*;
use tox::toxcore::dht::server::*;
use tox::toxcore::dht::kbucket::*;
use tox::toxcore::dht::packed_node::*;
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
    let handle = core.handle();

    // Bind a UDP listener to the socket address.
    let socket = UdpSocket::bind(&local).unwrap();

    // Create a channel for this socket
    let (tx, rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
    let server_obj = Rc::new(RefCell::new(Server::new(tx, pk, sk)));

    let bootstrap_pk = PublicKey([177, 185, 54, 250, 10, 168, 174,
                            148, 0, 93, 99, 13, 131, 131, 239,
                            193, 129, 141, 80, 158, 50, 133, 100,
                            182, 179, 183, 234, 116, 142, 102, 53, 38]);
    let saddr: SocketAddr = "51.15.37.145:33445".parse().unwrap();
    let bootstrap_pn = PackedNode::new(true, saddr, &bootstrap_pk);

    assert!(server_obj.borrow_mut().kbucket.try_add(&bootstrap_pn));

    let (sink, stream) = UdpFramed::new(socket, DhtCodec).split();
    // The server task asynchronously iterates over and processes each
    // incoming packet.
    let server_obj_c = server_obj.clone();
    let handler = stream.for_each(move |(packet, addr)| {
        let _ = server_obj_c.borrow_mut().handle_packet((packet, addr));
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

    let timer = Timer::default();
    let duration = Duration::new(60, 0); // 60 seconds for PingRequests
    let ping_wakeups = timer.interval(duration);

    let server_obj_c = server_obj.clone();
    let ping_sender = ping_wakeups.for_each(move |()| {
        let kbucket_c = server_obj_c.borrow().kbucket.clone().iter();
        let server_obj_c_c = server_obj_c.clone();

        type LoopFuture = Box<Future<Item = future::Loop<KbucketIter, KbucketIter>, Error = ()>>;

        let packet_sender = future::loop_fn(kbucket_c, move |mut iter| -> LoopFuture {
            let kbucket_c_c = server_obj_c_c.borrow().kbucket.clone().iter();;
            let peer = iter.next();
            match peer {
                None => Box::new(Ok(future::Loop::Break(iter)).into_future()),
                Some(peer) => Box::new(
                    server_obj_c_c.borrow_mut().send_ping_req(peer)
                        .map(|()| future::Loop::Continue(iter))
                        .or_else(|_| Ok(future::Loop::Break(kbucket_c_c)))
                ),
            }
        })
        .map(|_| ());

        handle.spawn(packet_sender);
        Ok(())
        })
        .map_err(|_err| Error::new(ErrorKind::Other, "Ping timer error"));

    let duration = Duration::new(20, 0); // 20 seconds for NodesRequest
    let nodes_wakeups = timer.interval(duration);
    let server_obj_c = server_obj.clone();
    let nodes_sender = nodes_wakeups.for_each(move |()| {
        let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
                                192, 117, 0, 225, 119, 43, 48, 117,
                                84, 109, 112, 57, 243, 216, 4, 171,
                                185, 111, 33, 146, 221, 31, 77, 118]);
        server_obj_c.borrow_mut().send_nodes_req(friend_pk);
        Ok(())
        })
        .map_err(|_err| Error::new(ErrorKind::Other, "Nodes timer error"));

    let duration = Duration::new(3, 0); // 3 seconds for NatPingRequest
    let nat_wakeups = timer.interval(duration);
    let server_obj_c = server_obj.clone();
    let nat_sender = nat_wakeups.for_each(move |()| {
        let peer_pk = gen_keypair().0;
        let node = PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &peer_pk.clone());
        let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
                                192, 117, 0, 225, 119, 43, 48, 117,
                                84, 109, 112, 57, 243, 216, 4, 171,
                                185, 111, 33, 146, 221, 31, 77, 118]);
        server_obj_c.borrow_mut().send_nat_ping_req(node, friend_pk);
        Ok(())
        })
        .map_err(|_err| Error::new(ErrorKind::Other, "NatPing timer error"));

    let packet_sender = ping_sender.select(nodes_sender)
        .map(|_| ())
        .map_err(move |(err, _select_next)| {
            error!("Processing ended with error: {:?}", err);
            err
        });
    let packet_sender = packet_sender.select(nat_sender)
        .map(|_| ())
        .map_err(move |(err, _select_next)| {
            error!("Processing ended with error: {:?}", err);
            err
        });

    let server = server.select(packet_sender)
        .map(|_| ())
        .map_err(move |(err, _select_next)| {
            error!("Processing ended with error: {:?}", err);
            err
        });

    info!("server running on localhost:12345");
    core.run(server).unwrap();
}
