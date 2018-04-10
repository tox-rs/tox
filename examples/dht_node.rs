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
extern crate futures_timer;
extern crate tokio;
extern crate tokio_io;
extern crate rustc_serialize;

#[macro_use]
extern crate log;
extern crate env_logger;

use futures::*;
use futures::sync::mpsc;
use futures_timer::Interval;
use tokio::net::{UdpSocket, UdpFramed};
use tokio_io::IoFuture;

use std::net::{SocketAddr, IpAddr};
use std::io::{ErrorKind, Error};
use std::time::*;
use rustc_serialize::hex::FromHex;

use tox::toxcore::dht::packet::*;
use tox::toxcore::dht::codec::*;
use tox::toxcore::dht::server::*;
use tox::toxcore::dht::packed_node::*;
use tox::toxcore::crypto_core::*;

fn main() {
    env_logger::init();

    if !crypto_init() {
        error!("Crypto initialization failed.");
        return;
    }

    let (pk, sk) = gen_keypair();

    let local: SocketAddr = "0.0.0.0:33445".parse().unwrap(); // 0.0.0.0 for ipv4, [::] for ipv6
    // let local: SocketAddr = "[::]:33445".parse().unwrap(); // 0.0.0.0 for ipv4, [::] for ipv6

    // Bind a UDP listener to the socket address.
    let socket = UdpSocket::bind(&local).unwrap();
    socket.set_broadcast(true).expect("set_broadcast call failed");
    if local.is_ipv6() {
        socket.set_multicast_loop_v6(true).expect("set_multicast_loop_v6 call failed");
    }

    // Create a channel for this socket
    let (tx, rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
    let server_obj = Server::new(tx, pk, sk);

    // get PK bytes of some "random" bootstrap node (Impyy's)
    let bootstrap_pk_bytes = FromHex::from_hex(
        "1D5A5F2F5D6233058BF0259B09622FB40B482E4FA0931EB8FD3AB8E7BF7DAF6F")
        .unwrap();
    // create PK from bytes
    let bootstrap_pk = PublicKey::from_slice(&bootstrap_pk_bytes).unwrap();

    let saddr: SocketAddr = "198.98.51.198:33445".parse().unwrap();
    let bootstrap_pn = PackedNode::new(true, saddr, &bootstrap_pk);
    assert!(server_obj.try_add_to_kbucket(&bootstrap_pn));

    let (sink, stream) = UdpFramed::new(socket, DhtCodec).split();
    // The server task asynchronously iterates over and processes each
    // incoming packet.
    let server_obj_c = server_obj.clone();
    let handler = stream.for_each(move |(packet, addr)| {
        println!("recv = {:?}", packet.clone());
        server_obj_c.handle_packet((packet, addr)).or_else(|err| {
            error!("failed to handle packet: {:?}", err);
            future::ok(())
        })
    }).map_err(|err| {
        // All tasks must have an `Error` type of `()`. This forces error
        // handling and helps avoid silencing failures.
        error!("packet receive error = {:?}", err);
        Error::new(ErrorKind::Other, "udp receive error")
    });

    let writer = rx
        .map_err(|_| Error::new(ErrorKind::Other, "rx error"))
         // filtering ipv6 peer address is temporary fix,
         // dht_node may run as ipv4 only
         // or may run as having two socket (ipv4 socket and ipv6 socket)
        .filter(move |&(ref _packet, addr)| !(local.is_ipv4() && addr.is_ipv6()))
        .fold(sink, move |sink, (packet, mut addr)| {
            debug!("Send {:?} => {:?}", packet, addr);
            println!("send = {:?} {:?}", packet.clone(), addr.clone());
            if local.is_ipv6() {
                if let IpAddr::V4(ip) = addr.ip() {
                    addr = SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), addr.port());
                }
            }
            sink.send((packet, addr))
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

    // Refresh onion symmetric key every 2 hours. This enforces onion paths expiration.
    let refresh_onion_key_wakeups = Interval::new(Duration::from_secs(7200));
    let server_obj_c = server_obj.clone();
    let onion_key_updater = refresh_onion_key_wakeups.for_each(move |()| {
            println!("refresh_onion_key_wakeup");
            server_obj_c.refresh_onion_key();
            future::ok(())
        })
        .map_err(|_err| Error::new(ErrorKind::Other, "Refresh onion key timer error"));

    let server: IoFuture<()> = Box::new(server); 
    let server = add_ping_sender(server, &server_obj);
    let server = add_nat_sender(server, &server_obj, pk);
    let server = add_lan_sender(server, &server_obj, local);
    let server = add_nodes_sender(server, &server_obj);

    let server = server.select(onion_key_updater)
        .map(|_| ())
        .map_err(move |(err, _select_next)| {
            error!("Processing ended with error: {:?}", err);
            ()
        });

    info!("server running on localhost:12345");
    tokio::run(server);
}

fn add_ping_sender(base_selector: IoFuture<()>, server_obj: &Server) -> IoFuture<()> {
    // 60 seconds for PingRequests
    let ping_wakeups = Interval::new(Duration::from_secs(60));

    let server_obj_c = server_obj.clone();
    
    let ping_sender = ping_wakeups.for_each(move |()| {
            println!("ping_wakeup");
            server_obj_c.send_pings()
        })
        .map_err(|_err| Error::new(ErrorKind::Other, "Ping timer error"));
    
    Box::new(base_selector.select(Box::new(ping_sender))
        .map(|_| ())
        .map_err(move |(err, _select_next)| {
            error!("Processing ended with error: {:?}", err);
            err
        }))
}
fn add_nat_sender(base_selector: IoFuture<()>, server_obj: &Server, pk: PublicKey) -> IoFuture<()> {
    // 3 seconds for NatPingRequest
    let nat_wakeups = Interval::new(Duration::from_secs(3));
    let server_obj_c = server_obj.clone();
    let nat_sender = nat_wakeups.for_each(move |()| {
            println!("nat_wakeup");
            // for now loopback nat_request, the sender's pk is dht_node's pk
            let node = PackedNode::new(false, SocketAddr::V4("127.0.0.1:33445".parse().unwrap()), &pk);
            let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
                                    192, 117, 0, 225, 119, 43, 48, 117,
                                    84, 109, 112, 57, 243, 216, 4, 171,
                                    185, 111, 33, 146, 221, 31, 77, 118]);
            server_obj_c.send_nat_ping_req(node, friend_pk)
        })
        .map_err(|_err| Error::new(ErrorKind::Other, "NatPing timer error"));
    
    Box::new(base_selector.select(Box::new(nat_sender))
        .map(|_| ())
        .map_err(move |(err, _select_next)| {
            error!("Processing ended with error: {:?}", err);
            err
        }))
}
fn add_nodes_sender(base_selector: IoFuture<()>, server_obj: &Server) -> IoFuture<()> {
    // 20 seconds for NodesRequest
    let nodes_wakeups = Interval::new(Duration::from_secs(20));
    let server_obj_c = server_obj.clone();
    let nodes_sender = nodes_wakeups.for_each(move |()| {
            println!("nodes_wakeup");
            let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
                                    192, 117, 0, 225, 119, 43, 48, 117,
                                    84, 109, 112, 57, 243, 216, 4, 171,
                                    185, 111, 33, 146, 221, 31, 77, 118]);
            server_obj_c.send_nodes_req(friend_pk)
        })
        .map_err(|_err| Error::new(ErrorKind::Other, "Nodes timer error"));

    Box::new(base_selector.select(Box::new(nodes_sender))
        .map(|_| ())
        .map_err(move |(err, _select_next)| {
            error!("Processing ended with error: {:?}", err);
            err
        }))
}
fn add_lan_sender(base_selector: IoFuture<()>, server_obj: &Server, local: SocketAddr) -> IoFuture<()> {
    // 10 seconds for LanDiscovery
    let lan_wakeups = Interval::new(Duration::from_secs(10));
    let server_obj_c = server_obj.clone();
    let lan_sender = lan_wakeups.for_each(move |()| {
            println!("lan_wakeup");
            if local.is_ipv4() {
                server_obj_c.send_lan_discovery_ipv4()
            } else {
                server_obj_c.send_lan_discovery_ipv6()
            }
        })
        .map_err(|_err| Error::new(ErrorKind::Other, "LanDiscovery timer error"));
    
    Box::new(base_selector.select(Box::new(lan_sender))
        .map(|_| ())
        .map_err(move |(err, _select_next)| {
            error!("Processing ended with error: {:?}", err);
            err
        }))
}
