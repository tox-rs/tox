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
extern crate failure;
extern crate futures;
extern crate tokio;
extern crate hex;

#[macro_use]
extern crate log;
extern crate env_logger;

use futures::*;
use futures::sync::mpsc;
use hex::FromHex;
use tokio::net::{UdpSocket, UdpFramed};
use tokio::timer::Interval;

use std::env;
use std::net::{SocketAddr, IpAddr};
use std::io::{ErrorKind, Error};
use std::time::{Duration, Instant};

use tox::toxcore::dht::packet::*;
use tox::toxcore::dht::codec::*;
use tox::toxcore::dht::server::*;
use tox::toxcore::dht::packed_node::*;
use tox::toxcore::dht::lan_discovery::*;
use tox::toxcore::crypto_core::*;
use tox::toxcore::io_tokio::*;
use tox::toxcore::dht::dht_friend::*;
use tox::toxcore::net_crypto::*;

fn main() {
    env_logger::init();

    if !crypto_init() {
        error!("Crypto initialization failed.");
        return;
    }

    let first_arg = env::args().nth(1);
    let (server_pk, server_sk) = if first_arg == Some("--const_key".to_string()) {
        // Server constant PK for examples/tests
        let server_pk = PublicKey([177, 185, 54, 250, 10, 168, 174,
                                148, 0, 93, 99, 13, 131, 131, 239,
                                193, 129, 141, 80, 158, 50, 133, 100,
                                182, 179, 183, 234, 116, 142, 102, 53, 38]);
        let server_sk = SecretKey([74, 163, 57, 111, 32, 145, 19, 40,
                                44, 145, 233, 210, 173, 67, 88, 217,
                                140, 147, 14, 176, 106, 255, 54, 249,
                                159, 12, 18, 39, 123, 29, 125, 230]);
        (server_pk, server_sk)
    } else {
        // Use `gen_keypair` to generate random keys
        gen_keypair()
    };

    let (real_pk, _real_sk) = gen_keypair();

    // Create a channel for server to communicate with network
    let (tx, rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();

    // Create a channel for DHT PublicKey updates. When we receive a message
    // from this channel we should update DHT PublicKey of our friend. The main
    // source of such message should be onion client but other modules can learn
    // DHT PublicKey as well.
    let (dht_pk_tx, dht_pk_rx) = mpsc::unbounded();

    // Create channels for packets sending through net crypto connection.
    // Lossless unlike lossy guarantees delivery and ordering of sent packets.
    let (lossless_tx, lossless_rx) = mpsc::unbounded();
    let (lossy_tx, lossy_rx) = mpsc::unbounded();

    let local_addr: SocketAddr = "0.0.0.0:33445".parse().unwrap(); // 0.0.0.0 for ipv4
    // let local_addr: SocketAddr = "[::]:33445".parse().unwrap(); // [::] for ipv6

    // Ignore DHT PublicKey updates for now
    let dht_pk_handler = dht_pk_rx
        .map_err(|_| Error::new(ErrorKind::Other, "rx error"))
        .for_each(|_| future::ok(()));

    // Ignore lossless packets for now
    let lossless_handler = lossless_rx
        .map_err(|_| Error::new(ErrorKind::Other, "rx error"))
        .for_each(|_| future::ok(()));

    // Ignore lossy packets for now
    let lossy_handler = lossy_rx
        .map_err(|_| Error::new(ErrorKind::Other, "rx error"))
        .for_each(|_| future::ok(()));

    let net_crypto = NetCrypto::new(NetCryptoNewArgs {
        udp_tx: tx.clone(),
        dht_pk_tx,
        lossless_tx,
        lossy_tx,
        dht_pk: server_pk,
        dht_sk: server_sk.clone(),
        real_pk
    });

    let lan_discovery_sender = LanDiscoverySender::new(tx.clone(), server_pk, local_addr.is_ipv6());

    let mut server_obj = Server::new(tx, server_pk, server_sk);
    server_obj.set_net_crypto(net_crypto);

    // Bootstrap from nodes
    for &(pk, saddr) in &[
        // Impyy
        ("1D5A5F2F5D6233058BF0259B09622FB40B482E4FA0931EB8FD3AB8E7BF7DAF6F", "198.98.51.198:33445"),
        // nurupo
        ("F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67", "67.215.253.85:33445"),
        // Manolis
        ("461FA3776EF0FA655F1A05477DF1B3B614F7D6B124F7DB1DD4FE3C08B03B640F", "130.133.110.14:33445"),
        // Busindre
        ("A179B09749AC826FF01F37A9613F6B57118AE014D4196A0E1105A98F93A54702", "205.185.116.116:33445"),
        // ray65536
        ("8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832", "85.172.30.117:33445"),
        // fluke571
        ("3CEE1F054081E7A011234883BC4FC39F661A55B73637A5AC293DDF1251D9432B", "194.249.212.109:33445"),
        // MAH69K
        ("DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43", "185.25.116.107:33445"),
        // clearmartin
        ("CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707", "46.101.197.175:443"),
        // tastytea
        ("2B2137E094F743AC8BD44652C55F41DFACC502F125E99E4FE24D40537489E32F", "5.189.176.217:5190"),

    ]
    {
        // get PK bytes of the bootstrap node
        let bootstrap_pk_bytes: [u8; 32] = FromHex::from_hex(pk).unwrap();
        // create PK from bytes
        let bootstrap_pk = PublicKey::from_slice(&bootstrap_pk_bytes).unwrap();

        let saddr: SocketAddr = saddr.parse().unwrap();
        let bootstrap_pn = PackedNode::new(true, saddr, &bootstrap_pk);
        assert!(server_obj.try_add_to_close_nodes(&bootstrap_pn));
    }

    // add example friend
    let pk_str = "9DA18776D7A8ABED7DB67D9B41B853D099A3D4E73C5925B74759E2CFF6289643";
    let friend_pk_bytes: [u8; 32] = FromHex::from_hex(&pk_str).unwrap();
    // create PK from bytes
    let friend_pk = PublicKey::from_slice(&friend_pk_bytes).unwrap();
    // add_friend with args, PK is friend_pk, bootstrap_time initial value is 0, so do bootstrapping 5 times
    server_obj.add_friend(DhtFriend::new(friend_pk, 0));
    // set bootstrap info
    server_obj.set_bootstrap_info(07032018, "This is tox-rs".as_bytes().to_owned());

    // Bind a UDP listener to the socket address.
    let socket = UdpSocket::bind(&local_addr).unwrap();
    socket.set_broadcast(true).expect("set_broadcast call failed");
    if local_addr.is_ipv6() {
        socket.set_multicast_loop_v6(true).expect("set_multicast_loop_v6 call failed");
    }

    let (sink, stream) = UdpFramed::new(socket, DhtCodec).split();
    // The server task asynchronously iterates over and processes each
    // incoming packet.
    let server_obj_c = server_obj.clone();
    let network_reader = stream.then(Ok).filter(|event| // TODO: use filter_map from futures 0.2 to avoid next `expect`
        match event {
            &Ok(_) => true,
            &Err(ref e) => {
                error!("packet receive error = {:?}", e);
                // ignore packet decode errors
                e.cause().downcast_ref::<DecodeError>().is_none()
            }
        }
    ).then(|event: Result<_, ()>|
        event.expect("always ok")
    ).for_each(move |(packet, addr)| {
        println!("recv = {:?}", packet.clone());
        server_obj_c.handle_packet(packet, addr).or_else(|err| {
            error!("failed to handle packet: {:?}", err);
            future::ok(())
        })
    }).map_err(|e| Error::new(ErrorKind::Other, e.compat()));

    let network_writer = rx
        .map_err(|_| Error::new(ErrorKind::Other, "rx error"))
         // filtering ipv6 peer address is temporary fix,
         // dht_node may run as ipv4 only
         // or may run as having two socket (ipv4 socket and ipv6 socket)
        .filter(move |&(ref _packet, addr)| !(local_addr.is_ipv4() && addr.is_ipv6()))
        .fold(sink, move |sink, (packet, mut addr)| {
            debug!("Send {:?} => {:?}", packet, addr);
            println!("send = {:?} {:?}", packet.clone(), addr.clone());
            if local_addr.is_ipv6() {
                if let IpAddr::V4(ip) = addr.ip() {
                    addr = SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), addr.port());
                }
            }
            sink.send((packet, addr)).map_err(|e| Error::new(ErrorKind::Other, e.compat()))
        })
        // drop sink when rx stream is exhausted
        .map(|_sink| ());

    let network = network_writer.select(network_reader)
        .map(|_| ())
        .map_err(move |(err, _select_next)| {
            error!("Processing ended with error: {:?}", err);
            err
        });

    let server: IoFuture<()> = Box::new(network);
    let server = add_server_main_loop(server, &server_obj);
    let server = add_onion_key_refresher(server, &server_obj);
    let server = server.join(run_lan_discovery_sender(lan_discovery_sender)).map(|_| ());
    let server = server.join(dht_pk_handler).map(|_| ());
    let server = server.join(lossless_handler).map(|_| ());
    let server = server.join(lossy_handler).map(|_| ());

    let server = server
        .map(|_| ())
        .map_err(move |err| {
            error!("Processing ended with error: {:?}", err);
            ()
        });

    info!("server running on localhost:12345");
    tokio::run(server);
}

fn add_server_main_loop(base_selector: IoFuture<()>, server_obj: &Server) -> IoFuture<()> {
    // 20 seconds for NodesRequest
    let interval = Duration::from_secs(1);
    let nodes_wakeups = Interval::new(Instant::now() + interval, interval);
    let mut server_obj_c = server_obj.clone();
    let mut bootstrap_fast: bool = false;

    let nodes_sender = nodes_wakeups
        .map_err(|e| Error::new(ErrorKind::Other, format!("Nodes timer error: {:?}", e)))
        .for_each(move |_instant| {
            println!("main_loop_wakeup");
            // flag for fast bootstrapping
            if bootstrap_fast {
                server_obj_c.dht_main_loop()
            } else {
                bootstrap_fast = true;
                // args to main loop, all value is seconds
                let args = ConfigArgs {
                    kill_node_timeout: 182,
                    ping_timeout: 5,
                    ping_interval: 0,
                    bad_node_timeout: 162,
                    nodes_req_interval: 0,
                    nat_ping_req_interval: 0,
                    ping_iter_interval: 0,
                };

                server_obj_c.set_config_values(args);
                let res = server_obj_c.dht_main_loop();

                // args to main loop, all value is seconds
                let args = ConfigArgs {
                    kill_node_timeout: 182,
                    ping_timeout: 5,
                    ping_interval: 60,
                    bad_node_timeout: 162,
                    nodes_req_interval: 20,
                    nat_ping_req_interval: 3,
                    ping_iter_interval: 2,
                };

                server_obj_c.set_config_values(args);

                res
            }
        })
        .map_err(|_err| Error::new(ErrorKind::Other, "Nodes timer error"));

    Box::new(base_selector.select(Box::new(nodes_sender))
        .map(|_| ())
        .map_err(move |(err, _select_next)| {
            error!("Processing ended with error: {:?}", err);
            err
        }))
}

fn run_lan_discovery_sender(mut lan_discovery_sender: LanDiscoverySender) -> IoFuture<()> {
    let interval = Duration::from_secs(LAN_DISCOVERY_INTERVAL);
    let lan_wakeups = Interval::new(Instant::now(), interval);
    let future = lan_wakeups
        .map_err(|e| Error::new(ErrorKind::Other, format!("LanDiscovery timer error: {:?}", e)))
        .for_each(move |_instant| {
            trace!("LAN discovery sender wake up");
            lan_discovery_sender.send()
        });
    Box::new(future)
}

fn add_onion_key_refresher(base_selector: IoFuture<()>, server_obj: &Server) -> IoFuture<()> {
    // Refresh onion symmetric key every 2 hours. This enforces onion paths expiration.
    let interval = Duration::from_secs(7200);
    let refresh_onion_key_wakeups = Interval::new(Instant::now() + interval, interval);
    let server_obj_c = server_obj.clone();
    let onion_key_updater = refresh_onion_key_wakeups
        .map_err(|e| Error::new(ErrorKind::Other, format!("Refresh onion key timer error: {:?}", e)))
        .for_each(move |_instant| {
            println!("refresh_onion_key_wakeup");
            server_obj_c.refresh_onion_key();
            future::ok(())
        });

    Box::new(base_selector.select(Box::new(onion_key_updater))
        .map(|_| ())
        .map_err(move |(err, _select_next)| {
            error!("Processing ended with error: {:?}", err);
            err
        }))
}
