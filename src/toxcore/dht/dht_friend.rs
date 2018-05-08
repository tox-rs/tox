/*
    Copyright (C) 2013 Tox project All Rights Reserved.
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


/*!
Module for friend.
*/

use std::time::{Duration, Instant};
use std::io::{Error, ErrorKind};
use std::mem;

use futures::{future, Future, stream, Stream};

use toxcore::dht::packed_node::*;
use toxcore::dht::kbucket::*;
use toxcore::crypto_core::*;
use toxcore::dht::server::*;
use toxcore::dht::server::client::*;
use toxcore::io_tokio::IoFuture;

/// Hold friend related info.
pub struct DhtFriend {
    // Public key of friend
    pk: PublicKey,
    // close nodes of friend
    close_nodes: Bucket,
    // Last time of NodesRequest packet sent
    last_nodes_req_time: Instant,
    // Counter for bootstappings.
    bootstrap_times: u32,
    // Nodes to bootstrap.
    bootstrap_nodes: Bucket,
}

impl DhtFriend {
    /// Create new DhtFriend object
    /// Maximum bootstrap_times is 5, if you want to bootstrap 2 times, set bootstrap_times to 3.
    pub fn new(pk: PublicKey, bootstrap_times: u32) -> Self {
        DhtFriend {
            pk,
            close_nodes: Bucket::new(None),
            last_nodes_req_time: Instant::now(),
            bootstrap_times,
            bootstrap_nodes: Bucket::new(None),
        }
    }

    /// send NodesRequest packet to bootstap_nodes, close list
    pub fn send_nodes_req_packets(&mut self, server: &Server,
                                  ping_interval: Duration, nodes_req_interval: Duration, bad_node_timeout: Duration) -> IoFuture<()> {
        let ping_bootstrap_nodes = self.ping_bootstrap_nodes(server);
        let ping_and_get_close_nodes = self.ping_and_get_close_nodes(server, ping_interval);
        let send_nodes_req_random = self.send_nodes_req_random(server, bad_node_timeout, nodes_req_interval);

        let res = ping_bootstrap_nodes.join3(
            ping_and_get_close_nodes, send_nodes_req_random
            ).map(|_| () );

        Box::new(res)
    }

    // send NodesRequest to ping on nodes gotten by NodesResponse
    fn ping_bootstrap_nodes(&mut self, server: &Server) -> IoFuture<()> {
        let mut bootstrap_nodes = Bucket::new(None);
        mem::swap(&mut bootstrap_nodes, &mut self.bootstrap_nodes);

        let mut peers_cache = server.get_peers_cache().write();

        let nodes_sender = bootstrap_nodes.nodes.iter()
            .map(|node| {
                let client = peers_cache.entry(node.pk).or_insert_with(ClientData::new);
                server.send_nodes_req(*node, self.pk, client)
            });

        let nodes_stream = stream::futures_unordered(nodes_sender).then(|_| Ok(()));

        Box::new(nodes_stream.for_each(|()| Ok(())))
    }

    // ping to close nodes of friend
    fn ping_and_get_close_nodes(&mut self, server: &Server, ping_interval: Duration) -> IoFuture<()> {
        let mut peers_cache = server.get_peers_cache().write();

        let nodes_sender = self.close_nodes.nodes.iter()
            .map(|node| {
                let client = peers_cache.entry(node.pk).or_insert_with(ClientData::new);

                if client.last_ping_req_time.elapsed() >= ping_interval {
                    client.last_ping_req_time = Instant::now();
                    server.send_nodes_req(*node, self.pk, client)
                } else {
                    Box::new(future::ok(()))
                }
            });

        let nodes_stream = stream::futures_unordered(nodes_sender).then(|_| Ok(()));

        Box::new(nodes_stream.for_each(|()| Ok(())))
    }

    // send NodesRequest to random node which is in close list
    fn send_nodes_req_random(&mut self, server: &Server, bad_node_timeout: Duration, nodes_req_interval: Duration) -> IoFuture<()> {
        let mut peers_cache = server.get_peers_cache().write();

        let good_nodes = self.close_nodes.nodes.iter()
            .filter(|node| {
                let client = peers_cache.entry(node.pk).or_insert_with(ClientData::new);
                client.last_resp_time.elapsed() < bad_node_timeout
            }).collect::<Vec<_>>();

        if !good_nodes.is_empty()
            && self.last_nodes_req_time.elapsed() >= nodes_req_interval
            && self.bootstrap_times < MAX_BOOTSTRAP_TIMES {

            // to increase probability of sending packet to a closer node
            // lower index is closer node
            let num_nodes = good_nodes.len();
            let mut random_node = random_u32() as usize % num_nodes;
            if 0 != random_node {
                random_node -= random_u32() as usize % (random_node + 1);
            }

            let random_node = good_nodes[random_node];

            if let Some(client) = peers_cache.get_mut(&random_node.pk) {
                let res = server.send_nodes_req(*random_node, self.pk, client);
                self.bootstrap_times += 1;
                self.last_nodes_req_time = Instant::now();

                res
            } else {
                Box::new(
                    future::err(
                        Error::new(ErrorKind::Other, "Can't find client in peers_cache")
                    )
                )
            }
        } else {
            Box::new(future::ok(()))
        }
    }

    /// add node to bootstrap_nodes and friend's close_nodes
    pub fn add_to_close(&mut self, node: &PackedNode) ->IoFuture<()> {
        self.bootstrap_nodes.try_add(&self.pk, node);
        self.close_nodes.try_add(&self.pk, node);

        Box::new(future::ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use toxcore::dht::packet::*;
    use toxcore::binary_io::*;
    use futures::sync::mpsc;
    use std::ops::DerefMut;
    use futures::Future;

    #[test]
    fn friend_new_test() {
        let _ = DhtFriend::new(gen_keypair().0, 0);
    }

    #[test]
    fn friend_ping_bootstrap_nodes_test() {
        crypto_init();

        let (friend_pk, _friend_sk) = gen_keypair();
        let mut friend = DhtFriend::new(friend_pk, 0);
        let (pk, sk) = gen_keypair();
        let (tx, rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
        let server = Server::new(tx, pk, sk.clone());

        let (node_pk1, node_sk1) = gen_keypair();
        let (node_pk2, node_sk2) = gen_keypair();
        assert!(friend.bootstrap_nodes.try_add(&friend_pk, &PackedNode {
            pk: node_pk1,
            saddr: "127.0.0.1:33445".parse().unwrap(),
        }));
        assert!(friend.bootstrap_nodes.try_add(&friend_pk, &PackedNode {
            pk: node_pk2,
            saddr: "127.0.0.1:33446".parse().unwrap(),
        }));

        let ping_interval = Duration::from_secs(0);
        let nodes_req_interval = Duration::from_secs(0);
        let bad_nodes_timeout = Duration::from_secs(0);
        assert!(friend.send_nodes_req_packets(&server, ping_interval, nodes_req_interval, bad_nodes_timeout).wait().is_ok());

        rx.take(2).map(|received| {
            let (packet, addr) = received;
            let mut buf = [0; 512];
            let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
            let (_, nodes_req) = NodesRequest::from_bytes(&buf[..size]).unwrap();

            let peers_cache = server.get_peers_cache();
            let mut peers_cache = peers_cache.write();
            let peers_cache = peers_cache.deref_mut();

            if addr == SocketAddr::V4("127.0.0.1:33445".parse().unwrap()) {
                let client = peers_cache.get_mut(&node_pk1).unwrap();
                let nodes_req_payload = nodes_req.get_payload(&node_sk1).unwrap();
                let dur = Duration::from_secs(PING_TIMEOUT);
                assert!(client.check_ping_id(nodes_req_payload.id, dur));
            } else {
                let client = peers_cache.get_mut(&node_pk2).unwrap();
                let nodes_req_payload = nodes_req.get_payload(&node_sk2).unwrap();
                let dur = Duration::from_secs(PING_TIMEOUT);
                assert!(client.check_ping_id(nodes_req_payload.id, dur));
            }
        }).collect().wait().unwrap();
    }

    fn insert_client_to_peers_cache(server: &Server, pk1: PublicKey, pk2: PublicKey) {
        let mut peers_cache = server.get_peers_cache().write();
        peers_cache.insert(pk1, ClientData::new());
        peers_cache.insert(pk2, ClientData::new());
    }

    #[test]
    fn friend_ping_and_get_close_nodes_test() {
        crypto_init();

        let (friend_pk, _friend_sk) = gen_keypair();
        let mut friend = DhtFriend::new(friend_pk, 0);
        let (pk, sk) = gen_keypair();
        let (tx, rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
        let server = Server::new(tx, pk, sk.clone());

        let ping_interval = Duration::from_secs(0);
        let nodes_req_interval = Duration::from_secs(0);
        let bad_nodes_timeout = Duration::from_secs(0);

        // Test with no close_nodes entry, send nothing, but return ok
        assert!(friend.send_nodes_req_packets(&server, ping_interval, nodes_req_interval, bad_nodes_timeout).wait().is_ok());

        // Now, test with close_nodes entry
        let (node_pk1, node_sk1) = gen_keypair();
        let (node_pk2, node_sk2) = gen_keypair();
        assert!(friend.close_nodes.try_add(&friend_pk, &PackedNode {
            pk: node_pk1,
            saddr: "127.0.0.1:33445".parse().unwrap(),
        }));
        assert!(friend.close_nodes.try_add(&friend_pk, &PackedNode {
            pk: node_pk2,
            saddr: "127.0.0.1:33446".parse().unwrap(),
        }));

        let ping_interval = Duration::from_secs(10);
        let nodes_req_interval = Duration::from_secs(0);
        let bad_nodes_timeout = Duration::from_secs(0);

        // But, there are no entry in peers_cache, just return ok
        assert!(friend.send_nodes_req_packets(&server, ping_interval, nodes_req_interval, bad_nodes_timeout).wait().is_ok());

        // Now, test with entry in peers_cache
        insert_client_to_peers_cache(&server, node_pk1, node_pk2);

        let ping_interval = Duration::from_secs(10);
        let nodes_req_interval = Duration::from_secs(0);
        let bad_nodes_timeout = Duration::from_secs(0);

        // There are no ertry which exceeds PING_INTERVAL, so send nothing, just return ok
        assert!(friend.send_nodes_req_packets(&server, ping_interval, nodes_req_interval, bad_nodes_timeout).wait().is_ok());

        let ping_interval = Duration::from_secs(0);
        let nodes_req_interval = Duration::from_secs(0);
        let bad_nodes_timeout = Duration::from_secs(0);

        // Now send packet
        assert!(friend.send_nodes_req_packets(&server, ping_interval, nodes_req_interval, bad_nodes_timeout).wait().is_ok());

        rx.take(2).map(|received| {
            let (packet, addr) = received;
            let mut buf = [0; 512];
            let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
            let (_, nodes_req) = NodesRequest::from_bytes(&buf[..size]).unwrap();

            let peers_cache = server.get_peers_cache();
            let mut peers_cache = peers_cache.write();
            let peers_cache = peers_cache.deref_mut();

            if addr == SocketAddr::V4("127.0.0.1:33445".parse().unwrap()) {
                let client = peers_cache.get_mut(&node_pk1).unwrap();
                let nodes_req_payload = nodes_req.get_payload(&node_sk1).unwrap();
                let dur = Duration::from_secs(PING_TIMEOUT);
                assert!(client.check_ping_id(nodes_req_payload.id, dur));
            } else {
                let client = peers_cache.get_mut(&node_pk2).unwrap();
                let nodes_req_payload = nodes_req.get_payload(&node_sk2).unwrap();
                let dur = Duration::from_secs(PING_TIMEOUT);
                assert!(client.check_ping_id(nodes_req_payload.id, dur));
            }
        }).collect().wait().unwrap();
    }

    #[test]
    fn friend_send_nodes_req_random_test() {
        crypto_init();

        let (friend_pk, _friend_sk) = gen_keypair();
        let mut friend = DhtFriend::new(friend_pk, 0);
        let (pk, sk) = gen_keypair();
        let (tx, rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
        let server = Server::new(tx, pk, sk.clone());

        let ping_interval = Duration::from_secs(0);
        let nodes_req_interval = Duration::from_secs(0);
        let bad_nodes_timeout = Duration::from_secs(0);

        // Test with no close_nodes entry, send nothing, but return ok
        assert!(friend.send_nodes_req_packets(&server, ping_interval, nodes_req_interval, bad_nodes_timeout).wait().is_ok());

        // Now, test with close_nodes entry
        let (node_pk1, node_sk1) = gen_keypair();
        let (node_pk2, node_sk2) = gen_keypair();
        assert!(friend.close_nodes.try_add(&friend_pk, &PackedNode {
            pk: node_pk1,
            saddr: "127.0.0.1:33445".parse().unwrap(),
        }));
        assert!(friend.close_nodes.try_add(&friend_pk, &PackedNode {
            pk: node_pk2,
            saddr: "127.0.0.1:33446".parse().unwrap(),
        }));

        let ping_interval = Duration::from_secs(10);
        let nodes_req_interval = Duration::from_secs(0);
        let bad_nodes_timeout = Duration::from_secs(0);

        // But, there are no entry in peers_cache, just return ok
        assert!(friend.send_nodes_req_packets(&server, ping_interval, nodes_req_interval, bad_nodes_timeout).wait().is_ok());

        // Now, test with entry in peers_cache
        insert_client_to_peers_cache(&server, node_pk1, node_pk2);

        let ping_interval = Duration::from_secs(10);
        let nodes_req_interval = Duration::from_secs(0);
        let bad_nodes_timeout = Duration::from_secs(0);

        // There are no ertry which exceeds BAD_NODE_TIMEOUT, so send nothing, just return ok
        assert!(friend.send_nodes_req_packets(&server, ping_interval, nodes_req_interval, bad_nodes_timeout).wait().is_ok());

        let ping_interval = Duration::from_secs(10);
        let nodes_req_interval = Duration::from_secs(0);
        let bad_nodes_timeout = Duration::from_secs(10);

        // Now send packet
        assert!(friend.send_nodes_req_packets(&server, ping_interval, nodes_req_interval, bad_nodes_timeout).wait().is_ok());

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, nodes_req) = NodesRequest::from_bytes(&buf[..size]).unwrap();

        let peers_cache = server.get_peers_cache();
        let mut peers_cache = peers_cache.write();
        let peers_cache = peers_cache.deref_mut();

        if addr == SocketAddr::V4("127.0.0.1:33445".parse().unwrap()) {
            let client = peers_cache.get_mut(&node_pk1).unwrap();
            let nodes_req_payload = nodes_req.get_payload(&node_sk1).unwrap();
            let dur = Duration::from_secs(PING_TIMEOUT);
            assert!(client.check_ping_id(nodes_req_payload.id, dur));
        } else {
            let client = peers_cache.get_mut(&node_pk2).unwrap();
            let nodes_req_payload = nodes_req.get_payload(&node_sk2).unwrap();
            let dur = Duration::from_secs(PING_TIMEOUT);
            assert!(client.check_ping_id(nodes_req_payload.id, dur));
        }
    }

    #[test]
    fn friend_add_to_close_test() {
        crypto_init();

        let (friend_pk, _friend_sk) = gen_keypair();
        let mut friend = DhtFriend::new(friend_pk, 0);

        let node_pk = gen_keypair().0;

        friend.add_to_close(&PackedNode {
            pk: node_pk,
            saddr: "127.0.0.1:33446".parse().unwrap(),
        });

        assert!(friend.close_nodes.contains(&node_pk));
        assert!(friend.bootstrap_nodes.contains(&node_pk));
    }
}
