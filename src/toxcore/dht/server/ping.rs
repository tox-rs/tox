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
Module for PingRequest
*/

use std::time::{Duration, Instant};
use std::mem;

use futures::{future, stream, Stream};
use parking_lot::RwLock;

use toxcore::dht::packed_node::*;
use toxcore::dht::kbucket::*;
use toxcore::dht::server::*;
use toxcore::dht::dht_node::*;
use toxcore::io_tokio::IoFuture;

/// Hold data for sending PingRequest
pub struct Ping {
    last_time_send_ping: Instant,
    nodes_to_send_ping: RwLock<Bucket>,
}

impl Ping {
    /// new Ping object
    pub fn new() -> Self {
        Ping {
            last_time_send_ping: Instant::now(),
            nodes_to_send_ping: RwLock::new(Bucket::new(None)),
        }
    }

    fn is_bad_node_timed_out(node: &DhtNode, server: &Server) -> bool {
        node.last_resp_time.elapsed() > Duration::from_secs(server.config.bad_node_timeout)
    }

    fn is_friend(node: &PackedNode, server: &Server) -> bool {
        server.friends.read().iter().any(|friend| friend.pk == node.pk)
    }

    fn is_in_close_list(node: &PackedNode, server: &Server) -> bool {
        server.friends.read().iter()
            .map(|friend| friend.close_nodes.nodes.iter().any(|peer| peer.pk == node.pk))
            .any(|result_bool| result_bool)
    }

    fn is_in_ping_list(node: &PackedNode, ping_list: &Bucket) -> bool {
        ping_list.nodes.iter().any(|peer| peer.pk == node.pk)
    }

    fn is_iterate_time(&self, iterate_interval: Duration) -> bool {
        self.last_time_send_ping.elapsed() >= iterate_interval
    }

    /// try to add node to list to send PingRequest
    /// return true if node is added, false otherwise
    pub fn try_add(&mut self, server: &Server, node: &PackedNode) -> bool {
        // if node already exists in close list and not timed out, then don't send PingRequest
        match server.close_nodes.read().find_node(&node.pk) {
            Some(ref node_in_close_list) if !Ping::is_bad_node_timed_out(node_in_close_list, server) => return false,
            _ => {},
        };

        // if node is not addable to close list, dont't send PingRequest
        if !server.close_nodes.read().can_add(node) {
            return false
        }

        // If node is friend and don't exist in friend's close list then send PingRequest
        if Ping::is_friend(node, server) && !Ping::is_in_close_list(node, server) {
            server.send_ping_req(node);
            return false
        }

        let mut nodes_to_send_ping = self.nodes_to_send_ping.write();
        // if node already exists in ping list, then don't add
        if Ping::is_in_ping_list(node, nodes_to_send_ping.deref()) {
            return false
        }

        // PingRequest is sent only for maximum 8 nodes in Bucket
        nodes_to_send_ping.try_add(&server.pk, node)
    }

    /// send PingRequest to all nodes in list
    pub fn iterate_ping_list(&mut self, server: &Server, iterate_interval: Duration) -> IoFuture<()> {
        if !self.is_iterate_time(iterate_interval) {
            return Box::new(future::ok(()))
        }

        let mut now = Instant::now();
        let mut nodes_to_send_ping = Bucket::new(None);

        mem::swap(&mut self.last_time_send_ping, &mut now);
        mem::swap(self.nodes_to_send_ping.write().deref_mut(), &mut nodes_to_send_ping);

        if nodes_to_send_ping.is_empty() {
            return Box::new(future::ok(()))
        }

        let ping_sender = nodes_to_send_ping.nodes.iter().map(|node| {
            server.send_ping_req(&(node.clone()).into())
        });

        let pings_stream = stream::futures_unordered(ping_sender).then(|_| Ok(()));

        Box::new(pings_stream.for_each(|()| Ok(())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use toxcore::dht::packet::*;
    use futures::sync::mpsc;
    use futures::Future;
    use toxcore::crypto_core::*;
    use toxcore::dht::dht_friend::*;

    const BOOTSTRAP_TIMES: u32 = 5;

    macro_rules! unpack {
        ($variable:expr, $variant:path) => (
            match $variable {
                $variant(inner) => inner,
                other => panic!("Expected {} but got {:?}", stringify!($variant), other),
            }
        )
    }

    #[test]
    fn ping_new_test() {
        let _ = Ping::new();
    }

    #[test]
    fn ping_try_add_test() {
        let (pk, sk) = gen_keypair();
        let (tx, _rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
        let mut server = Server::new(tx, pk, sk);
        let args = ConfigArgs {
            kill_node_timeout: 10,
            ping_timeout: 10,
            ping_interval: 0,
            bad_node_timeout: 10,
            nodes_req_interval: 0,
            nat_ping_req_interval: 0,
            ping_iter_interval: 0,
        };

        server.set_config_values(args);

        let mut ping = Ping::new();

        let pn = PackedNode {
            pk: gen_keypair().0,
            saddr: "127.0.0.1:33445".parse().unwrap(),
        };

        // adding success
        ping.try_add(&server,&pn);

        assert_eq!(pn, ping.nodes_to_send_ping.read().nodes[0].clone().into());

        // try again, it is already in ping list
        assert!(!ping.try_add(&server,&pn));

        // clear ping list
        ping.nodes_to_send_ping.write().nodes.clear();

        // node already exist in close list, do not be added to ping list
        server.close_nodes.write().try_add(&pn);
        ping.try_add(&server,&pn);

        assert!(ping.nodes_to_send_ping.read().is_empty());

        // node is a friend, do not be added to ping list
        server.add_friend(DhtFriend::new(pn.pk, BOOTSTRAP_TIMES));

        ping.try_add(&server,&pn);

        assert!(ping.nodes_to_send_ping.read().is_empty());
    }

    #[test]
    fn ping_iterate_ping_list_test() {
        let (pk, sk) = gen_keypair();
        let (tx, rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
        let server = Server::new(tx, pk, sk.clone());
        let mut ping = Ping::new();

        let (pn_pk, pn_sk) = gen_keypair();
        let pn = PackedNode {
            pk: pn_pk,
            saddr: "127.0.0.1:33445".parse().unwrap(),
        };

        ping.try_add(&server,&pn);

        ping.iterate_ping_list(&server, Duration::from_secs(0)).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, _addr) = received.unwrap();

        let ping_req = unpack!(packet, DhtPacket::PingRequest);

        let ping_map = server.get_ping_map();
        let mut ping_map = ping_map.write();

        let client = ping_map.get_mut(&pn.pk).unwrap();
        let ping_req_payload = ping_req.get_payload(&pn_sk).unwrap();
        let dur = Duration::from_secs(PING_TIMEOUT);
        assert!(client.check_ping_id(ping_req_payload.id, dur));
    }
}
