/*!
Module for sending PingRequest.
This module has Bucket for sending PingRequest.
Using Bucket, we can avoid flooding of sending PingRequest.
*/

use std::time::{Duration, Instant};
use std::mem;
use std::io::{Error, ErrorKind};

use futures::{future, stream, Stream};

use toxcore::dht::packed_node::*;
use toxcore::dht::kbucket::*;
use toxcore::dht::server::*;
use toxcore::io_tokio::IoFuture;

const TIME_TO_PING: u64 = 2;

/// Hold data for sending PingRequest
pub struct PingSender {
    last_time_send_ping: Option<Instant>,
    nodes_to_send_ping: Bucket,
}

impl PingSender {
    /// new PingSender object
    pub fn new() -> Self {
        PingSender {
            last_time_send_ping: None,
            nodes_to_send_ping: Bucket::new(None),
        }
    }

    fn is_friend(node: &PackedNode, server: &Server) -> bool {
        server.friends.read().iter().any(|friend| friend.pk == node.pk)
    }

    fn is_in_close_list(node: &PackedNode, server: &Server) -> bool {
        server.friends.read().iter()
            .any(|friend| friend.close_nodes.nodes.iter().any(|peer| peer.pk == node.pk))
    }

    fn is_in_ping_list(&self, node: &PackedNode) -> bool {
        self.nodes_to_send_ping.nodes.iter().any(|peer| peer.pk == node.pk)
    }

    fn can_send_pings(&self) -> bool {
        self.last_time_send_ping.map_or(true, |time| time.elapsed() >= Duration::from_secs(TIME_TO_PING))
    }

    /// try to add node to list to send PingRequest
    /// return true if node is added, false otherwise
    pub fn try_add(&mut self, server: &Server, node: &PackedNode) -> IoFuture<bool> {
        // if node already exists in close list and not timed out, then don't send PingRequest
        let close_nodes = server.close_nodes.read();

        match close_nodes.get_node(&node.pk) {
            Some(ref node_in_close_list) if !node_in_close_list.is_bad() => return Box::new(future::ok(false)),
            _ => {},
        };

        // if node is not addable to close list, don't send PingRequest
        if !close_nodes.can_add(node) {
            return Box::new(future::ok(false))
        }

        // If node is friend and don't exist in friend's close list then send PingRequest
        if PingSender::is_friend(node, server) && !PingSender::is_in_close_list(node, server) {
            return Box::new(server.send_ping_req(node)
                .map(|_| false)
                .map_err(|e| {
                    debug!("Sending PingRequest fails {:?}", e);
                    Error::from(ErrorKind::Other)
                }))
        }

        // if node already exists in ping list, then don't add
        if self.is_in_ping_list(node) {
            return Box::new(future::ok(false));
        }

        // PingRequest is sent only for maximum 8 nodes in Bucket
        Box::new(future::ok(self.nodes_to_send_ping.try_add(&server.pk, node)))
    }

    /// send PingRequest to all nodes in list
    pub fn send_pings(&mut self, server: &Server) -> IoFuture<()> {
        if !self.can_send_pings() {
            return Box::new(future::ok(()))
        }

        let nodes_to_send_ping = mem::replace(&mut self.nodes_to_send_ping, Bucket::new(None));
        self.last_time_send_ping = Some(Instant::now());

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

    #[test]
    fn ping_new_test() {
        let _ = PingSender::new();
    }

    #[test]
    fn ping_try_add_test() {
        let (pk, sk) = gen_keypair();
        let (tx, _rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
        let server = Server::new(tx, pk, sk);

        let mut ping = PingSender::new();

        let pn = PackedNode {
            pk: gen_keypair().0,
            saddr: "127.0.0.1:33445".parse().unwrap(),
        };

        // adding success
        ping.try_add(&server,&pn).wait().unwrap();

        assert_eq!(pn, ping.nodes_to_send_ping.nodes[0].clone().into());

        // try again, it is already in ping list
        assert!(!ping.try_add(&server,&pn).wait().unwrap());

        // clear ping list
        ping.nodes_to_send_ping.nodes.clear();

        // node already exist in close list, do not be added to ping list
        server.close_nodes.write().try_add(&pn);
        ping.try_add(&server,&pn).wait().unwrap();

        assert!(ping.nodes_to_send_ping.is_empty());

        // node is a friend, do not be added to ping list
        server.add_friend(DhtFriend::new(pn.pk, BOOTSTRAP_TIMES));

        ping.try_add(&server,&pn).wait().unwrap();

        assert!(ping.nodes_to_send_ping.is_empty());
    }

    #[test]
    fn ping_send_pings_test() {
        let (pk, sk) = gen_keypair();
        let (tx, rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
        let server = Server::new(tx, pk, sk.clone());
        let mut ping = PingSender::new();

        let (pn_pk, pn_sk) = gen_keypair();
        let pn = PackedNode {
            pk: pn_pk,
            saddr: "127.0.0.1:33445".parse().unwrap(),
        };

        ping.try_add(&server, &pn).wait().unwrap();

        ping.send_pings(&server).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, _addr) = received.unwrap();

        let ping_req = unpack!(packet, DhtPacket::PingRequest);
        let ping_req_payload = ping_req.get_payload(&pn_sk).unwrap();

        let mut request_queue = server.request_queue.write();
        assert!(request_queue.check_ping_id(pn.pk, ping_req_payload.id));
    }
}
