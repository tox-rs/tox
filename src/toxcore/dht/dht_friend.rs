/*!
Module for friend.
*/

use std::time::Instant;
use std::net::SocketAddr;

use toxcore::time::*;
use toxcore::dht::kbucket::*;
use toxcore::crypto_core::*;
use toxcore::dht::server::hole_punching::*;

/// Number of close nodes each friend has.
pub const FRIEND_CLOSE_NODES_COUNT: u8 = 4;

/// Hold friend related info.
#[derive(Clone, Debug)]
pub struct DhtFriend {
    /// Friend's `PublicKey`.
    pub pk: PublicKey,
    /// Friend's close nodes. If this list contains a node with the same
    /// `PublicKey` as the friend has this means that we know friend's IP
    /// address and successfully reached him.
    pub close_nodes: Bucket,
    /// Time when we sent `NodesRequest` packet to a random node from close
    /// nodes list.
    pub last_nodes_req_time: Instant,
    /// How many times we sent `NodesRequest` packet to a random node from close
    /// nodes list.
    pub bootstrap_times: u32,
    /// List of nodes to send `NodesRequest` packet.
    pub bootstrap_nodes: Bucket,
    /// Struct for hole punching.
    pub hole_punch: HolePunching,
}

impl DhtFriend {
    /// Create new `DhtFriend`.
    pub fn new(pk: PublicKey) -> Self {
        DhtFriend {
            pk,
            close_nodes: Bucket::new(Some(FRIEND_CLOSE_NODES_COUNT)),
            last_nodes_req_time: clock_now(),
            bootstrap_times: 0,
            bootstrap_nodes: Bucket::new(None),
            hole_punch: HolePunching::new(),
        }
    }

    /// IP address is known when `DhtFriend` has node in close nodes list with
    /// the same `PublicKey`.
    pub fn is_addr_known(&self) -> bool {
        // Since nodes in Bucket are sorted by distance to our PublicKey the
        // node with the same PublicKey will be always the first
        self.close_nodes.nodes.first()
            .map_or(false, |node| node.pk == self.pk)
    }

    /// get Socket Address list of a friend, a friend can have multi IP address bacause of NAT
    pub fn get_addrs_of_clients(&self, is_ipv6_mode: bool) -> Vec<SocketAddr> {
        self.close_nodes.nodes.iter()
            .map(|node| node.get_socket_addr(is_ipv6_mode))
            .filter_map(|addr| addr)
            .collect::<Vec<SocketAddr>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use toxcore::dht::packed_node::*;

    #[test]
    fn friend_new_test() {
        let _ = DhtFriend::new(gen_keypair().0);
    }

    #[test]
    fn friend_get_addrs_of_clients_test() {
        let (friend_pk, _friend_sk) = gen_keypair();
        let mut friend = DhtFriend::new(friend_pk);

        let (node_pk1, _node_sk1) = gen_keypair();
        assert!(friend.close_nodes.try_add(&friend_pk, &PackedNode {
            pk: node_pk1,
            saddr: "127.0.0.1:33445".parse().unwrap(),
        }));
        let (node_pk2, _node_sk2) = gen_keypair();
        assert!(friend.close_nodes.try_add(&friend_pk, &PackedNode {
            pk: node_pk2,
            saddr: "[2001:db8::1]:33445".parse().unwrap(),
        }));
        let (node_pk3, _node_sk3) = gen_keypair();
        assert!(friend.close_nodes.try_add(&friend_pk, &PackedNode {
            pk: node_pk3,
            saddr: "127.0.0.2:33445".parse().unwrap(),
        }));
        let (node_pk4, _node_sk4) = gen_keypair();
        assert!(friend.close_nodes.try_add(&friend_pk, &PackedNode {
            pk: node_pk4,
            saddr: "127.0.0.3:33445".parse().unwrap(),
        }));

        assert!(friend.get_addrs_of_clients(true).contains(&"127.0.0.1:33445".parse().unwrap()));
        assert!(friend.get_addrs_of_clients(true).contains(&"127.0.0.2:33445".parse().unwrap()));
        assert!(friend.get_addrs_of_clients(true).contains(&"127.0.0.3:33445".parse().unwrap()));
        assert!(friend.get_addrs_of_clients(true).contains(&"[2001:db8::1]:33445".parse().unwrap()));
    }
}
