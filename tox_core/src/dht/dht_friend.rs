/*!
Module for friend.
*/

use std::time::Instant;
use std::net::SocketAddr;
use rand::{CryptoRng, Rng};

use crate::time::*;
use crate::dht::kbucket::*;
use tox_crypto::*;
use crate::dht::dht_node::*;
use tox_packet::dht::packed_node::*;
use crate::dht::server::hole_punching::*;

/// Number of bootstrap nodes each friend has.
pub const FRIEND_BOOTSTRAP_NODES_COUNT: u8 = 4;
/// Maximum close nodes friend can have.
pub const FRIEND_CLOSE_NODES_COUNT: u8 = 8;

/// Hold friend related info.
#[derive(Clone, Debug)]
pub struct DhtFriend {
    /// Friend's `PublicKey`.
    pub pk: PublicKey,
    /// Friend's close nodes. If this list contains a node with the same
    /// `PublicKey` as the friend has this means that we know friend's IP
    /// address and successfully reached him.
    pub close_nodes: Kbucket<DhtNode>,
    /// Time when we sent `NodesRequest` packet to a random node from close
    /// nodes list.
    pub last_nodes_req_time: Instant,
    /// How many times we sent `NodesRequest` packet to a random node from close
    /// nodes list.
    pub random_requests_count: u32,
    /// List of nodes to send `NodesRequest` packet.
    pub nodes_to_bootstrap: Kbucket<PackedNode>,
    /// Struct for hole punching.
    pub hole_punch: HolePunching,
}

impl DhtFriend {
    /// Create new `DhtFriend`.
    pub fn new<R: Rng + CryptoRng>(rng: &mut R, pk: PublicKey) -> Self {
        DhtFriend {
            pk,
            close_nodes: Kbucket::new(FRIEND_CLOSE_NODES_COUNT),
            last_nodes_req_time: clock_now(),
            random_requests_count: 0,
            nodes_to_bootstrap: Kbucket::new(FRIEND_BOOTSTRAP_NODES_COUNT),
            hole_punch: HolePunching::new(rng),
        }
    }

    /// IP address is known when `DhtFriend` has node in close nodes list with
    /// the same `PublicKey`.
    pub fn is_addr_known(&self) -> bool {
        // Since nodes in Kbucket are sorted by distance to our PublicKey the
        // node with the same PublicKey will be always the first
        self.close_nodes.nodes.first()
            .map_or(false, |node| node.pk == self.pk)
    }

    /// Get addresses of friend that returned by his close nodes. Close nodes
    /// may return different addresses in case if this friend is behind NAT.
    pub fn get_returned_addrs(&self) -> Vec<SocketAddr> {
        let mut addrs = Vec::new();

        for node in &self.close_nodes.nodes {
            if let Some(v6) = node.assoc6.ret_saddr {
                if !node.assoc6.is_bad() {
                    addrs.push(SocketAddr::V6(v6));
                }
            }

            if let Some(v4) = node.assoc4.ret_saddr {
                if !node.assoc4.is_bad() {
                    addrs.push(SocketAddr::V4(v4));
                }
            }
        }

        addrs
    }

    /// Try to add a node to the friend's close nodes list.
    pub fn try_add_to_close(&mut self, node: PackedNode) -> bool {
        self.close_nodes.try_add(&self.pk, node, /* evict */ true)
    }

    /// Check if a node can be added to the friend's close nodes list.
    pub fn can_add_to_close(&self, node: &PackedNode) -> bool {
        self.close_nodes.can_add(&self.pk, node, /* evict */ true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;
    use rand::thread_rng;

    #[test]
    fn addr_is_unknown() {
        let mut rng = thread_rng();
        let pk = SecretKey::generate(&mut rng).public_key();
        let mut friend = DhtFriend::new(&mut thread_rng(), pk);

        assert!(friend.try_add_to_close(PackedNode::new("192.168.1.1:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key())));
        assert!(friend.try_add_to_close(PackedNode::new("192.168.1.2:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key())));

        assert!(!friend.is_addr_known())
    }

    #[test]
    fn addr_is_known() {
        let mut rng = thread_rng();
        let pk = SecretKey::generate(&mut rng).public_key();
        let mut friend = DhtFriend::new(&mut thread_rng(), pk.clone());

        assert!(friend.try_add_to_close(PackedNode::new("192.168.1.1:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key())));
        assert!(friend.try_add_to_close(PackedNode::new("192.168.1.2:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key())));

        assert!(friend.try_add_to_close(PackedNode::new("192.168.1.3:12345".parse().unwrap(), pk)));

        assert!(friend.is_addr_known())
    }

    #[test]
    fn get_returned_addrs() {
        let mut rng = thread_rng();
        let pk = SecretKey::generate(&mut rng).public_key();
        let mut friend = DhtFriend::new(&mut thread_rng(), pk.clone());

        let nodes = [
            PackedNode::new("192.168.1.1:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key()),
            PackedNode::new("192.168.1.2:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key()),
            PackedNode::new("192.168.1.3:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key()),
        ];
        let addrs: Vec<SocketAddr> = vec![
            "192.168.2.1:12345".parse().unwrap(),
            "192.168.2.2:12345".parse().unwrap(),
            "192.168.2.3:12345".parse().unwrap(),
        ];

        for (node, &addr) in nodes.iter().zip(addrs.iter()) {
            friend.try_add_to_close(node.clone());
            let dht_node = friend.close_nodes.get_node_mut(&pk, &node.pk).unwrap();
            dht_node.update_returned_addr(addr);
        }

        let returned_addrs = friend.get_returned_addrs();

        use std::collections::HashSet;

        let addrs_set = addrs.into_iter().collect::<HashSet<_>>();
        let returned_addrs_set = returned_addrs.into_iter().collect::<HashSet<_>>();

        assert_eq!(returned_addrs_set, addrs_set);
    }

    #[tokio::test]
    async fn get_returned_addrs_timed_out() {
        let mut rng = thread_rng();
        let pk = SecretKey::generate(&mut rng).public_key();
        let mut friend = DhtFriend::new(&mut thread_rng(), pk.clone());

        let nodes = [
            PackedNode::new("192.168.1.1:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key()),
            PackedNode::new("192.168.1.2:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key()),
            PackedNode::new("192.168.1.3:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key()),
        ];
        let addrs: Vec<SocketAddr> = vec![
            "192.168.2.1:12345".parse().unwrap(),
            "192.168.2.2:12345".parse().unwrap(),
            "192.168.2.3:12345".parse().unwrap(),
        ];

        for (node, &addr) in nodes.iter().zip(addrs.iter()) {
            friend.try_add_to_close(node.clone());
            let dht_node = friend.close_nodes.get_node_mut(&pk, &node.pk).unwrap();
            dht_node.update_returned_addr(addr);
        }

        tokio::time::pause();
        tokio::time::advance(BAD_NODE_TIMEOUT + Duration::from_secs(1)).await;

        assert!(friend.get_returned_addrs().is_empty());
    }

    #[test]
    fn can_and_try_add_to_close() {
        let pk = PublicKey::from([0; crypto_box::KEY_SIZE]);
        let mut friend = DhtFriend::new(&mut thread_rng(), pk);

        for i in 0 .. 8 {
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + u16::from(i));
            let node = PackedNode::new(addr, PublicKey::from([i + 2; crypto_box::KEY_SIZE]));
            assert!(friend.try_add_to_close(node));
        }

        let closer_node = PackedNode::new(
            "1.2.3.5:12345".parse().unwrap(),
            PublicKey::from([1; crypto_box::KEY_SIZE])
        );

        // should add a new closer node with eviction
        assert!(friend.can_add_to_close(&closer_node));
        assert!(friend.try_add_to_close(closer_node));
    }
}
