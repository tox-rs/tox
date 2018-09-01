/*!
Module for friend.
*/

use std::time::Instant;
use std::net::SocketAddr;

use toxcore::time::*;
use toxcore::dht::kbucket::*;
use toxcore::crypto_core::*;
use toxcore::dht::server::hole_punching::*;

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
    pub close_nodes: Bucket,
    /// Time when we sent `NodesRequest` packet to a random node from close
    /// nodes list.
    pub last_nodes_req_time: Instant,
    /// How many times we sent `NodesRequest` packet to a random node from close
    /// nodes list.
    pub random_requests_count: u32,
    /// List of nodes to send `NodesRequest` packet.
    pub nodes_to_bootstrap: Bucket,
    /// Struct for hole punching.
    pub hole_punch: HolePunching,
}

impl DhtFriend {
    /// Create new `DhtFriend`.
    pub fn new(pk: PublicKey) -> Self {
        DhtFriend {
            pk,
            close_nodes: Bucket::new(FRIEND_CLOSE_NODES_COUNT),
            last_nodes_req_time: clock_now(),
            random_requests_count: 0,
            nodes_to_bootstrap: Bucket::new(FRIEND_BOOTSTRAP_NODES_COUNT),
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
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use tokio_executor;
    use tokio_timer::clock::*;

    use toxcore::dht::dht_node::*;
    use toxcore::dht::packed_node::*;
    use toxcore::time::ConstNow;

    #[test]
    fn addr_is_unknown() {
        let pk = gen_keypair().0;
        let mut friend = DhtFriend::new(pk);

        assert!(friend.close_nodes.try_add(&pk, &PackedNode::new("192.168.1.1:12345".parse().unwrap(), &gen_keypair().0), true));
        assert!(friend.close_nodes.try_add(&pk, &PackedNode::new("192.168.1.2:12345".parse().unwrap(), &gen_keypair().0), true));

        assert!(!friend.is_addr_known())
    }

    #[test]
    fn addr_is_known() {
        let pk = gen_keypair().0;
        let mut friend = DhtFriend::new(pk);

        assert!(friend.close_nodes.try_add(&pk, &PackedNode::new("192.168.1.1:12345".parse().unwrap(), &gen_keypair().0), true));
        assert!(friend.close_nodes.try_add(&pk, &PackedNode::new("192.168.1.2:12345".parse().unwrap(), &gen_keypair().0), true));

        assert!(friend.close_nodes.try_add(&pk, &PackedNode::new("192.168.1.3:12345".parse().unwrap(), &pk), true));

        assert!(friend.is_addr_known())
    }

    #[test]
    fn get_returned_addrs() {
        let pk = gen_keypair().0;
        let mut friend = DhtFriend::new(pk);

        let nodes = [
            PackedNode::new("192.168.1.1:12345".parse().unwrap(), &gen_keypair().0),
            PackedNode::new("192.168.1.2:12345".parse().unwrap(), &gen_keypair().0),
            PackedNode::new("192.168.1.3:12345".parse().unwrap(), &gen_keypair().0),
        ];
        let addrs: Vec<SocketAddr> = vec![
            "192.168.2.1:12345".parse().unwrap(),
            "192.168.2.2:12345".parse().unwrap(),
            "192.168.2.3:12345".parse().unwrap(),
        ];

        for (&node, &addr) in nodes.iter().zip(addrs.iter()) {
            friend.close_nodes.try_add(&pk, &node, true);
            let dht_node = friend.close_nodes.get_node_mut(&pk, &node.pk).unwrap();
            dht_node.update_returned_addr(addr);
        }

        let returned_addrs = friend.get_returned_addrs();

        use std::collections::HashSet;

        let addrs_set = addrs.into_iter().collect::<HashSet<_>>();
        let returned_addrs_set = returned_addrs.into_iter().collect::<HashSet<_>>();

        assert_eq!(returned_addrs_set, addrs_set);
    }

    #[test]
    fn get_returned_addrs_timed_out() {
        let pk = gen_keypair().0;
        let mut friend = DhtFriend::new(pk);

        let nodes = [
            PackedNode::new("192.168.1.1:12345".parse().unwrap(), &gen_keypair().0),
            PackedNode::new("192.168.1.2:12345".parse().unwrap(), &gen_keypair().0),
            PackedNode::new("192.168.1.3:12345".parse().unwrap(), &gen_keypair().0),
        ];
        let addrs: Vec<SocketAddr> = vec![
            "192.168.2.1:12345".parse().unwrap(),
            "192.168.2.2:12345".parse().unwrap(),
            "192.168.2.3:12345".parse().unwrap(),
        ];

        for (&node, &addr) in nodes.iter().zip(addrs.iter()) {
            friend.close_nodes.try_add(&pk, &node, true);
            let dht_node = friend.close_nodes.get_node_mut(&pk, &node.pk).unwrap();
            dht_node.update_returned_addr(addr);
        }

        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(
            Instant::now() + Duration::from_secs(BAD_NODE_TIMEOUT + 1)
        ));

        with_default(&clock, &mut enter, |_| {
            assert!(friend.get_returned_addrs().is_empty());
        });
    }
}
