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
    pub fn get_addrs_of_clients(&self) -> Vec<SocketAddr> {
        let mut socks = Vec::new();
        let mut direct_connected = false;

        self.close_nodes.nodes.iter()
            .for_each(|node| {
                if let Some(v6) = node.assoc6.ret_saddr {
                    if !node.assoc6.is_bad() {
                        socks.push(v6);
                    }
                }

                if let Some(v4) = node.assoc4.ret_saddr {
                    if !node.assoc4.is_bad() {
                        socks.push(v4);
                    }
                }

                if self.pk == node.pk && (!node.assoc4.is_bad() || !node.assoc6.is_bad()) {
                    direct_connected = true;
                }
            });

        if direct_connected {
            Vec::new()
        } else {
            socks
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn friend_new_test() {
        let _ = DhtFriend::new(gen_keypair().0);
    }
}
