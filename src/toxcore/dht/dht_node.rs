/*! Data structure used by Bucket.
PackedNode type contains PK and SocketAddress.
PackedNode does not contain status of Node, this struct contains status of node.
Bucket needs status of node, because BAD status node should be replaced with higher proirity than GOOD node.
Even GOOD node is farther than BAD node, BAD node should be replaced.
Here, GOOD node is the node responded within 162 seconds, BAD node is the node not responded over 162 seconds.
*/

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};

use toxcore::crypto_core::*;
use toxcore::dht::packed_node::*;
use toxcore::time::*;

/// The number of seconds for a non responsive node to become bad.
pub const BAD_NODE_TIMEOUT: u64 = 182;

/** Struct used by Bucket, DHT maintains close node list, when we got new node,
we should make decision to add new node to close node list, or not.
the PK's distance and status of node help making decision.
Bad node have higher priority than Good node.
If both node is Good node, then we compare PK's distance.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtNode {
    /// Socket addr of node for IPv4.
    pub saddr_v4: Option<SocketAddrV4>,
    /// Socket addr of node for IPv6.
    pub saddr_v6: Option<SocketAddrV6>,
    /// Public Key of the node.
    pub pk: PublicKey,
    /// last received ping/nodes-response time for IPv4
    pub last_resp_time_v4: Option<Instant>,
    /// last received ping/nodes-response time for IPv6
    pub last_resp_time_v6: Option<Instant>,
    /// last sent ping-req time
    pub last_ping_req_time: Option<Instant>,
}

impl DhtNode {
    /// create DhtNode object
    pub fn new(pn: PackedNode) -> DhtNode {
        let (saddr_v4, saddr_v6) = match pn.saddr {
            SocketAddr::V4(v4) => (Some(v4), None),
            SocketAddr::V6(v6) => {
                if let Some(converted_ip4) = v6.ip().to_ipv4() {
                    (Some(SocketAddrV4::new(converted_ip4, v6.port())), None)
                } else {
                    (None, Some(v6))
                }
            },
        };

        let (last_resp_time_v4, last_resp_time_v6) = if saddr_v4.is_some() {
            (Some(clock_now()), None)
        } else {
            (None, Some(clock_now()))
        };

        DhtNode {
            pk: pn.pk,
            saddr_v4,
            saddr_v6,
            last_resp_time_v4,
            last_resp_time_v6,
            last_ping_req_time: None,
        }
    }

    /// Check if the node is timed out i.e. it does not answer both on IPv4 and
    /// IPv6 addresses for `BAD_NODE_TIMEOUT` seconds.
    pub fn is_bad(&self) -> bool {
        self.last_resp_time_v4.map_or(true, |time| clock_elapsed(time) > Duration::from_secs(BAD_NODE_TIMEOUT)) &&
            self.last_resp_time_v6.map_or(true, |time| clock_elapsed(time) > Duration::from_secs(BAD_NODE_TIMEOUT))
    }

    /// return SocketAddr for DhtNode
    pub fn get_socket_addr(&self, is_ipv6_mode: bool) -> Option<SocketAddr> {
        if is_ipv6_mode {
            match self.saddr_v6 {
                Some(v6) => {
                    match self.saddr_v4 {
                        Some(v4) => {
                            if self.last_resp_time_v4 >= self.last_resp_time_v6 {
                                Some(SocketAddr::V4(v4))
                            } else {
                                Some(SocketAddr::V6(v6))
                            }
                        },
                        None => Some(SocketAddr::V6(v6)),
                    }
                },
                None => {
                    match self.saddr_v4 {
                        Some(v4) => Some(SocketAddr::V4(v4)),
                        None => None,
                    }
                },
            }
        } else {
            match self.saddr_v4 {
                Some(v4) => Some(SocketAddr::V4(v4)),
                None => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::quickcheck;

    use toxcore::dht::kbucket::Bucket;

    #[test]
    fn dht_node_clonable() {
        let pn = PackedNode {
            pk: gen_keypair().0,
            saddr: "127.0.0.1:33445".parse().unwrap(),
        };
        let dht_node = DhtNode::new(pn);
        let _ = dht_node.clone();
    }

    #[test]
    fn dht_node_bucket_try_add_test() {
        fn with_nodes(n1: PackedNode, n2: PackedNode, n3: PackedNode,
                      n4: PackedNode, n5: PackedNode, n6: PackedNode,
                      n7: PackedNode, n8: PackedNode) {
            let pk = PublicKey([0; PUBLICKEYBYTES]);
            let mut bucket = Bucket::new(None);
            assert_eq!(true, bucket.try_add(&pk, &n1));
            assert_eq!(true, bucket.try_add(&pk, &n2));
            assert_eq!(true, bucket.try_add(&pk, &n3));
            assert_eq!(true, bucket.try_add(&pk, &n4));
            assert_eq!(true, bucket.try_add(&pk, &n5));
            assert_eq!(true, bucket.try_add(&pk, &n6));
            assert_eq!(true, bucket.try_add(&pk, &n7));
            assert_eq!(true, bucket.try_add(&pk, &n8));

            // updating bucket
            assert_eq!(true, bucket.try_add(&pk, &n1));
        }
        quickcheck(with_nodes as fn(PackedNode, PackedNode, PackedNode, PackedNode,
                                    PackedNode, PackedNode, PackedNode, PackedNode));
    }
}
