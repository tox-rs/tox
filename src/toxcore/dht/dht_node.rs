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

/// Ping interval in seconds for each node in our lists.
pub const PING_INTERVAL: u64 = 60;

/// The number of seconds for a non responsive node to become bad.
pub const BAD_NODE_TIMEOUT: u64 = PING_INTERVAL * 2 + 2;

/// The timeout after which a node is discarded completely.
pub const KILL_NODE_TIMEOUT: u64 = BAD_NODE_TIMEOUT + PING_INTERVAL;

/// Struct conatains SocketAddrs and timestamps for sending and receiving packet
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SockAndTime<T> {
    /// Socket addr of node
    pub saddr: Option<T>,
    /// Last received ping/nodes-response time
    pub last_resp_time: Option<Instant>,
    /// Last sent ping-req time
    pub last_ping_req_time: Option<Instant>,
    /// Returned by this node. Either our friend or us
    pub ret_saddr: Option<T>,
    /// Last time for receiving returned packet
    pub ret_last_resp_time: Option<Instant>,
}

impl<T> SockAndTime<T> {
    /// Create SockAndTime object
    pub fn new(saddr: Option<T>, last_resp_time: Option<Instant>) -> Self {
        SockAndTime {
            saddr,
            last_resp_time,
            last_ping_req_time: None,
            ret_saddr: None,
            ret_last_resp_time: None,
        }
    }
    /// Check if the address is considered bad i.e. it does not answer on
    /// addresses for `BAD_NODE_TIMEOUT` seconds.
    pub fn is_bad(&self) -> bool {
        self.last_resp_time.map_or(true, |time| clock_elapsed(time) > Duration::from_secs(BAD_NODE_TIMEOUT))
    }

    /// Check if the node is considered discarded i.e. it does not answer on
    /// addresses for `KILL_NODE_TIMEOUT` seconds.
    pub fn is_discarded(&self) -> bool {
        self.last_resp_time.map_or(true, |time| clock_elapsed(time) > Duration::from_secs(KILL_NODE_TIMEOUT))
    }

    /// Check if `PING_INTERVAL` is passed after last ping request.
    pub fn is_ping_interval_passed(&self) -> bool {
        self.last_ping_req_time.map_or(true, |time| clock_elapsed(time) >= Duration::from_secs(PING_INTERVAL))
    }
}

/** Struct used by Bucket, DHT maintains close node list, when we got new node,
we should make decision to add new node to close node list, or not.
the PK's distance and status of node help making decision.
Bad node have higher priority than Good node.
If both node is Good node, then we compare PK's distance.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtNode {
    /// Socket addr and times of node for IPv4.
    pub assoc4: SockAndTime<SocketAddrV4>,
    /// Socket addr and times of node for IPv6.
    pub assoc6: SockAndTime<SocketAddrV6>,
    /// Public Key of the node.
    pub pk: PublicKey,
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
            assoc4: SockAndTime::new(saddr_v4, last_resp_time_v4),
            assoc6: SockAndTime::new(saddr_v6, last_resp_time_v6),
        }
    }

    /// Check if the node is considered bad i.e. it does not answer both on IPv4
    /// and IPv6 addresses for `BAD_NODE_TIMEOUT` seconds.
    pub fn is_bad(&self) -> bool {
        self.is_ipv4_bad() && self.is_ipv6_bad()
    }

    /// Check if the IPv4 address is considered bad i.e. it does not answer on IPv4
    /// addresses for `BAD_NODE_TIMEOUT` seconds.
    fn is_ipv4_bad(&self) -> bool {
        self.assoc4.is_bad()
    }

    /// Check if the IPv6 address is considered bad i.e. it does not answer on IPv6
    /// addresses for `BAD_NODE_TIMEOUT` seconds.
    fn is_ipv6_bad(&self) -> bool {
        self.assoc6.is_bad()
    }

    /// Check if the node is considered discarded i.e. it does not answer both
    /// on IPv4 and IPv6 addresses for `KILL_NODE_TIMEOUT` seconds.
    pub fn is_discarded(&self) -> bool {
        self.assoc4.is_discarded() && self.assoc6.is_discarded()
    }

    /// Check if `PING_INTERVAL` is passed after last ping request.
    pub fn is_ping_interval_passed(&self) -> bool {
        self.assoc4.is_ping_interval_passed() || self.assoc6.is_ping_interval_passed()
    }

    /// return SocketAddr for DhtNode
    pub fn get_socket_addr(&self, is_ipv6_enabled: bool) -> Option<SocketAddr> {
        if is_ipv6_enabled {
            match self.assoc6.saddr {
                Some(v6) => {
                    match self.assoc4.saddr {
                        Some(v4) => {
                            if self.assoc4.last_resp_time >= self.assoc6.last_resp_time {
                                Some(SocketAddr::V4(v4))
                            } else {
                                Some(SocketAddr::V6(v6))
                            }
                        },
                        None => Some(SocketAddr::V6(v6)),
                    }
                },
                None => {
                    match self.assoc4.saddr {
                        Some(v4) => Some(SocketAddr::V4(v4)),
                        None => {
                            warn!("get_socket_addr: failed to get address of DhtNode");
                            None
                        },
                    }
                },
            }
        } else {
            match self.assoc4.saddr {
                Some(v4) => Some(SocketAddr::V4(v4)),
                None => {
                    warn!("get_socket_addr: failed to get address of DhtNode");
                    None
                },
            }
        }
    }

    /// convert Dhtnode to PackedNode object based on is_ipv6_enabled flag
    pub fn to_packed_node(&self, is_ipv6_enabled: bool) -> Option<PackedNode> {
        self.get_socket_addr(is_ipv6_enabled)
            .map(|saddr|
                PackedNode {
                    pk: self.pk,
                    saddr,
                })
    }

    /// Update time for ping request, Server sends packets to both IPv4 and IPv6 addresses if exist.
    pub fn update_ping_req_time(&mut self) {
        if self.assoc4.saddr.is_some() {
            self.assoc4.last_ping_req_time = Some(clock_now());
        }
        if self.assoc6.saddr.is_some() {
            self.assoc6.last_ping_req_time = Some(clock_now());
        }
    }

    /// Update returned socket address and time of receiving packet
    pub fn update_returned_addr(&mut self, addr: SocketAddr) {
        match addr {
            SocketAddr::V4(v4) => {
                self.assoc4.ret_saddr = Some(v4);
                self.assoc4.ret_last_resp_time = Some(clock_now());
            },
            SocketAddr::V6(v6) => {
                self.assoc6.ret_saddr = Some(v6);
                self.assoc6.ret_last_resp_time = Some(clock_now());
            },
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
