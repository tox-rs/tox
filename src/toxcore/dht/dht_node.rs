/*! Data structure used by Bucket.
PackedNode type contains PK and SocketAddress.
PackedNode does not contain status of Node, this struct contains status of node.
Bucket needs status of node, because BAD status node should be replaced with higher proirity than GOOD node.
Even GOOD node is farther than BAD node, BAD node should be replaced.
Here, GOOD node is the node responded within 162 seconds, BAD node is the node not responded over 162 seconds.
*/

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};

use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::kbucket::*;
use crate::toxcore::dht::packed_node::*;
use crate::toxcore::time::*;

/// Ping interval for each node in our lists.
pub const PING_INTERVAL: Duration = Duration::from_secs(60);

/// Interval of time for a non responsive node to become bad.
pub const BAD_NODE_TIMEOUT: Duration = Duration::from_secs(PING_INTERVAL.as_secs() * 2 + 2);

/// The timeout after which a node is discarded completely.
pub const KILL_NODE_TIMEOUT: Duration = 
    Duration::from_secs(BAD_NODE_TIMEOUT.as_secs() + PING_INTERVAL.as_secs());

/// Struct conatains SocketAddrs and timestamps for sending and receiving packet
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SockAndTime<T: Into<SocketAddr> + Copy> {
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

impl<T: Into<SocketAddr> + Copy> SockAndTime<T> {
    /// Create SockAndTime object
    pub fn new(saddr: Option<T>) -> Self {
        let last_resp_time = if saddr.is_some() {
            Some(clock_now())
        } else {
            None
        };
        SockAndTime {
            saddr,
            last_resp_time,
            last_ping_req_time: None,
            ret_saddr: None,
            ret_last_resp_time: None,
        }
    }
    /// Check if the address is considered bad i.e. it does not answer on
    /// addresses for `BAD_NODE_TIMEOUT`.
    pub fn is_bad(&self) -> bool {
        self.last_resp_time.map_or(true, |time| clock_elapsed(time) > BAD_NODE_TIMEOUT)
    }

    /// Check if the node is considered discarded i.e. it does not answer on
    /// addresses for `KILL_NODE_TIMEOUT`.
    pub fn is_discarded(&self) -> bool {
        self.last_resp_time.map_or(true, |time| clock_elapsed(time) > KILL_NODE_TIMEOUT)
    }

    /// Check if `PING_INTERVAL` is passed after last ping request.
    pub fn is_ping_interval_passed(&self) -> bool {
        self.last_ping_req_time.map_or(true, |time| clock_elapsed(time) >= PING_INTERVAL)
    }

    /// Get address if it should be pinged and update `last_ping_req_time`.
    pub fn ping_addr(&mut self) -> Option<T> {
        if let Some(saddr) = self.saddr {
            if !self.is_discarded() && self.is_ping_interval_passed() {
                self.last_ping_req_time = Some(clock_now());
                Some(saddr)
            } else {
                None
            }
        } else {
            None
        }
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
            SocketAddr::V6(v6) => (None, Some(v6)),
        };

        DhtNode {
            pk: pn.pk,
            assoc4: SockAndTime::new(saddr_v4),
            assoc6: SockAndTime::new(saddr_v6),
        }
    }

    /// Check if the node is considered bad i.e. it does not answer both on IPv4
    /// and IPv6 addresses for `BAD_NODE_TIMEOUT` seconds.
    pub fn is_bad(&self) -> bool {
        self.assoc4.is_bad() && self.assoc6.is_bad()
    }

    /// Check if the node is considered discarded i.e. it does not answer both
    /// on IPv4 and IPv6 addresses for `KILL_NODE_TIMEOUT`.
    pub fn is_discarded(&self) -> bool {
        self.assoc4.is_discarded() && self.assoc6.is_discarded()
    }

    /// Return `SocketAddr` for `DhtNode` based on the last response time.
    pub fn get_socket_addr(&self) -> Option<SocketAddr> {
        let addr = if self.assoc4.last_resp_time >= self.assoc6.last_resp_time {
            self.assoc4.saddr.map(Into::into)
        } else {
            self.assoc6.saddr.map(Into::into)
        };

        if addr.is_none() {
            warn!("get_socket_addr: failed to get address of DhtNode!");
        }

        addr
    }

    /// Returns all available socket addresses of DhtNode
    pub fn get_all_addrs(&self) -> Vec<SocketAddr> {
        let addrs = self.assoc4.saddr.into_iter().map(SocketAddr::V4)
            .chain(self.assoc6.saddr.into_iter().map(SocketAddr::V6))
            .collect::<Vec<_>>();

        if addrs.is_empty() {
            warn!("get_all_addrs: DhtNode doesn't have IP addresses!");
        }

        addrs
    }

    /// Convert `DhtNode` to `PackedNode`. The address is chosen based on the
    /// last response time.
    pub fn to_packed_node(&self) -> Option<PackedNode> {
        self.get_socket_addr()
            .map(|addr| PackedNode::new(addr, &self.pk))
    }

    /// Convert `DhtNode` to list of `PackedNode` which can contain IPv4 and
    /// IPv6 addresses.
    pub fn to_all_packed_nodes(&self) -> Vec<PackedNode> {
        self.get_all_addrs()
            .into_iter()
            .map(|addr| PackedNode::new(addr, &self.pk))
            .collect()
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

impl From<PackedNode> for DhtNode {
    fn from(node: PackedNode) -> Self {
        DhtNode::new(node)
    }
}

impl HasPK for DhtNode {
    fn pk(&self) -> PublicKey {
        self.pk
    }
}

impl KbucketNode for DhtNode {
    type NewNode = PackedNode;
    type CheckNode = PackedNode;

    fn is_outdated(&self, other: &PackedNode) -> bool {
        self.assoc4.saddr.map(SocketAddr::V4) != Some(other.saddr) &&
            self.assoc6.saddr.map(SocketAddr::V6) != Some(other.saddr)
    }
    fn update(&mut self, other: &PackedNode) {
        match other.saddr {
            SocketAddr::V4(sock_v4) => {
                self.assoc4.saddr = Some(sock_v4);
                self.assoc4.last_resp_time = Some(clock_now());
            },
            SocketAddr::V6(sock_v6) => {
                self.assoc6.saddr = Some(sock_v6);
                self.assoc6.last_resp_time = Some(clock_now());
            }
        }
    }
    fn is_evictable(&self) -> bool {
        self.is_bad()
    }
    fn eviction_index(nodes: &[Self]) -> Option<usize> {
        nodes.iter().rposition(|n| n.is_discarded()).or_else(||
            nodes.iter().rposition(|n| n.is_bad())
        )
    }
}
