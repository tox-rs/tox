/*! Data structure used by Bucket.
PackedNode type contains PK and SocketAddress.
PackedNode does not contain status of Node, this struct contains status of node.
Bucket needs status of node, because BAD status node should be replaced with higher proirity than GOOD node.
Even GOOD node is farther than BAD node, BAD node should be replaced.
Here, GOOD node is the node responded within 162 seconds, BAD node is the node not responded over 162 seconds.
*/

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::cmp::Ordering;
use toxcore::crypto_core::*;
use toxcore::dht::packed_node::*;
use toxcore::dht::kbucket::*;
use toxcore::dht::server::*;

/** Status of node in bucket.
Good means it is online and responded within 162 seconds
Bad means it is probably offline and did not responded for over 162 seconds
When new peer is added to bucket, Bad status node should be replace.
If there are no Bad nodes in bucket, node which is farther than peer is replaced.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NodeStatus {
    /// online
    Good,
    /// maybe offline
    Bad,
}

/// check distance of PK1 and PK2 from base_PK including status of node
pub trait ReplaceOrder {
    /// Check distance of PK1 and Pk2 including status of node
    fn replace_order(&self, &DhtNode, &DhtNode, Duration) -> Ordering;
}

impl ReplaceOrder for PublicKey {
    fn replace_order(&self,
                     node1: &DhtNode,
                     node2: &DhtNode,
                     bad_node_timeout: Duration) -> Ordering {

        trace!(target: "Distance", "Comparing distance between PKs. and status of node");
        match node1.calc_status(bad_node_timeout) {
            NodeStatus::Good => {
                match node2.calc_status(bad_node_timeout) {
                    NodeStatus::Good => { // Good, Good
                        self.distance(&node1.pk, &node2.pk)
                    },
                    NodeStatus::Bad => { // Good, Bad
                        Ordering::Less // Good is closer
                    },
                }
            },
            NodeStatus::Bad => {
                match node2.calc_status(bad_node_timeout) {
                    NodeStatus::Good => { // Bad, Good
                        Ordering::Greater // Bad is farther
                    },
                    NodeStatus::Bad => { // Bad, Bad
                        self.distance(&node1.pk, &node2.pk)
                    },
                }
            },
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
    /// Socket addr of node.
    pub saddr: SocketAddr,
    /// Public Key of the node.
    pub pk: PublicKey,
    /// last received ping/nodes-response time
    pub last_resp_time: Instant,
}

impl DhtNode {
    /// create DhtNode object
    pub fn new(pn: PackedNode) -> DhtNode {
        DhtNode {
            pk: pn.pk,
            saddr: pn.saddr,
            last_resp_time: Instant::now(),
        }
    }

    /// calc. status of node
    pub fn calc_status(&self, bad_node_timeout: Duration) -> NodeStatus {
        if self.last_resp_time.elapsed() > bad_node_timeout {
            NodeStatus::Bad
        } else {
            NodeStatus::Good
        }
    }

    /// check it the node is timed out
    pub fn is_bad_node_timed_out(&self, server: &Server) -> bool {
        self.last_resp_time.elapsed() > Duration::from_secs(server.config.bad_node_timeout)
    }


}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::quickcheck;

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
            bucket.set_bad_node_timeout(0);
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
