use std::cmp::Ordering;

use itertools::Itertools;

use tox_crypto::*;
use tox_packet::dht::packed_node::*;
use crate::dht::dht_node::*;
use crate::dht::kbucket::*;
use crate::dht::ktree::*;
use crate::dht::ip_port::IsGlobal;

/** K-buckets structure to hold up to
([`KBUCKET_MAX_ENTRIES`](./constant.KBUCKET_MAX_ENTRIES.html) + 1) *
[`KBUCKET_DEFAULT_SIZE`](./constant.KBUCKET_DEFAULT_SIZE.html) nodes close to
own PK.

Buckets in ktree are sorted by closeness to the PK; closest bucket is the last
one, while furthest is the first one.

This structure implements a force-k modification described in the whitepaper
"Improving the Performance and Robustness of Kademlia-based Overlay Networks".

Unlike `Ktree` it holds additional `KBUCKET_MAX_ENTRIES` nodes that are always
closest to own PK. It forces a peer to always accept nodes that are closer than
known ones which improves search time.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForcedKtree {
    ktree: Ktree,
    kbucket: Kbucket<DhtNode>,
}

impl ForcedKtree {
    /// Create a new `ForceKtree`.
    pub fn new(pk: &PublicKey) -> Self {
        ForcedKtree {
            ktree: Ktree::new(pk),
            kbucket: Kbucket::new(KBUCKET_DEFAULT_SIZE),
        }
    }

    /// Get reference to a `DhtNode` by it's `PublicKey`.
    pub fn get_node(&self, pk: &PublicKey) -> Option<&DhtNode> {
        self.ktree.get_node(pk).or_else(||
            self.kbucket.get_node(&self.ktree.pk, pk)
        )
    }

    /// Get mutable reference to a `DhtNode` by it's `PublicKey`.
    pub fn get_node_mut(&mut self, pk: &PublicKey) -> Option<&mut DhtNode> {
        let base_pk = self.ktree.pk;
        let bucket = &mut self.kbucket;
        self.ktree.get_node_mut(pk).or_else(move ||
            bucket.get_node_mut(&base_pk, pk)
        )
    }

    /** Add [`PackedNode`](./struct.PackedNode.html) to `Kbucket`.

    Node can be added only if:

    * its [`kbucket index`](./fn.kbucket_index.html) is lower than the
      number of buckets.
    * [`Bucket`](./struct.Bucket.html) to which it is added has free space
      or added node is closer to the PK than other node in the bucket.

    Returns `true` if node was added successfully, `false` otherwise.
    */
    pub fn try_add(&mut self, node: PackedNode) -> bool {
        if self.ktree.try_add(node) {
            if let Some(dht_node) = self.kbucket.remove(&self.ktree.pk, &node.pk) {
                let added_node = self.ktree.get_node_mut(&node.pk).expect("Node should be added");
                if node.saddr.is_ipv4() {
                    added_node.assoc6 = dht_node.assoc6;
                } else {
                    added_node.assoc4 = dht_node.assoc4;
                }
            }
            true
        } else if !self.ktree.contains(&node.pk) {
            self.kbucket.try_add(&self.ktree.pk, node, /* evict */ true)
        } else {
            false
        }
    }

    /// Remove [`DhtNode`](./struct.DhtNode.html) with given PK from the
    /// `Kbucket`.
    pub fn remove(&mut self, node_pk: &PublicKey) -> Option<DhtNode> {
        self.ktree.remove(node_pk).or_else(||
            self.kbucket.remove(&self.ktree.pk, node_pk)
        )
    }

    /** Get (up to) `count` closest nodes to given PK.

    Functionality for [`SendNodes`](./struct.SendNodes.html).

    Returns less than `count` nodes only if `Ktree` contains less than `count`
    nodes.

    It should not contain LAN ip node if the request is from global ip.
    */
    pub fn get_closest(&self, pk: &PublicKey, count: u8, only_global: bool) -> Kbucket<PackedNode> {
        let mut kbucket = self.ktree.get_closest(pk, count, only_global);
        for node in self.kbucket.iter().filter(|node| !node.is_bad()) {
            if let Some(pn) = node.to_packed_node() {
                if !only_global || IsGlobal::is_global(&pn.saddr.ip()) {
                    kbucket.try_add(pk, pn, /* evict */ true);
                }
            }
        }
        kbucket
    }

    /**
    Check if `Kbucket` contains [`PackedNode`] with given PK.

    [`PackedNode`]: ./struct.PackedNode.html
    */
    pub fn contains(&self, pk: &PublicKey) -> bool {
        self.kbucket.contains(&self.ktree.pk, pk) ||
            self.ktree.contains(pk)
    }

    /**
    Naive check whether a [`PackedNode`] can be added to the `Kbucket`.

    Returns `true` if [`Bucket`] where node could be placed is not full
    and node is not already in the [`Bucket`].

    Otherwise `false` is returned.

    [`Bucket`]: ./struct.Bucket.html
    [`PackedNode`]: ./struct.PackedNode.html
    */
    pub fn can_add(&self, new_node: &PackedNode) -> bool {
        self.ktree.can_add(new_node) ||
            !self.ktree.contains(&new_node.pk) && self.kbucket.can_add(&self.ktree.pk, new_node, /* evict */ true)
    }

    /** Check if `Kbucket` is empty.

    Returns `true` if all `buckets` are empty, `false`
    otherwise.
    */
    pub fn is_empty(&self) -> bool {
        self.ktree.is_empty() &&
            self.kbucket.is_empty()
    }

    /// Create iterator over [`DhtNode`](./struct.DhtNode.html)s in `Kbucket`.
    /// Nodes that this iterator produces are sorted by distance to a base
    /// `PublicKey` (in ascending order).
    pub fn iter(&self) -> impl Iterator<Item = &DhtNode> {
        let pk = self.ktree.pk;
        self.ktree.iter().merge_by(self.kbucket.iter(), move |x, y|
            pk.distance(&x.pk, &y.pk) == Ordering::Less
        )
    }

    /// Create mutable iterator over [`DhtNode`](./struct.DhtNode.html)s in
    /// `Kbucket`. Nodes that this iterator produces are sorted by distance to a
    /// base `PublicKey` (in ascending order).
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut DhtNode> {
        let pk = self.ktree.pk;
        self.ktree.iter_mut().merge_by(self.kbucket.iter_mut(), move |x, y|
            pk.distance(&x.pk, &y.pk) == Ordering::Less
        )
    }

    /// Check if all nodes in Kbucket are discarded
    pub fn is_all_discarded(&self) -> bool {
        self.iter().all(|node| node.is_discarded())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;
    use std::time::Duration;

    // ForcedKtree::try_add()

    #[test]
    fn forced_ktree_try_add() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut ktree = ForcedKtree::new(&pk);

        for i in 0 .. 8 {
            let mut pk = [i + 2; PUBLICKEYBYTES];
            // make first bit differ from base pk so all these nodes will get
            // into the first kbucket
            pk[0] = 255;
            let pk = PublicKey(pk);
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + u16::from(i));
            let node = PackedNode::new(addr, &pk);
            assert!(ktree.try_add(node));
        }

        // first kbucket if full but it still can accommodate one more node, if
        // it has closer key
        let mut pk = [1; PUBLICKEYBYTES];
        pk[0] = 255;
        let pk = PublicKey(pk);
        let node = PackedNode::new(
            "1.2.3.5:12345".parse().unwrap(),
            &pk
        );
        assert!(ktree.try_add(node));
    }

    // ForcedKtree::remove()

    #[test]
    fn forced_ktree_remove() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut ktree = ForcedKtree::new(&pk);

        let node1 = PackedNode::new(
            "1.2.3.4:12345".parse().unwrap(),
            &PublicKey([1; PUBLICKEYBYTES])
        );
        let node2 = PackedNode::new(
            "1.2.3.4:12345".parse().unwrap(),
            &PublicKey([2; PUBLICKEYBYTES])
        );

        // "removing" non-existent node
        assert!(ktree.remove(&node1.pk).is_none());
        assert!(ktree.is_empty());

        assert!(ktree.kbucket.try_add(&pk, node1, /* evict */ true));
        assert!(!ktree.is_empty());

        assert!(ktree.try_add(node2));
        assert!(!ktree.is_empty());

        assert!(ktree.remove(&node1.pk).is_some());
        assert!(!ktree.is_empty());

        assert!(ktree.remove(&node2.pk).is_some());
        assert!(ktree.is_empty());
    }

    // ForcedKtree::get_closest()

    #[test]
    fn forced_ktree_get_closest() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut ktree = ForcedKtree::new(&pk);

        fn node_by_idx(i: u8) -> PackedNode {
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + u16::from(i));
            PackedNode::new(addr, &PublicKey([i + 1; PUBLICKEYBYTES]))
        }

        for i in 0 .. 4 {
            assert!(ktree.try_add(node_by_idx(i)));
        }
        for i in 4 .. 8 {
            assert!(ktree.kbucket.try_add(&pk, node_by_idx(i), /* evict */ true));
        }

        for count in 1 ..= 4 {
            let closest: Vec<_> = ktree.get_closest(&PublicKey([0; PUBLICKEYBYTES]), count, true).into();
            let should_be = (0 .. count).map(node_by_idx).collect::<Vec<_>>();
            assert_eq!(closest, should_be);

            let closest: Vec<_> = ktree.get_closest(&PublicKey([255; PUBLICKEYBYTES]), count, true).into();
            let should_be = (8 - count .. 8).rev().map(node_by_idx).collect::<Vec<_>>();
            assert_eq!(closest, should_be);
        }
    }

    // ForcedKtree::contains()

    #[test]
    fn forced_ktree_contains() {
        let (pk, _) = gen_keypair();
        let mut ktree = ForcedKtree::new(&pk);

        assert!(!ktree.contains(&pk));

        let node = PackedNode::new(
            "1.2.3.5:12345".parse().unwrap(),
            &gen_keypair().0
        );

        assert!(!ktree.contains(&node.pk));
        assert!(ktree.try_add(node));
        assert!(ktree.contains(&node.pk));


        let node = PackedNode::new(
            "1.2.3.4:12345".parse().unwrap(),
            &PublicKey([1; PUBLICKEYBYTES])
        );

        assert!(!ktree.contains(&node.pk));
        assert!(ktree.kbucket.try_add(&pk, node, /* evict */ true));
        assert!(ktree.contains(&node.pk));
    }

    // ForcedKtree::can_add()

    #[test]
    fn forced_ktree_can_add() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut ktree = ForcedKtree::new(&pk);

        for i in 0 .. 16 {
            let mut pk = [i + 2; PUBLICKEYBYTES];
            // make first bit differ from base pk so all these nodes will get
            // into the first kbucket
            pk[0] = 255;
            let pk = PublicKey(pk);
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + u16::from(i));
            let node = PackedNode::new(addr, &pk);

            assert!(ktree.can_add(&node));
            assert!(ktree.try_add(node));
            assert!(!ktree.can_add(&node));
        }

        let mut pk = [1; PUBLICKEYBYTES];
        pk[0] = 255;
        let pk = PublicKey(pk);
        let node = PackedNode::new(
            "1.2.3.5:12345".parse().unwrap(),
            &pk
        );

        assert!(ktree.can_add(&node));

        let mut pk = [18; PUBLICKEYBYTES];
        pk[0] = 255;
        let pk = PublicKey(pk);
        let node = PackedNode::new(
            "1.2.3.5:12345".parse().unwrap(),
            &pk
        );

        assert!(!ktree.can_add(&node));
    }

    // ForcedKtree::iter()

    #[test]
    fn forced_ktree_iter() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut ktree = ForcedKtree::new(&pk);

        // empty always returns None
        assert!(ktree.iter().next().is_none());

        fn node_by_idx(i: u8) -> PackedNode {
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + u16::from(i));
            PackedNode::new(addr, &PublicKey([i + 1; PUBLICKEYBYTES]))
        }

        for i in 0 .. 4 {
            assert!(ktree.try_add(node_by_idx(i)));
        }
        for i in 4 .. 8 {
            assert!(ktree.kbucket.try_add(&pk, node_by_idx(i), /* evict */ true));
        }

        assert_eq!(ktree.iter().count(), 8);

        // iterator should produce sorted nodes
        for (i, node) in ktree.iter().enumerate() {
            assert_eq!(node.pk, PublicKey([i as u8 + 1; PUBLICKEYBYTES]));
        }
    }

    // ForcedKtree::iter_mut()

    #[test]
    fn forced_ktree_iter_mut() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut ktree = ForcedKtree::new(&pk);

        // empty always returns None
        assert!(ktree.iter_mut().next().is_none());

        fn node_by_idx(i: u8) -> PackedNode {
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + u16::from(i));
            PackedNode::new(addr, &PublicKey([i + 1; PUBLICKEYBYTES]))
        }

        for i in 0 .. 4 {
            assert!(ktree.try_add(node_by_idx(i)));
        }
        for i in 4 .. 8 {
            assert!(ktree.kbucket.try_add(&pk, node_by_idx(i), /* evict */ true));
        }

        assert_eq!(ktree.iter_mut().count(), 8);

        // iterator should produce sorted nodes
        for (i, node) in ktree.iter_mut().enumerate() {
            assert_eq!(node.pk, PublicKey([i as u8 + 1; PUBLICKEYBYTES]));
        }
    }

    // ForcedKtree::is_all_discarded()

    #[tokio::test]
    async fn forced_ktree_is_all_discarded() {
        let (pk, _) = gen_keypair();
        let mut ktree = ForcedKtree::new(&pk);

        let node = PackedNode::new(
            "1.2.3.4:33445".parse().unwrap(),
            &gen_keypair().0
        );
        assert!(ktree.try_add(node));

        let node = PackedNode::new(
            "1.2.3.5:12345".parse().unwrap(),
            &gen_keypair().0
        );
        assert!(ktree.kbucket.try_add(&pk, node, /* evict */ true));

        assert!(!ktree.is_all_discarded());

        tokio::time::pause();
        tokio::time::advance(KILL_NODE_TIMEOUT + Duration::from_secs(1)).await;

        assert!(ktree.is_all_discarded());
    }
}
