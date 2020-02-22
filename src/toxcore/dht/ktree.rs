//! K-buckets structure

use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::dht_node::*;
use crate::toxcore::dht::packed_node::*;
use crate::toxcore::dht::ip_port::IsGlobal;
use crate::toxcore::dht::kbucket::*;

/** K-buckets structure to hold up to
[`KBUCKET_MAX_ENTRIES`](./constant.KBUCKET_MAX_ENTRIES.html) *
[`KBUCKET_DEFAULT_SIZE`](./constant.KBUCKET_DEFAULT_SIZE.html) nodes close to
own PK.

Buckets in ktree are sorted by closeness to the PK; closest bucket is the last
one, while furthest is the first one.

Further reading: [Tox spec](https://zetok.github.io/tox-spec#k-buckets).

The name references to the kademlia binary tree from
[Kademlia whitepaper](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf).
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ktree {
    /// `PublicKey` for which `Ktree` holds close nodes.
    pk: PublicKey,
    /// List of [`Kbucket`](./struct.Kbucket.html)s.
    pub kbuckets: Vec<Kbucket<DhtNode>>,
}

/** Maximum number of [`Kbucket`](./struct.Kbucket.html)s that [`Ktree`]
can hold.

Realistically, not even half of that will be ever used, given how
[index calculation](./fn.kbucket_index.html) works.

[`Ktree`]: ./struct.Ktree.html
*/
pub const KBUCKET_MAX_ENTRIES: u8 = ::std::u8::MAX;

impl Ktree {
    /// Create a new `Ktree`.
    pub fn new(pk: &PublicKey) -> Self {
        trace!(target: "Ktree", "Creating new Ktree with PK: {:?}", pk);
        Ktree {
            pk: *pk,
            kbuckets: vec![Kbucket::new(KBUCKET_DEFAULT_SIZE); KBUCKET_MAX_ENTRIES as usize]
        }
    }

    /// Get reference to a `DhtNode` by it's `PublicKey`.
    pub fn get_node(&self, pk: &PublicKey) -> Option<&DhtNode> {
        self.kbucket_index(pk).and_then(|index|
            self.kbuckets[index]
                .get_node(&self.pk, pk)
        )
    }

    /// Get mutable reference to a `DhtNode` by it's `PublicKey`.
    pub fn get_node_mut(&mut self, pk: &PublicKey) -> Option<&mut DhtNode> {
        self.kbucket_index(pk).and_then(move |index|
            self.kbuckets[index]
                .get_node_mut(&self.pk, pk)
        )
    }

    /** Return the possible internal index of [`Kbucket`](./struct.Kbucket.html)
        where the key could be inserted/removed.

    Same as [`kbucket index`](./fn.kbucket_index.html) but uses stored in
    `Ktree` public key.

    Returns `None` only if supplied key is the same as stored in `Ktree` key.
    */
    fn kbucket_index(&self, pk: &PublicKey) -> Option<usize> {
        kbucket_index(&self.pk, pk).map(|index| index as usize)
    }

    /** Add [`PackedNode`](./struct.PackedNode.html) to `Ktree`.

    Node can be added only if:

    * its [`kbucket index`](./fn.kbucket_index.html) is lower than the
      number of kbuckets.
    * [`Kbucket`](./struct.Kbucket.html) to which it is added has free space
      or added node is closer to the PK than other node in the kbucket.

    Returns `true` if node was added successfully, `false` otherwise.
    */
    pub fn try_add(&mut self, node: PackedNode) -> bool {
        debug!(target: "Ktree", "Trying to add PackedNode.");
        trace!(target: "Ktree", "With PN: {:?}; and self: {:?}", node, self);

        match self.kbucket_index(&node.pk) {
            Some(index) => self.kbuckets[index].try_add(&self.pk, node, /* evict */ false),
            None => {
                trace!("Failed to add node: {:?}", node);
                false
            }
        }
    }

    /// Remove [`DhtNode`](./struct.DhtNode.html) with given PK from the
    /// `Ktree`.
    pub fn remove(&mut self, node_pk: &PublicKey) -> Option<DhtNode> {
        trace!(target: "Ktree", "Removing PK: {:?} from Ktree: {:?}", node_pk,
                self);

        match self.kbucket_index(node_pk) {
            Some(index) => self.kbuckets[index].remove(&self.pk, node_pk),
            None => {
                trace!("Failed to remove PK: {:?}", node_pk);
                None
            },
        }
    }

    /** Get (up to) 4 closest nodes to given PK.

    Functionality for [`SendNodes`](./struct.SendNodes.html).

    Returns less than `count` nodes only if `Ktree` contains less than `count`
    nodes.

    It should not contain LAN ip node if the request is from global ip.
    */
    pub fn get_closest(&self, pk: &PublicKey, count: u8, only_global: bool) -> Kbucket<PackedNode> {
        debug!(target: "Ktree", "Getting closest nodes.");
        trace!(target: "Ktree", "With PK: {:?} and self: {:?}", pk, self);

        let mut kbucket = Kbucket::new(count);
        for node in self.iter().filter(|node| !node.is_bad()) {
            if let Some(pn) = node.to_packed_node() {
                if !only_global || IsGlobal::is_global(&pn.saddr.ip()) {
                    kbucket.try_add(pk, pn, /* evict */ true);
                }
            }
        }
        trace!("Returning nodes: {:?}", kbucket);
        kbucket
    }

    /**
    Check if `Ktree` contains [`PackedNode`] with given PK.

    [`PackedNode`]: ./struct.PackedNode.html
    */
    pub fn contains(&self, pk: &PublicKey) -> bool {
        match self.kbucket_index(pk) {
            Some(i) => self.kbuckets[i].contains(&self.pk, pk),
            None => false,
        }
    }

    /**
    Naive check whether a [`PackedNode`] can be added to the `Ktree`.

    Returns `true` if [`Kbucket`] where node could be placed is not full
    and node is not already in the [`Kbucket`].

    Otherwise `false` is returned.

    [`Kbucket`]: ./struct.Kbucket.html
    [`PackedNode`]: ./struct.PackedNode.html
    */
    pub fn can_add(&self, new_node: &PackedNode) -> bool {
        match self.kbucket_index(&new_node.pk) {
            None => false,
            Some(i) =>
                self.kbuckets[i].can_add(&self.pk, new_node, /* evict */ false),
        }
    }

    /** Check if `Ktree` is empty.

    Returns `true` if all `kbuckets` are empty, `false`
    otherwise.
    */
    pub fn is_empty(&self) -> bool {
        self.kbuckets.iter().all(|kbucket| kbucket.is_empty())
    }

    /// Create iterator over [`DhtNode`](./struct.DhtNode.html)s in `Ktree`.
    /// Nodes that this iterator produces are sorted by distance to a base
    /// `PublicKey` (in ascending order).
    pub fn iter(&self) -> impl Iterator<Item = &DhtNode> + Clone {
        self.kbuckets.iter()
            .rev()
            .flat_map(|kbucket| kbucket.iter())
    }

    /// Create mutable iterator over [`DhtNode`](./struct.DhtNode.html)s in
    /// `Ktree`. Nodes that this iterator produces are sorted by distance to a
    /// base `PublicKey` (in ascending order).
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut DhtNode> {
        self.kbuckets.iter_mut()
            .rev()
            .flat_map(|kbucket| kbucket.iter_mut())
    }

    /// Check if all nodes in Ktree are discarded
    pub fn is_all_discarded(&self) -> bool {
        self.iter()
            .all(|node| node.is_discarded())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;
    use std::time::Duration;

    #[test]
    fn ktree_new() {
        crypto_init().unwrap();
        let pk = gen_keypair().0;
        let ktree = Ktree::new(&pk);
        assert_eq!(pk, ktree.pk);
    }

    // Ktree::try_add()

    #[test]
    fn ktree_try_add() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut ktree = Ktree::new(&pk);

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

        // first kbucket if full so it can't accommodate one more node, even if
        // it has closer key
        let mut pk = [1; PUBLICKEYBYTES];
        pk[0] = 255;
        let pk = PublicKey(pk);
        let node = PackedNode::new(
            "1.2.3.5:12345".parse().unwrap(),
            &pk
        );
        assert!(!ktree.try_add(node));

        // but nodes still can be added to other kbuckets
        let pk = PublicKey([1; PUBLICKEYBYTES]);
        let node = PackedNode::new(
            "1.2.3.5:12346".parse().unwrap(),
            &pk
        );
        assert!(ktree.try_add(node));
    }

    #[test]
    fn ktree_try_add_self() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut ktree = Ktree::new(&pk);

        let node = PackedNode::new(
            "1.2.3.5:12345".parse().unwrap(),
            &pk
        );

        assert!(!ktree.try_add(node));
    }

    // Ktree::remove()

    #[test]
    fn ktree_remove() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut ktree = Ktree::new(&pk);

        let node = PackedNode::new(
            "1.2.3.4:12345".parse().unwrap(),
            &PublicKey([1; PUBLICKEYBYTES])
        );

        // "removing" non-existent node
        assert!(ktree.remove(&node.pk).is_none());
        assert!(ktree.is_empty());

        assert!(ktree.try_add(node));

        assert!(!ktree.is_empty());

        assert!(ktree.remove(&node.pk).is_some());

        assert!(ktree.is_empty());
    }

    // Ktree::get_closest()

    #[test]
    fn ktree_get_closest() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut ktree = Ktree::new(&pk);

        fn node_by_idx(i: u8) -> PackedNode {
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + u16::from(i));
            PackedNode::new(addr, &PublicKey([i + 1; PUBLICKEYBYTES]))
        }

        for i in 0 .. 8 {
            assert!(ktree.try_add(node_by_idx(i)));
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

    // Ktree::contains()

    #[test]
    fn ktree_contains() {
        crypto_init().unwrap();
        let (pk, _) = gen_keypair();
        let mut ktree = Ktree::new(&pk);

        assert!(!ktree.contains(&pk));

        let node = PackedNode::new(
            "1.2.3.5:12345".parse().unwrap(),
            &gen_keypair().0
        );

        assert!(!ktree.contains(&node.pk));
        assert!(ktree.try_add(node));
        assert!(ktree.contains(&node.pk));
    }

    // Ktree::can_add()

    #[test]
    fn ktree_can_add() {
        crypto_init().unwrap();
        let (pk, _) = gen_keypair();
        let mut ktree = Ktree::new(&pk);

        let node = PackedNode::new(
            "1.2.3.5:12345".parse().unwrap(),
            &gen_keypair().0
        );

        assert!(ktree.can_add(&node));
        assert!(ktree.try_add(node));
        assert!(!ktree.can_add(&node));
    }

    // Ktree::iter()

    #[test]
    fn ktree_iter() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut ktree = Ktree::new(&pk);

        // empty always returns None
        assert!(ktree.iter().next().is_none());

        for i in 0 .. 8 {
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + u16::from(i));
            let node = PackedNode::new(addr, &PublicKey([i + 1; PUBLICKEYBYTES]));
            assert!(ktree.try_add(node));
        }

        assert_eq!(ktree.iter().count(), 8);

        // iterator should produce sorted nodes
        for (i, node) in ktree.iter().enumerate() {
            assert_eq!(node.pk, PublicKey([i as u8 + 1; PUBLICKEYBYTES]));
        }
    }

    // Ktree::iter_mut()

    #[test]
    fn ktree_iter_mut() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut ktree = Ktree::new(&pk);

        // empty always returns None
        assert!(ktree.iter_mut().next().is_none());

        for i in 0 .. 8 {
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + u16::from(i));
            let node = PackedNode::new(addr, &PublicKey([i + 1; PUBLICKEYBYTES]));
            assert!(ktree.try_add(node));
        }

        assert_eq!(ktree.iter_mut().count(), 8);

        // iterator should produce sorted nodes
        for (i, node) in ktree.iter_mut().enumerate() {
            assert_eq!(node.pk, PublicKey([i as u8 + 1; PUBLICKEYBYTES]));
        }
    }

    // Ktree::is_all_discarded()

    #[tokio::test]
    async fn ktree_is_all_discarded() {
        crypto_init().unwrap();
        let (pk, _) = gen_keypair();
        let mut ktree = Ktree::new(&pk);

        let pn = PackedNode {
            pk: gen_keypair().0,
            saddr: "127.0.0.1:33445".parse().unwrap(),
        };
        assert!(ktree.try_add(pn));

        let pn = PackedNode {
            pk: gen_keypair().0,
            saddr: "127.0.0.1:12345".parse().unwrap(),
        };
        assert!(ktree.try_add(pn));

        assert!(!ktree.is_all_discarded());

        tokio::time::pause();
        tokio::time::advance(KILL_NODE_TIMEOUT + Duration::from_secs(1)).await;

        assert!(ktree.is_all_discarded());
    }
}
