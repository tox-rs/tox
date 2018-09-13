/*!
Structure for holding nodes.

Number of nodes it can contain is set during creation.

Nodes stored in `Kbucket` are in [`DhtNode`](./struct.DhtNode.html)
format.

Used in [`Ktree`](./struct.Ktree.html) for storing nodes close to given
PK; and additionally used to store nodes closest to friends.

[Spec definition](https://zetok.github.io/tox-spec#updating-k-buckets).
*/

use std::cmp::{Ord, Ordering};
use std::convert::Into;
use std::net::SocketAddr;

use toxcore::crypto_core::*;
use toxcore::dht::dht_node::*;
use toxcore::dht::packed_node::*;
use toxcore::dht::ip_port::IsGlobal;
use toxcore::dht::nodes_queue::*;
use toxcore::time::*;

/** Calculate the [`k-bucket`](./struct.Ktree.html) index of a PK compared
to "own" PK.

According to the [spec](https://zetok.github.io/tox-spec#bucket-index).

Fails (returns `None`) only if supplied keys are the same.
*/
pub fn kbucket_index(&PublicKey(ref own_pk): &PublicKey,
                     &PublicKey(ref other_pk): &PublicKey) -> Option<u8> {

    debug!(target: "KBucketIndex", "Calculating KBucketIndex for PKs.");
    trace!(target: "KBucketIndex", "With PK1: {:?}; PK2: {:?}", own_pk, other_pk);

    let xoring = own_pk.iter().zip(other_pk.iter()).map(|(x, y)| x ^ y);
    for (i, byte) in xoring.enumerate() {
        for j in 0..8 {
            if byte & (0x80 >> j) != 0 {
                return Some(i as u8 * 8 + j);
            }
        }
    }
    None  // PKs are equal
}

impl Into<DhtNode> for PackedNode {
    fn into(self) -> DhtNode {
        DhtNode::new(self)
    }
}

/// Trait for functionality related to distance between `PublicKey`s.
pub trait Distance {
    /// Check whether distance between PK1 and own PK is smaller than distance
    /// between PK2 and own PK.
    fn distance(&self, &PublicKey, &PublicKey) -> Ordering;
}

impl Distance for PublicKey {
    fn distance(&self,
                &PublicKey(ref pk1): &PublicKey,
                &PublicKey(ref pk2): &PublicKey) -> Ordering {

        trace!(target: "Distance", "Comparing distance between PKs.");
        let &PublicKey(own) = self;
        for i in 0..PUBLICKEYBYTES {
            if pk1[i] != pk2[i] {
                return Ord::cmp(&(own[i] ^ pk1[i]), &(own[i] ^ pk2[i]))
            }
        }
        Ordering::Equal
    }
}

/**
Structure for holding nodes.

Number of nodes it can contain is set during creation.

Nodes stored in `Kbucket` are in [`DhtNode`](./struct.DhtNode.html)
format.

Nodes in kbucket are sorted by closeness to the PK; closest node is the first
one, while furthest is the last one.

Used in [`Ktree`](./struct.Ktree.html) for storing nodes close to given
PK; and additionally used to store nodes closest to friends.

[Spec definition](https://zetok.github.io/tox-spec#updating-k-buckets).

[Kademlia whitepaper](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf).
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kbucket {
    /// Amount of nodes it can hold.
    pub capacity: u8,
    /// Nodes that kbucket has, sorted by distance to PK.
    pub nodes: Vec<DhtNode>,
}

/// Default number of nodes that kbucket can hold.
pub const KBUCKET_DEFAULT_SIZE: u8 = 8;

impl Kbucket {
    /** Create a new `Kbucket` to store nodes close to the `PublicKey`.

    Can hold up to `capacity` nodes.
    */
    pub fn new(capacity: u8) -> Self {
        trace!("Creating a new Kbucket with capacity: {}", capacity);
        Kbucket {
            capacity,
            nodes: Vec::with_capacity(capacity as usize),
        }
    }

    fn find(&self, base_pk: &PublicKey, pk: &PublicKey) -> Option<usize> {
        self.nodes.binary_search_by(|n| base_pk.distance(&n.pk, pk)).ok()
    }

    /// Get reference to a `DhtNode` by it's `PublicKey`.
    pub fn get_node(&self, base_pk: &PublicKey, pk: &PublicKey) -> Option<&DhtNode> {
        self.find(base_pk, pk)
            .map(move |node_index| &self.nodes[node_index])
    }

    /// Get mutable reference to a `DhtNode` by it's `PublicKey`.
    pub fn get_node_mut(&mut self, base_pk: &PublicKey, pk: &PublicKey) -> Option<&mut DhtNode> {
        self.find(base_pk, pk)
            .map(move |node_index| &mut self.nodes[node_index])
    }

    /**
    Try to add [`PackedNode`] to the kbucket.

    - If the [`PackedNode`] with given `PublicKey` is already in the `Kbucket`,
      the [`DhtNode`] is updated (since its `SocketAddr` can differ).
    - If kbucket is not full, node is appended.
    - If kbucket is full and `evict` is `true`, node's closeness is compared to
      nodes already in kbucket, and if it's closer than some node, it prepends
      that node, and last node is removed from the list.
    - If the node being added is farther away than the nodes in the kbucket or
      `evict` is `false`, it isn't added and `false` is returned.

    Note that you must pass the same `base_pk` each call or the internal
    state will be undefined.

    Returns `true` if node was added or updated, `false` otherwise.

    Note that the result of this function doesn't always match the result of
    `can_add` function. If node is already in the [`Kbucket`], `can_add` will
    return `true` only when it has different address or is in a bad state.

    [`DhtNode`]: ./struct.DhtNode.html
    [`PackedNode`]: ../packed_node/struct.PackedNode.html
    */
    pub fn try_add(&mut self, base_pk: &PublicKey, new_node: &PackedNode, evict: bool) -> bool {
        debug!(target: "Kbucket", "Trying to add PackedNode.");
        trace!(target: "Kbucket", "With kbucket: {:?}; PK: {:?} and new node: {:?}",
            self, base_pk, new_node);

        match self.nodes.binary_search_by(|n| base_pk.distance(&n.pk, &new_node.pk)) {
            Ok(index) => {
                debug!(target: "Kbucket",
                    "Updated: the node was already in the kbucket.");
                match new_node.saddr {
                    SocketAddr::V4(sock_v4) => {
                        self.nodes[index].assoc4.saddr = Some(sock_v4);
                        self.nodes[index].assoc4.last_resp_time = Some(clock_now());
                    },
                    SocketAddr::V6(sock_v6) => {
                        self.nodes[index].assoc6.saddr = Some(sock_v6);
                        self.nodes[index].assoc6.last_resp_time = Some(clock_now());
                    }
                }
                true
            },
            Err(index) if !evict || index == self.nodes.len() => {
                // index is pointing past the end
                // we are not going to evict the farthest node or the current
                // node is the farthest one
                if self.is_full() {
                    let index = self.nodes.iter().rposition(|n| n.is_discarded()).or_else(||
                        self.nodes.iter().rposition(|n| n.is_bad())
                    );
                    match index {
                        Some(index) => {
                            debug!(target: "Kbucket",
                                "No free space left in the kbucket, the last bad node removed.");
                            // replace the farthest bad node
                            self.nodes.remove(index);
                            self.nodes.push((*new_node).into());
                            true
                        },
                        None => {
                            debug!(target: "Kbucket",
                                "Node can't be added to the kbucket.");
                            false
                        },
                    }
                } else {
                    // distance to the PK was bigger than the other keys, but
                    // there's still free space in the kbucket for a node
                    debug!(target: "Kbucket",
                        "Node inserted inside the kbucket.");
                    self.nodes.insert(index, (*new_node).into());
                    true
                }
            },
            Err(index) => {
                // index is pointing inside the list
                // we are going to evict the farthest node if the kbucket is full
                if self.is_full() {
                    debug!(target: "Kbucket",
                        "No free space left in the kbucket, the last node removed.");
                    self.nodes.pop();
                }
                debug!(target: "Kbucket", "Node inserted inside the kbucket.");
                self.nodes.insert(index, (*new_node).into());
                true
            },
        }
    }

    /** Remove [`DhtNode`](./struct.DhtNode.html) with given PK from the
    `Kbucket`.

    Note that you must pass the same `base_pk` each call or the internal
    state will be undefined. Also `base_pk` must be equal to `base_pk` you added
    a node with. Normally you don't call this function on your own but Ktree does.

    If there's no `DhtNode` with given PK, nothing is being done.
    */
    pub fn remove(&mut self, base_pk: &PublicKey, node_pk: &PublicKey) -> Option<DhtNode> {
        trace!(target: "Kbucket", "Removing DhtNode with PK: {:?}", node_pk);
        match self.nodes.binary_search_by(|n| base_pk.distance(&n.pk, node_pk)) {
            Ok(index) => Some(self.nodes.remove(index)),
            Err(_) => {
                trace!("No DhtNode to remove with PK: {:?}", node_pk);
                None
            }
        }
    }

    /// Check if node with given PK is in the `Kbucket`.
    pub fn contains(&self, base_pk: &PublicKey, pk: &PublicKey) -> bool {
        self.nodes.binary_search_by(|n| base_pk.distance(&n.pk, pk)).is_ok()
    }

    /// Get the capacity of the Kbucket.
    pub fn capacity(&self) -> usize {
        self.capacity as usize
    }

    /** Check if `Kbucket` is empty.

    Returns `true` if there are no nodes in the `Kbucket`, `false`
    otherwise.
    */
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /** Check if `Kbucket` is full.

    Returns `true` if there is no free space in the `Kbucket`, `false`
    otherwise.
    */
    pub fn is_full(&self) -> bool {
        self.nodes.len() == self.capacity()
    }

    /**
    Check whether a [`PackedNode`] can be added to the `Kbucket`.

    Returns `true` in one of the next conditions:
      - [`Kbucket`] where node could be placed is not full and node is not
        already in the [`Kbucket`]
      - [`Kbucket`] where node could be placed is full but node can evict a
        farther node
      - Node is already in the [`Kbucket`] but has different address or in a bad
        state

    Otherwise `false` is returned.

    Note that the result of this function doesn't always match the result of
    `try_add` function. `try_add` will always return `true` when node is already
    in the [`Kbucket`].

    [`Kbucket`]: ./struct.Kbucket.html
    [`PackedNode`]: ./struct.PackedNode.html
    */
    pub fn can_add(&self, base_pk: &PublicKey, new_node: &PackedNode, evict: bool) -> bool {
        match self.nodes.binary_search_by(|n| base_pk.distance(&n.pk, &new_node.pk)) {
            Ok(index) =>
                // if node is bad then we'd want to update it's address
                self.nodes[index].is_bad() ||
                    self.nodes[index].assoc4.saddr.map(SocketAddr::V4) != Some(new_node.saddr) &&
                        self.nodes[index].assoc6.saddr.map(SocketAddr::V6) != Some(new_node.saddr),
            Err(index) if !evict || index == self.nodes.len() =>
                // can't find node in the kbucket
                // we are not going to evict the farthest node or the current
                // node is the farthest one
                !self.is_full() || self.nodes.iter().any(|n| n.is_bad()),
            Err(_index) =>
                // can't find node in the kbucket
                // we are going to evict the farthest node if the kbucket is full
                true,
        }
    }

    /// Create iterator over [`DhtNode`](./struct.DhtNode.html)s in `Ktree`.
    /// Nodes that this iterator produces are sorted by distance to a base
    /// `PublicKey` (in ascending order).
    pub fn iter(&self) -> impl Iterator<Item = &DhtNode> {
        self.nodes.iter()
    }

    /// Create mutable iterator over [`DhtNode`](./struct.DhtNode.html)s in
    /// `Ktree`. Nodes that this iterator produces are sorted by distance to a
    /// base `PublicKey` (in ascending order).
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut DhtNode> {
        self.nodes.iter_mut()
    }
}

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
    pub kbuckets: Vec<Kbucket>,
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

    /// Find indices of `DhtNode` by it's `PublicKey`.
    #[cfg(test)]
    fn find(&self, pk: &PublicKey) -> Option<(usize, usize)> {
        self.kbucket_index(pk).and_then(|index|
            self.kbuckets[index]
                .find(&self.pk, pk)
                .map(|node_index| (index, node_index))
        )
    }

    /// Get reference to a `DhtNode` by it's `PublicKey`.
    pub fn get_node(&self, pk: &PublicKey) -> Option<&DhtNode> {
        self.kbucket_index(pk).and_then(|index|
            self.kbuckets[index]
                .find(&self.pk, pk)
                .map(|node_index| &self.kbuckets[index].nodes[node_index])
        )
    }

    /// Get mutable reference to a `DhtNode` by it's `PublicKey`.
    pub fn get_node_mut(&mut self, pk: &PublicKey) -> Option<&mut DhtNode> {
        self.kbucket_index(pk).and_then(|index|
            self.kbuckets[index]
                .find(&self.pk, pk)
                .map(move |node_index| &mut self.kbuckets[index].nodes[node_index])
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
    pub fn try_add(&mut self, node: &PackedNode) -> bool {
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

    Returns less than 4 nodes only if `Ktree` contains less than 4
    nodes.

    It should not contain LAN ip node if the request is from global ip.
    */
    pub fn get_closest(&self, pk: &PublicKey, only_global: bool) -> NodesQueue {
        debug!(target: "Ktree", "Getting closest nodes.");
        trace!(target: "Ktree", "With PK: {:?} and self: {:?}", pk, self);

        let mut queue = NodesQueue::new(4);
        for node in self.iter().filter(|node| !node.is_bad()) {
            if let Some(pn) = node.to_packed_node() {
                if !only_global || IsGlobal::is_global(&pn.saddr.ip()) {
                    queue.try_add(pk, &pn);
                }
            }
        }
        trace!("Returning nodes: {:?}", queue);
        queue
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
    pub fn iter(&self) -> impl Iterator<Item = &DhtNode> {
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

    use std::net::{
        Ipv4Addr,
        SocketAddr,
        SocketAddrV4,
    };
    use std::time::{Duration, Instant};

    use tokio_executor;
    use tokio_timer::clock::*;

    use toxcore::time::ConstNow;

    // PublicKey::distance()

    #[test]
    fn public_key_distance() {
        let pk_0 = PublicKey([0; PUBLICKEYBYTES]);
        let pk_1 = PublicKey([1; PUBLICKEYBYTES]);
        let pk_2 = PublicKey([2; PUBLICKEYBYTES]);
        let pk_ff = PublicKey([0xff; PUBLICKEYBYTES]);
        let pk_fe = PublicKey([0xfe; PUBLICKEYBYTES]);

        assert_eq!(Ordering::Less, pk_0.distance(&pk_1, &pk_2));
        assert_eq!(Ordering::Equal, pk_2.distance(&pk_2, &pk_2));
        assert_eq!(Ordering::Less, pk_2.distance(&pk_0, &pk_1));
        assert_eq!(Ordering::Greater, pk_2.distance(&pk_ff, &pk_fe));
        assert_eq!(Ordering::Greater, pk_2.distance(&pk_ff, &pk_fe));
        assert_eq!(Ordering::Less, pk_fe.distance(&pk_ff, &pk_2));
    }


    // kbucket_index()

    #[test]
    fn kbucket_index_test() {
        let pk1 = PublicKey([0b10_10_10_10; PUBLICKEYBYTES]);
        let pk2 = PublicKey([0; PUBLICKEYBYTES]);
        let pk3 = PublicKey([0b00_10_10_10; PUBLICKEYBYTES]);
        assert_eq!(None, kbucket_index(&pk1, &pk1));
        assert_eq!(Some(0), kbucket_index(&pk1, &pk2));
        assert_eq!(Some(2), kbucket_index(&pk2, &pk3));
    }


    // Kbucket::

    // Kbucket::try_add()

    #[test]
    fn kbucket_try_add() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut kbucket = Kbucket::new(KBUCKET_DEFAULT_SIZE);

        for i in 0 .. 8 {
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + i as u16);
            let node = PackedNode::new(addr, &PublicKey([i + 2; PUBLICKEYBYTES]));
            assert!(kbucket.try_add(&pk, &node, /* evict */ false));
        }

        let closer_node = PackedNode::new(
            "1.2.3.5:12345".parse().unwrap(),
            &PublicKey([1; PUBLICKEYBYTES])
        );
        let farther_node = PackedNode::new(
            "1.2.3.5:12346".parse().unwrap(),
            &PublicKey([10; PUBLICKEYBYTES])
        );
        let existing_node = PackedNode::new(
            "1.2.3.5:12347".parse().unwrap(),
            &PublicKey([2; PUBLICKEYBYTES])
        );

        // can't add a new farther node
        assert!(!kbucket.try_add(&pk, &farther_node, /* evict */ false));
        // can't add a new farther node with eviction
        assert!(!kbucket.try_add(&pk, &farther_node, /* evict */ true));
        // can't add a new closer node
        assert!(!kbucket.try_add(&pk, &closer_node, /* evict */ false));
        // can add a new closer node with eviction
        assert!(kbucket.try_add(&pk, &closer_node, /* evict */ true));
        // can update a node
        assert!(kbucket.try_add(&pk, &existing_node, /* evict */ false));
    }

    #[test]
    fn kbucket_try_add_should_replace_bad_nodes() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut kbucket = Kbucket::new(1);

        let node_1 = PackedNode::new(
            "1.2.3.4:12345".parse().unwrap(),
            &PublicKey([1; PUBLICKEYBYTES])
        );
        let node_2 = PackedNode::new(
            "1.2.3.4:12346".parse().unwrap(),
            &PublicKey([2; PUBLICKEYBYTES])
        );

        assert!(kbucket.try_add(&pk, &node_2, /* evict */ false));
        assert!(!kbucket.try_add(&pk, &node_1, /* evict */ false));

        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(
            Instant::now() + Duration::from_secs(BAD_NODE_TIMEOUT + 1)
        ));

        // replacing bad node
        with_default(&clock, &mut enter, |_| {
            assert!(kbucket.try_add(&pk, &node_1, /* evict */ false));
        });
    }

    #[test]
    fn kbucket_try_add_evict_should_replace_bad_nodes() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut kbucket = Kbucket::new(1);

        let node_1 = PackedNode::new(
            "1.2.3.4:12345".parse().unwrap(),
            &PublicKey([1; PUBLICKEYBYTES])
        );
        let node_2 = PackedNode::new(
            "1.2.3.4:12346".parse().unwrap(),
            &PublicKey([2; PUBLICKEYBYTES])
        );

        assert!(kbucket.try_add(&pk, &node_1, /* evict */ true));
        assert!(!kbucket.try_add(&pk, &node_2, /* evict */ true));

        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(
            Instant::now() + Duration::from_secs(BAD_NODE_TIMEOUT + 1)
        ));

        // replacing bad node
        with_default(&clock, &mut enter, |_| {
            assert!(kbucket.try_add(&pk, &node_2, /* evict */ true));
        });
    }

    // Kbucket::remove()

    #[test]
    fn kbucket_remove() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut kbucket = Kbucket::new(KBUCKET_DEFAULT_SIZE);

        let node = PackedNode::new(
            "1.2.3.4:12345".parse().unwrap(),
            &PublicKey([1; PUBLICKEYBYTES])
        );

        // "removing" non-existent node
        assert!(kbucket.remove(&pk, &node.pk).is_none());
        assert!(kbucket.is_empty());

        assert!(kbucket.try_add(&pk, &node, /* evict */ true));

        assert!(!kbucket.is_empty());

        assert!(kbucket.remove(&pk, &node.pk).is_some());

        assert!(kbucket.is_empty());
    }

    // Kbucket::is_empty()

    #[test]
    fn kbucket_is_empty() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut kbucket = Kbucket::new(KBUCKET_DEFAULT_SIZE);

        assert!(kbucket.is_empty());

        let node = PackedNode::new(
            "1.2.3.4:12345".parse().unwrap(),
            &PublicKey([1; PUBLICKEYBYTES])
        );

        assert!(kbucket.try_add(&pk, &node, /* evict */ true));

        assert!(!kbucket.is_empty());
    }

    // Kbucket::get_node()

    #[test]
    fn kbucket_get_node() {
        let (pk, _) = gen_keypair();
        let mut kbucket = Kbucket::new(KBUCKET_DEFAULT_SIZE);

        let node_pk = gen_keypair().0;

        let pn = PackedNode {
            pk: node_pk,
            saddr: "127.0.0.1:33445".parse().unwrap(),
        };

        assert!(kbucket.try_add(&pk, &pn, true));
        assert!(kbucket.get_node(&pk, &node_pk).is_some());
    }

    // Kbucket::get_node_mut()

    #[test]
    fn kbucket_get_node_mut() {
        let (pk, _) = gen_keypair();
        let mut kbucket = Kbucket::new(KBUCKET_DEFAULT_SIZE);

        let node_pk = gen_keypair().0;

        let pn = PackedNode {
            pk: node_pk,
            saddr: "127.0.0.1:33445".parse().unwrap(),
        };

        assert!(kbucket.try_add(&pk, &pn, true));
        assert!(kbucket.get_node_mut(&pk, &node_pk).is_some());
    }


    // Ktree::

    // Ktree::new()

    #[test]
    fn ktree_new() {
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
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + i as u16);
            let node = PackedNode::new(addr, &pk);
            assert!(ktree.try_add(&node));
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
        assert!(!ktree.try_add(&node));

        // but nodes still can be added to other kbuckets
        let pk = PublicKey([1; PUBLICKEYBYTES]);
        let node = PackedNode::new(
            "1.2.3.5:12346".parse().unwrap(),
            &pk
        );
        assert!(ktree.try_add(&node));
    }

    #[test]
    fn ktree_try_add_self() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut ktree = Ktree::new(&pk);

        let node = PackedNode::new(
            "1.2.3.5:12345".parse().unwrap(),
            &pk
        );

        assert!(!ktree.try_add(&node));
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

        assert!(ktree.try_add(&node));

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
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + i as u16);
            PackedNode::new(addr, &PublicKey([i + 1; PUBLICKEYBYTES]))
        }

        for i in 0 .. 8 {
            assert!(ktree.try_add(&node_by_idx(i)));
        }

        let closest: Vec<_> = ktree.get_closest(&PublicKey([0; PUBLICKEYBYTES]), true).into();
        let should_be = (0 .. 4).map(node_by_idx).collect::<Vec<_>>();
        assert_eq!(closest, should_be);

        let closest: Vec<_> = ktree.get_closest(&PublicKey([255; PUBLICKEYBYTES]), true).into();
        let should_be = (4 .. 8).rev().map(node_by_idx).collect::<Vec<_>>();
        assert_eq!(closest, should_be);
    }

    // Ktree::position()

    fn position_test_data() -> (Ktree, PackedNode, PackedNode, PackedNode) {
        let mut pk_bytes = [3; PUBLICKEYBYTES];

        pk_bytes[0] = 1;
        let base_pk = PublicKey(pk_bytes);

        let ktree = Ktree::new(&base_pk);

        let addr = Ipv4Addr::new(0, 0, 0, 0);
        let saddr = SocketAddrV4::new(addr, 0);

        pk_bytes[5] = 1;
        let pk1 = PublicKey(pk_bytes);
        let n1 = PackedNode::new(SocketAddr::V4(saddr), &pk1);

        pk_bytes[10] = 2;
        let pk2 = PublicKey(pk_bytes);
        let n2 = PackedNode::new(SocketAddr::V4(saddr), &pk2);

        pk_bytes[14] = 4;
        let pk3 = PublicKey(pk_bytes);
        let n3 = PackedNode::new(SocketAddr::V4(saddr), &pk3);

        assert!(pk1 > pk2);
        assert!(pk2 < pk3);
        assert!(pk1 > pk3);

        (ktree, n1, n2, n3)
    }

    // Check that insertion order does not affect
    // the result order in the ktree

    #[test]
    fn ktree_position_straight_insertion() {
        let (mut ktree, n1, n2, n3) = position_test_data();
        // insert order: n1 n2 n3 maps to position
        // n1 => 0, n2 => 1, n3 => 2
        ktree.try_add(&n1);
        ktree.try_add(&n2);
        ktree.try_add(&n3);
        assert_eq!(ktree.find(&n1.pk), Some((46, 0)));
        assert_eq!(ktree.find(&n2.pk), Some((46, 1)));
        assert_eq!(ktree.find(&n3.pk), Some((46, 2)));
    }

    #[test]
    fn ktree_position_reverse_insertion() {
        let (mut ktree, n1, n2, n3) = position_test_data();
        // insert order: n3 n2 n1 maps to position
        // n1 => 0, n2 => 1, n3 => 2
        ktree.try_add(&n3);
        ktree.try_add(&n2);
        ktree.try_add(&n1);
        assert_eq!(ktree.find(&n1.pk), Some((46, 0)));
        assert_eq!(ktree.find(&n2.pk), Some((46, 1)));
        assert_eq!(ktree.find(&n3.pk), Some((46, 2)));
    }

    // Check that removing order does not affect
    // the order of nodes inside

    #[test]
    fn ktree_position_remove_first() {
        let (mut ktree, n1, n2, n3) = position_test_data();
        // prepare ktree
        ktree.try_add(&n1); // => 0
        ktree.try_add(&n2); // => 1
        ktree.try_add(&n3); // => 2
        // test removing from the beginning (n1 => 0)
        ktree.remove(&n1.pk);
        assert_eq!(ktree.find(&n1.pk), None);
        assert_eq!(ktree.find(&n2.pk), Some((46, 0)));
        assert_eq!(ktree.find(&n3.pk), Some((46, 1)));
    }

    #[test]
    fn ktree_position_remove_second() {
        let (mut ktree, n1, n2, n3) = position_test_data();
        // prepare ktree
        ktree.try_add(&n1); // => 0
        ktree.try_add(&n2); // => 1
        ktree.try_add(&n3); // => 2
        // test removing from the middle (n2 => 1)
        ktree.remove(&n2.pk);
        assert_eq!(ktree.find(&n1.pk), Some((46, 0)));
        assert_eq!(ktree.find(&n2.pk), None);
        assert_eq!(ktree.find(&n3.pk), Some((46, 1)));
    }

    #[test]
    fn ktree_position_remove_third() {
        let (mut ktree, n1, n2, n3) = position_test_data();
        // prepare ktree
        ktree.try_add(&n1); // => 0
        ktree.try_add(&n2); // => 1
        ktree.try_add(&n3); // => 2
        // test removing from the end (n3 => 2)
        ktree.remove(&n3.pk);
        assert_eq!(ktree.find(&n1.pk), Some((46, 0)));
        assert_eq!(ktree.find(&n2.pk), Some((46, 1)));
        assert_eq!(ktree.find(&n3.pk), None);
    }

    // Ktree::contains()

    #[test]
    fn ktree_contains() {
        let (pk, _) = gen_keypair();
        let mut ktree = Ktree::new(&pk);

        assert!(!ktree.contains(&pk));

        let node = PackedNode::new(
            "1.2.3.5:12345".parse().unwrap(),
            &gen_keypair().0
        );

        assert!(!ktree.contains(&node.pk));
        assert!(ktree.try_add(&node));
        assert!(ktree.contains(&node.pk));
    }

    // Ktree::can_add()

    #[test]
    fn ktree_can_add() {
        let (pk, _) = gen_keypair();
        let mut ktree = Ktree::new(&pk);

        let node = PackedNode::new(
            "1.2.3.5:12345".parse().unwrap(),
            &gen_keypair().0
        );

        assert!(ktree.can_add(&node));
        assert!(ktree.try_add(&node));
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
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + i as u16);
            let node = PackedNode::new(addr, &PublicKey([i + 1; PUBLICKEYBYTES]));
            assert!(ktree.try_add(&node));
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
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + i as u16);
            let node = PackedNode::new(addr, &PublicKey([i + 1; PUBLICKEYBYTES]));
            assert!(ktree.try_add(&node));
        }

        assert_eq!(ktree.iter_mut().count(), 8);

        // iterator should produce sorted nodes
        for (i, node) in ktree.iter_mut().enumerate() {
            assert_eq!(node.pk, PublicKey([i as u8 + 1; PUBLICKEYBYTES]));
        }
    }

    // Ktree::is_all_discarded()

    #[test]
    fn ktree_is_all_discarded() {
        let (pk, _) = gen_keypair();
        let mut ktree = Ktree::new(&pk);

        let pn = PackedNode {
            pk: gen_keypair().0,
            saddr: "127.0.0.1:33445".parse().unwrap(),
        };
        assert!(ktree.try_add(&pn));

        let pn = PackedNode {
            pk: gen_keypair().0,
            saddr: "127.0.0.1:12345".parse().unwrap(),
        };
        assert!(ktree.try_add(&pn));

        assert!(!ktree.is_all_discarded());

        let time = Instant::now() + Duration::from_secs(KILL_NODE_TIMEOUT + 1);

        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(time));

        with_default(&clock, &mut enter, |_| {
            assert!(ktree.is_all_discarded());
        });
    }
}
