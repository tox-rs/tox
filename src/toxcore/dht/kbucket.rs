/*!
Structure for holding nodes.

Number of nodes it can contain is set during creation.

Nodes stored in `Kbucket` are in [`DhtNode`](./struct.DhtNode.html)
format.

Used in [`Ktree`](../ktree/struct.Ktree.html) for storing nodes close to given
PK; and additionally used to store nodes closest to friends.

[Spec definition](https://zetok.github.io/tox-spec#updating-k-buckets).
*/

use std::cmp::{Ord, Ordering};
use std::convert::{From, Into};

use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packed_node::*;

/** Calculate the [`k-tree`](../ktree/struct.Ktree.html) index of a PK compared
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

/// Trait for functionality related to distance between `PublicKey`s.
pub trait Distance {
    /// Check whether distance between PK1 and own PK is smaller than distance
    /// between PK2 and own PK.
    fn distance(&self, pk1: &PublicKey, pk2: &PublicKey) -> Ordering;
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

/// Anything that has `PublicKey`.
pub trait HasPK {
    /// `PublicKey`.
    fn pk(&self) -> PublicKey;
}

impl HasPK for PackedNode {
    fn pk(&self) -> PublicKey {
        self.pk
    }
}

/// Node that can be stored in a `Kbucket`.
pub trait KbucketNode : Sized + HasPK {
    /// The type of nodes that can be added to a `Kbucket`.
    type NewNode: HasPK;
    /// The type of nodes that can be checked if they can be added to a
    /// `Kbucket`.
    type CheckNode: HasPK;

    /// Check if the node can be updated with a new one.
    fn is_outdated(&self, other: &Self::CheckNode) -> bool;
    /// Update the existing node with a new one.
    fn update(&mut self, other: &Self::NewNode);
    /// Check if the node can be evicted.
    fn is_evictable(&self) -> bool;
    /// Find the index of a node that should be evicted in case if `Kbucket` is
    /// full. It must return `Some` if and only if nodes list contains at least
    /// one evictable node.
    fn eviction_index(nodes: &[Self]) -> Option<usize> {
        nodes.iter().rposition(|node| node.is_evictable())
    }
}

impl KbucketNode for PackedNode {
    type NewNode = PackedNode;
    type CheckNode = PackedNode;

    fn is_outdated(&self, other: &PackedNode) -> bool {
        self.saddr != other.saddr
    }
    fn update(&mut self, other: &PackedNode) {
        self.saddr = other.saddr;
    }
    fn is_evictable(&self) -> bool {
        false
    }
    fn eviction_index(_nodes: &[Self]) -> Option<usize> {
        None
    }
}

/**
Structure for holding nodes.

Number of nodes it can contain is set during creation.

Nodes stored in `Kbucket` are in [`KbucketNode`](./struct.KbucketNode.html)
format.

Nodes in kbucket are sorted by closeness to the PK; closest node is the first
one, while furthest is the last one.

Used in [`Ktree`](../ktree/struct.Ktree.html) for storing nodes close to given
PK; and additionally used to store nodes closest to friends.

[Spec definition](https://zetok.github.io/tox-spec#updating-k-buckets).

[Kademlia whitepaper](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf).
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kbucket<Node> {
    /// Amount of nodes it can hold.
    pub capacity: u8,
    /// Nodes that kbucket has, sorted by distance to PK.
    pub nodes: Vec<Node>,
}

impl<Node> Into<Vec<Node>> for Kbucket<Node> {
    fn into(self) -> Vec<Node> {
        self.nodes
    }
}

/// Default number of nodes that kbucket can hold.
pub const KBUCKET_DEFAULT_SIZE: u8 = 8;

impl<NewNode, CheckNode, Node> Kbucket<Node>
where
    NewNode: HasPK,
    CheckNode: HasPK,
    Node: KbucketNode<NewNode = NewNode, CheckNode = CheckNode> + From<NewNode>
{
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
        self.nodes.binary_search_by(|n| base_pk.distance(&n.pk(), pk)).ok()
    }

    /// Get reference to a `KbucketNode` by it's `PublicKey`.
    pub fn get_node(&self, base_pk: &PublicKey, pk: &PublicKey) -> Option<&Node> {
        self.find(base_pk, pk)
            .map(move |node_index| &self.nodes[node_index])
    }

    /// Get mutable reference to a `KbucketNode` by it's `PublicKey`.
    pub fn get_node_mut(&mut self, base_pk: &PublicKey, pk: &PublicKey) -> Option<&mut Node> {
        self.find(base_pk, pk)
            .map(move |node_index| &mut self.nodes[node_index])
    }

    /**
    Try to add [`PackedNode`] to the kbucket.

    - If the [`PackedNode`] with given `PublicKey` is already in the `Kbucket`,
      the [`KbucketNode`] is updated (since its `SocketAddr` can differ).
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

    [`KbucketNode`]: ./struct.KbucketNode.html
    [`PackedNode`]: ../packed_node/struct.PackedNode.html
    */
    pub fn try_add(&mut self, base_pk: &PublicKey, new_node: NewNode, evict: bool) -> bool {
        trace!(target: "Kbucket", "Trying to add PackedNode: {:?}.", new_node.pk());

        match self.nodes.binary_search_by(|n| base_pk.distance(&n.pk(), &new_node.pk())) {
            Ok(index) => {
                debug!(target: "Kbucket",
                    "Updated: the node was already in the kbucket.");
                self.nodes[index].update(&new_node);
                true
            },
            Err(index) if !evict || index == self.nodes.len() => {
                // index is pointing past the end
                // we are not going to evict the farthest node or the current
                // node is the farthest one
                if self.is_full() {
                    match Node::eviction_index(&self.nodes) {
                        Some(index) => {
                            debug!(target: "Kbucket",
                                "No free space left in the kbucket, the last bad node removed.");
                            // replace the farthest bad node
                            self.nodes.remove(index);
                            self.nodes.push(new_node.into());
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
                    self.nodes.insert(index, new_node.into());
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
                self.nodes.insert(index, new_node.into());
                true
            },
        }
    }

    /** Remove [`KbucketNode`](./struct.KbucketNode.html) with given PK from the
    `Kbucket`.

    Note that you must pass the same `base_pk` each call or the internal
    state will be undefined. Also `base_pk` must be equal to `base_pk` you added
    a node with. Normally you don't call this function on your own but Ktree does.

    If there's no `KbucketNode` with given PK, nothing is being done.
    */
    pub fn remove(&mut self, base_pk: &PublicKey, node_pk: &PublicKey) -> Option<Node> {
        trace!(target: "Kbucket", "Removing KbucketNode with PK: {:?}", node_pk);
        match self.nodes.binary_search_by(|n| base_pk.distance(&n.pk(), node_pk)) {
            Ok(index) => Some(self.nodes.remove(index)),
            Err(_) => {
                trace!("No KbucketNode to remove with PK: {:?}", node_pk);
                None
            }
        }
    }

    /// Check if node with given PK is in the `Kbucket`.
    pub fn contains(&self, base_pk: &PublicKey, pk: &PublicKey) -> bool {
        self.nodes.binary_search_by(|n| base_pk.distance(&n.pk(), pk)).is_ok()
    }

    /// Number of nodes this `Kbucket` contains.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Get the capacity of the `Kbucket`.
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
    pub fn can_add(&self, base_pk: &PublicKey, new_node: &CheckNode, evict: bool) -> bool {
        match self.nodes.binary_search_by(|n| base_pk.distance(&n.pk(), &new_node.pk())) {
            Ok(index) =>
                // if node is bad then we'd want to update it's address
                self.nodes[index].is_evictable() || self.nodes[index].is_outdated(new_node),
            Err(index) if !evict || index == self.nodes.len() =>
                // can't find node in the kbucket
                // we are not going to evict the farthest node or the current
                // node is the farthest one
                !self.is_full() || self.nodes.iter().any(|n| n.is_evictable()),
            Err(_index) =>
                // can't find node in the kbucket
                // we are going to evict the farthest node if the kbucket is full
                true,
        }
    }

    /// Create iterator over [`KbucketNode`](./struct.KbucketNode.html)s in
    /// `Ktree`. Nodes that this iterator produces are sorted by distance to a
    /// base `PublicKey` (in ascending order).
    pub fn iter(&self) -> impl Iterator<Item = &Node> + Clone {
        self.nodes.iter()
    }

    /// Create mutable iterator over [`KbucketNode`](./struct.KbucketNode.html)s
    /// in `Ktree`. Nodes that this iterator produces are sorted by distance to
    /// a base `PublicKey` (in ascending order).
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Node> {
        self.nodes.iter_mut()
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
    use std::time::Duration;

    use crate::toxcore::dht::dht_node::*;

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

    #[test]
    fn kbucket_index_test() {
        let pk1 = PublicKey([0b10_10_10_10; PUBLICKEYBYTES]);
        let pk2 = PublicKey([0; PUBLICKEYBYTES]);
        let pk3 = PublicKey([0b00_10_10_10; PUBLICKEYBYTES]);
        assert_eq!(None, kbucket_index(&pk1, &pk1));
        assert_eq!(Some(0), kbucket_index(&pk1, &pk2));
        assert_eq!(Some(2), kbucket_index(&pk2, &pk3));
    }

    #[test]
    fn kbucket_try_add() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut kbucket = Kbucket::<DhtNode>::new(KBUCKET_DEFAULT_SIZE);

        for i in 0 .. 8 {
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + u16::from(i));
            let node = PackedNode::new(addr, &PublicKey([i + 2; PUBLICKEYBYTES]));
            assert!(kbucket.try_add(&pk, node, /* evict */ false));
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
        assert!(!kbucket.try_add(&pk, farther_node, /* evict */ false));
        // can't add a new farther node with eviction
        assert!(!kbucket.try_add(&pk, farther_node, /* evict */ true));
        // can't add a new closer node
        assert!(!kbucket.try_add(&pk, closer_node, /* evict */ false));
        // can add a new closer node with eviction
        assert!(kbucket.try_add(&pk, closer_node, /* evict */ true));
        // can update a node
        assert!(kbucket.try_add(&pk, existing_node, /* evict */ false));
    }

    #[tokio::test]
    async fn kbucket_try_add_should_replace_bad_nodes() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut kbucket = Kbucket::<DhtNode>::new(1);

        let node_1 = PackedNode::new(
            "1.2.3.4:12345".parse().unwrap(),
            &PublicKey([1; PUBLICKEYBYTES])
        );
        let node_2 = PackedNode::new(
            "1.2.3.4:12346".parse().unwrap(),
            &PublicKey([2; PUBLICKEYBYTES])
        );

        assert!(kbucket.try_add(&pk, node_2, /* evict */ false));
        assert!(!kbucket.try_add(&pk, node_1, /* evict */ false));

        tokio::time::pause();
        tokio::time::advance(BAD_NODE_TIMEOUT + Duration::from_secs(1)).await;

        // replacing bad node
        assert!(kbucket.try_add(&pk, node_1, /* evict */ false));
    }

    #[tokio::test]
    async fn kbucket_try_add_evict_should_replace_bad_nodes() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut kbucket = Kbucket::<DhtNode>::new(1);

        let node_1 = PackedNode::new(
            "1.2.3.4:12345".parse().unwrap(),
            &PublicKey([1; PUBLICKEYBYTES])
        );
        let node_2 = PackedNode::new(
            "1.2.3.4:12346".parse().unwrap(),
            &PublicKey([2; PUBLICKEYBYTES])
        );

        assert!(kbucket.try_add(&pk, node_1, /* evict */ true));
        assert!(!kbucket.try_add(&pk, node_2, /* evict */ true));

        tokio::time::pause();
        tokio::time::advance(BAD_NODE_TIMEOUT + Duration::from_secs(1)).await;

        // replacing bad node
        assert!(kbucket.try_add(&pk, node_2, /* evict */ true));
    }

    #[test]
    fn kbucket_remove() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut kbucket = Kbucket::<DhtNode>::new(KBUCKET_DEFAULT_SIZE);

        let node = PackedNode::new(
            "1.2.3.4:12345".parse().unwrap(),
            &PublicKey([1; PUBLICKEYBYTES])
        );

        // "removing" non-existent node
        assert!(kbucket.remove(&pk, &node.pk).is_none());
        assert!(kbucket.is_empty());

        assert!(kbucket.try_add(&pk, node, /* evict */ true));

        assert!(!kbucket.is_empty());

        assert!(kbucket.remove(&pk, &node.pk).is_some());

        assert!(kbucket.is_empty());
    }

    #[test]
    fn kbucket_is_empty() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut kbucket = Kbucket::<DhtNode>::new(KBUCKET_DEFAULT_SIZE);

        assert!(kbucket.is_empty());

        let node = PackedNode::new(
            "1.2.3.4:12345".parse().unwrap(),
            &PublicKey([1; PUBLICKEYBYTES])
        );

        assert!(kbucket.try_add(&pk, node, /* evict */ true));

        assert!(!kbucket.is_empty());
    }

    #[test]
    fn kbucket_get_node() {
        crypto_init().unwrap();
        let (pk, _) = gen_keypair();
        let mut kbucket = Kbucket::<DhtNode>::new(KBUCKET_DEFAULT_SIZE);

        let node_pk = gen_keypair().0;

        let pn = PackedNode {
            pk: node_pk,
            saddr: "127.0.0.1:33445".parse().unwrap(),
        };

        assert!(kbucket.try_add(&pk, pn, true));
        assert!(kbucket.get_node(&pk, &node_pk).is_some());
    }

    #[test]
    fn kbucket_get_node_mut() {
        crypto_init().unwrap();
        let (pk, _) = gen_keypair();
        let mut kbucket = Kbucket::<DhtNode>::new(KBUCKET_DEFAULT_SIZE);

        let node_pk = gen_keypair().0;

        let pn = PackedNode {
            pk: node_pk,
            saddr: "127.0.0.1:33445".parse().unwrap(),
        };

        assert!(kbucket.try_add(&pk, pn, true));
        assert!(kbucket.get_node_mut(&pk, &node_pk).is_some());
    }

    fn position_test_data() -> (PublicKey, PackedNode, PackedNode, PackedNode) {
        let mut pk_bytes = [3; PUBLICKEYBYTES];

        pk_bytes[0] = 1;
        let base_pk = PublicKey(pk_bytes);

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

        (base_pk, n1, n2, n3)
    }

    // Check that insertion order does not affect
    // the result order in the ktree

    #[test]
    fn kbucket_position_straight_insertion() {
        let mut kbucket = Kbucket::<DhtNode>::new(KBUCKET_DEFAULT_SIZE);
        let (base_pk, n1, n2, n3) = position_test_data();
        // insert order: n1 n2 n3 maps to position
        // n1 => 0, n2 => 1, n3 => 2
        kbucket.try_add(&base_pk, n1, true);
        kbucket.try_add(&base_pk, n2, true);
        kbucket.try_add(&base_pk, n3, true);
        assert_eq!(kbucket.find(&base_pk, &n1.pk), Some(0));
        assert_eq!(kbucket.find(&base_pk, &n2.pk), Some(1));
        assert_eq!(kbucket.find(&base_pk, &n3.pk), Some(2));
    }

    #[test]
    fn kbucket_position_reverse_insertion() {
        let mut kbucket = Kbucket::<DhtNode>::new(KBUCKET_DEFAULT_SIZE);
        let (base_pk, n1, n2, n3) = position_test_data();
        // insert order: n3 n2 n1 maps to position
        // n1 => 0, n2 => 1, n3 => 2
        kbucket.try_add(&base_pk, n3, true);
        kbucket.try_add(&base_pk, n2, true);
        kbucket.try_add(&base_pk, n1, true);
        assert_eq!(kbucket.find(&base_pk, &n1.pk), Some(0));
        assert_eq!(kbucket.find(&base_pk, &n2.pk), Some(1));
        assert_eq!(kbucket.find(&base_pk, &n3.pk), Some(2));
    }

    // Check that removing order does not affect
    // the order of nodes inside

    #[test]
    fn kbucket_position_remove_first() {
        let mut kbucket = Kbucket::<DhtNode>::new(KBUCKET_DEFAULT_SIZE);
        let (base_pk, n1, n2, n3) = position_test_data();
        // prepare kbucket
        kbucket.try_add(&base_pk, n1, true); // => 0
        kbucket.try_add(&base_pk, n2, true); // => 1
        kbucket.try_add(&base_pk, n3, true); // => 2
        // test removing from the beginning (n1 => 0)
        kbucket.remove(&base_pk, &n1.pk);
        assert_eq!(kbucket.find(&base_pk, &n1.pk), None);
        assert_eq!(kbucket.find(&base_pk, &n2.pk), Some(0));
        assert_eq!(kbucket.find(&base_pk, &n3.pk), Some(1));
    }

    #[test]
    fn kbucket_position_remove_second() {
        let mut kbucket = Kbucket::<DhtNode>::new(KBUCKET_DEFAULT_SIZE);
        let (base_pk, n1, n2, n3) = position_test_data();
        // prepare kbucket
        kbucket.try_add(&base_pk, n1, true); // => 0
        kbucket.try_add(&base_pk, n2, true); // => 1
        kbucket.try_add(&base_pk, n3, true); // => 2
        // test removing from the middle (n2 => 1)
        kbucket.remove(&base_pk, &n2.pk);
        assert_eq!(kbucket.find(&base_pk, &n1.pk), Some(0));
        assert_eq!(kbucket.find(&base_pk, &n2.pk), None);
        assert_eq!(kbucket.find(&base_pk, &n3.pk), Some(1));
    }

    #[test]
    fn kbucket_position_remove_third() {
        let mut kbucket = Kbucket::<DhtNode>::new(KBUCKET_DEFAULT_SIZE);
        let (base_pk, n1, n2, n3) = position_test_data();
        // prepare kbucket
        kbucket.try_add(&base_pk, n1, true); // => 0
        kbucket.try_add(&base_pk, n2, true); // => 1
        kbucket.try_add(&base_pk, n3, true); // => 2
        // test removing from the end (n3 => 2)
        kbucket.remove(&base_pk, &n3.pk);
        assert_eq!(kbucket.find(&base_pk, &n1.pk), Some(0));
        assert_eq!(kbucket.find(&base_pk, &n2.pk), Some(1));
        assert_eq!(kbucket.find(&base_pk, &n3.pk), None);
    }

    #[test]
    fn kbucket_len() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut kbucket = Kbucket::<DhtNode>::new(KBUCKET_DEFAULT_SIZE);

        assert_eq!(kbucket.len(), 0);

        let node = PackedNode::new(
            "1.2.3.4:12345".parse().unwrap(),
            &PublicKey([1; PUBLICKEYBYTES])
        );

        assert!(kbucket.try_add(&pk, node, /* evict */ true));

        assert_eq!(kbucket.len(), 1);
    }
}
