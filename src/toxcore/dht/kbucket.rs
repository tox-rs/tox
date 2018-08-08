/*!
Structure for holding nodes.

Number of nodes it can contain is set during creation. If not set (aka `None`
is supplied), number of nodes defaults to [`BUCKET_DEFAULT_SIZE`].

Nodes stored in `Bucket` are in [`DhtNode`](./struct.DhtNode.html)
format.

Used in [`Kbucket`](./struct.Kbucket.html) for storing nodes close to given
PK; and additionally used to store nodes closest to friends.

[Spec definition](https://zetok.github.io/tox-spec#updating-k-buckets).

[`BUCKET_DEFAULT_SIZE`]: ./constant.BUCKET_DEFAULT_SIZE.html
*/

use std::cmp::{Ord, Ordering};
use std::convert::Into;
use std::net::SocketAddr;

use toxcore::crypto_core::*;
use toxcore::dht::dht_node::*;
use toxcore::dht::packed_node::*;
use toxcore::dht::ip_port::IsGlobal;
use toxcore::time::*;

/** Calculate the [`k-bucket`](./struct.Kbucket.html) index of a PK compared
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

impl Into<PackedNode> for DhtNode {
    fn into(self) -> PackedNode {
        let saddr = if self.assoc4.saddr.is_none() {
            SocketAddr::V6(self.assoc6.saddr.expect("into() PackedNode fails"))
        } else {
            SocketAddr::V4(self.assoc4.saddr.expect("into() PackedNode fails"))
        };

        PackedNode {
            pk: self.pk,
            saddr,
        }
    }
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

Number of nodes it can contain is set during creation. If not set (aka `None`
is supplied), number of nodes defaults to [`BUCKET_DEFAULT_SIZE`].

Nodes stored in `Bucket` are in [`DhtNode`](./struct.DhtNode.html)
format.

Used in [`Kbucket`](./struct.Kbucket.html) for storing nodes close to given
PK; and additionally used to store nodes closest to friends.

[Spec definition](https://zetok.github.io/tox-spec#updating-k-buckets).

[`BUCKET_DEFAULT_SIZE`]: ./constant.BUCKET_DEFAULT_SIZE.html
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bucket {
    /// Amount of nodes it can hold.
    pub capacity: u8,
    /// Nodes that bucket has, sorted by distance to PK.
    pub nodes: Vec<DhtNode>,
}

/// Default number of nodes that bucket can hold.
pub const BUCKET_DEFAULT_SIZE: usize = 8;

impl Bucket {
    /** Create a new `Bucket` to store nodes close to the `PublicKey`.

    Can hold up to `num` nodes if number is supplied. If `None` is
    supplied, holds up to [`BUCKET_DEFAULT_SIZE`] nodes. If `Some(0)`
    is supplied, it is treated as `None`.

    [`BUCKET_DEFAULT_SIZE`]: ./constant.BUCKET_DEFAULT_SIZE.html
    */
    pub fn new(num: Option<u8>) -> Self {
        trace!(target: "Bucket", "Creating a new Bucket.");
        match num {
            None => {
                trace!("Creating a new Bucket with default capacity.");
                Bucket {
                    capacity: BUCKET_DEFAULT_SIZE as u8,
                    nodes: Vec::with_capacity(BUCKET_DEFAULT_SIZE),
                }
            },
            Some(0) => {
                debug!("Treating Some(0) as None");
                Bucket::new(None)
            },
            Some(n) => {
                trace!("Creating a new Bucket with capacity: {}", n);
                Bucket {
                    capacity: n,
                    nodes: Vec::with_capacity(n as usize),
                }
            }
        }
    }

    fn find(&self, base_pk: &PublicKey, pk: &PublicKey) -> Option<usize> {
        self.nodes.binary_search_by(|n| base_pk.distance(&n.pk, pk)).ok()
    }

    /// Get mutable reference to a `DhtNode` by it's `PublicKey`.
    pub fn get_node_mut(&mut self, base_pk: &PublicKey, pk: &PublicKey) -> Option<&mut DhtNode> {
        self.find(base_pk, pk)
            .map(move |node_index| &mut self.nodes[node_index])
    }

    /**
    Try to add [`PackedNode`] to the bucket.

    - If the [`PackedNode`] with given `PublicKey` is already in the `Bucket`,
      the [`PackedNode`] is updated (since its `SocketAddr` can differ).
    - If bucket is not full, node is appended.
    - If bucket is full, node's closeness is compared to nodes already
      in bucket, and if it's closer than some node, it prepends that
      node, and last node is removed from the list.
    - If the node being added is farther away than the nodes in the bucket,
      it isn't added and `false` is returned.

    Note that you must pass the same `base_pk` each call or the internal
    state will be undefined.

    Returns `true` if node was added, `false` otherwise.

    [`PackedNode`]: ../packed_node/struct.PackedNode.html
    */
    pub fn try_add(&mut self, base_pk: &PublicKey, new_node: &PackedNode)
        -> bool
    {
        debug!(target: "Bucket", "Trying to add PackedNode.");
        trace!(target: "Bucket", "With bucket: {:?}; PK: {:?} and new node: {:?}",
            self, base_pk, new_node);

        match self.nodes.binary_search_by(|n| base_pk.distance(&n.pk, &new_node.pk)) {
            Ok(index) => {
                debug!(target: "Bucket",
                    "Updated: the node was already in the bucket.");
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
            Err(index) if index == self.nodes.len() => {
                // index is pointing past the end
                if self.is_full() {
                    match self.nodes.iter().rposition(|n| n.is_bad()) {
                        Some(index) => {
                            debug!(target: "Bucket",
                                "No free space left in the bucket, the last bad node removed.");
                            // replace the farthest bad node
                            self.nodes.remove(index);
                            self.nodes.push((*new_node).into());
                            true
                        },
                        None => {
                            debug!(target: "Bucket",
                                "Node is too distant to add to the bucket.");
                            false
                        },
                    }
                } else {
                    // distance to the PK was bigger than the other keys, but
                    // there's still free space in the bucket for a node
                    debug!(target: "Bucket",
                        "Node inserted at the end of the bucket.");
                    self.nodes.push((*new_node).into());
                    true
                }
            },
            Err(index) => {
                // index is pointing inside the list
                if self.is_full() {
                    debug!(target: "Bucket",
                        "No free space left in the bucket, the last node removed.");
                    self.nodes.pop();
                }
                debug!(target: "Bucket", "Node inserted inside the bucket.");
                self.nodes.insert(index, (*new_node).into());
                true
            },
        }
    }

    /** Remove [`DhtNode`](./struct.DhtNode.html) with given PK from the
    `Bucket`.

    Note that you must pass the same `base_pk` each call or the internal
    state will be undefined. Also `base_pk` must be equal to `base_pk` you added
    a node with. Normally you don't call this function on your own but Kbucket does.

    If there's no `DhtNode` with given PK, nothing is being done.
    */
    pub fn remove(&mut self, base_pk: &PublicKey, node_pk: &PublicKey) {
        trace!(target: "Bucket", "Removing DhtNode with PK: {:?}", node_pk);
        match self.nodes.binary_search_by(|n| base_pk.distance(&n.pk, node_pk)) {
            Ok(index) => {
                self.nodes.remove(index);
            },
            Err(_) => {
                trace!("No DhtNode to remove with PK: {:?}", node_pk);
            }
        }
    }

    /// Check if node with given PK is in the `Bucket`.
    pub fn contains(&self, base_pk: &PublicKey, pk: &PublicKey) -> bool {
        self.nodes.binary_search_by(|n| base_pk.distance(&n.pk, pk)).is_ok()
    }

    /// Get the capacity of the Bucket.
    pub fn capacity(&self) -> usize {
        self.capacity as usize
    }

    /** Check if `Bucket` is empty.

    Returns `true` if there are no nodes in the `Bucket`, `false`
    otherwise.
    */
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /** Check if `Bucket` is full.

    Returns `true` if there is no free space in the `Bucket`, `false`
    otherwise.
    */
    pub fn is_full(&self) -> bool {
        self.nodes.len() == self.capacity()
    }

    /**
    Naive check whether a [`PackedNode`] can be added to the `Bucket`.

    Returns `true` if [`Bucket`] where node could be placed is not full
    and node is not already in the [`Bucket`].

    Otherwise `false` is returned.

    [`Bucket`]: ./struct.Bucket.html
    [`PackedNode`]: ./struct.PackedNode.html
    */
    pub fn can_add(&self, base_pk: &PublicKey, new_node: &PackedNode) -> bool { // TODO: synchronize result with try_add?
        match self.nodes.binary_search_by(|n| base_pk.distance(&n.pk, &new_node.pk)) {
            Ok(index) => // if node is bad then we'd want to update it's address
                self.nodes[index].is_bad() ||
                    self.nodes[index].assoc4.saddr.map(SocketAddr::V4) != Some(new_node.saddr) &&
                        self.nodes[index].assoc6.saddr.map(SocketAddr::V6) != Some(new_node.saddr),
            Err(index) if index == self.nodes.len() => // can't find node in bucket
                !self.is_full() || self.nodes.iter().any(|n| n.is_bad()),
            Err(_index) => true, // node is not found in bucket, so can add node
        }
    }

    /// Get vector of `PackedNode`s that `Bucket` has.
    pub fn to_packed(&self) -> Vec<PackedNode> {
        self.nodes.iter().map(|node| node.clone().into()).collect()
    }
}

/**
Equivalent to calling [`Bucket::new()`] with `None`:

```
# use tox::toxcore::dht::kbucket::Bucket;
assert_eq!(Bucket::new(None), Bucket::default());
```

[`Bucket::new()`]: ./struct.Bucket.html#method.new
*/
impl Default for Bucket {
    fn default() -> Self {
        Bucket::new(Some(BUCKET_DEFAULT_SIZE as u8))
    }
}

/** K-buckets structure to hold up to
[`KBUCKET_MAX_ENTRIES`](./constant.KBUCKET_MAX_ENTRIES.html) *
[`BUCKET_DEFAULT_SIZE`](./constant.BUCKET_DEFAULT_SIZE.html) nodes close to
own PK.

Nodes in bucket are sorted by closeness to the PK; closest node is the last
one, while furthest is the first one.

Further reading: [Tox spec](https://zetok.github.io/tox-spec#k-buckets).
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kbucket {
    /// `PublicKey` for which `Kbucket` holds close nodes.
    pk: PublicKey,
    /// flag for Dht server is running in IPv6 mode.
    pub is_ipv6_mode: bool,

    /// List of [`Bucket`](./struct.Bucket.html)s.
    pub buckets: Vec<Bucket>,
}

/** Maximum number of [`Bucket`](./struct.Bucket.html)s that [`Kbucket`]
can hold.

Realistically, not even half of that will be ever used, given how
[index calculation](./fn.kbucket_index.html) works.

[`Kbucket`]: ./struct.Kbucket.html
*/
pub const KBUCKET_MAX_ENTRIES: u8 = ::std::u8::MAX;

impl Kbucket {
    /// Create a new `Kbucket`.
    pub fn new(pk: &PublicKey) -> Self {
        trace!(target: "Kbucket", "Creating new Kbucket with PK: {:?}", pk);
        Kbucket {
            pk: *pk,
            is_ipv6_mode: false,
            buckets: vec![Bucket::new(None); KBUCKET_MAX_ENTRIES as usize]
        }
    }

    /// Find indices of `DhtNode` by it's `PublicKey`.
    #[cfg(test)]
    fn find(&self, pk: &PublicKey) -> Option<(usize, usize)> {
        self.bucket_index(pk).and_then(|index|
            self.buckets[index]
                .find(&self.pk, pk)
                .map(|node_index| (index, node_index))
        )
    }

    /// Get reference to a `DhtNode` by it's `PublicKey`.
    pub fn get_node(&self, pk: &PublicKey) -> Option<&DhtNode> {
        self.bucket_index(pk).and_then(|index|
            self.buckets[index]
                .find(&self.pk, pk)
                .map(|node_index| &self.buckets[index].nodes[node_index])
        )
    }

    /// Get mutable reference to a `DhtNode` by it's `PublicKey`.
    pub fn get_node_mut(&mut self, pk: &PublicKey) -> Option<&mut DhtNode> {
        self.bucket_index(pk).and_then(|index|
            self.buckets[index]
                .find(&self.pk, pk)
                .map(move |node_index| &mut self.buckets[index].nodes[node_index])
        )
    }

    /** Return the possible internal index of [`Bucket`](./struct.Bucket.html)
        where the key could be inserted/removed.

    Same as [`kbucket index`](./fn.kbucket_index.html) but uses stored in
    `Kbucket` public key.

    Returns `None` only if supplied key is the same as stored in `Kbucket` key.
    */
    fn bucket_index(&self, pk: &PublicKey) -> Option<usize> {
        kbucket_index(&self.pk, pk).map(|index| index as usize)
    }

    /** Add [`PackedNode`](./struct.PackedNode.html) to `Kbucket`.

    Node can be added only if:

    * its [`kbucket index`](./fn.kbucket_index.html) is lower than the
      number of buckets.
    * [`Bucket`](./struct.Bucket.html) to which it is added has free space
      or added node is closer to the PK than other node in the bucket.

    Returns `true` if node was added successfully, `false` otherwise.
    */
    pub fn try_add(&mut self, node: &PackedNode) -> bool {
        debug!(target: "Kbucket", "Trying to add PackedNode.");
        trace!(target: "Kbucket", "With PN: {:?}; and self: {:?}", node, self);

        match self.bucket_index(&node.pk) {
            Some(index) => self.buckets[index].try_add(&self.pk, node),
            None => {
                trace!("Failed to add node: {:?}", node);
                false
            }
        }
    }

    /// Remove [`DhtNode`](./struct.DhtNode.html) with given PK from the
    /// `Kbucket`.
    pub fn remove(&mut self, node_pk: &PublicKey) {
        trace!(target: "Kbucket", "Removing PK: {:?} from Kbucket: {:?}", node_pk,
                self);

        match self.bucket_index(node_pk) {
            Some(index) => self.buckets[index].remove(&self.pk, node_pk),
            None => trace!("Failed to remove PK: {:?}", node_pk)
        }
    }

    /** Get (up to) 4 closest nodes to given PK.

    Functionality for [`SendNodes`](./struct.SendNodes.html).

    Returns less than 4 nodes only if `Kbucket` contains less than 4
    nodes.

    It should not contain LAN ip node if the request is from global ip.
    */
    pub fn get_closest(&self, pk: &PublicKey, only_global_ip: bool) -> Vec<PackedNode> {
        debug!(target: "Kbucket", "Getting closest nodes.");
        trace!(target: "Kbucket", "With PK: {:?} and self: {:?}", pk, self);
        // create a new Bucket with associated pk, and add nodes that are close
        // to the PK
        let mut bucket = Bucket::new(Some(4));
        for buc in &self.buckets {
            for node in buc.nodes.iter().filter(|node| !node.is_bad()) {
                if let Some(sock) = node.get_socket_addr(self.is_ipv6_mode) {
                    if only_global_ip && !IsGlobal::is_global(&sock.ip()) {
                        continue;
                    }
                } else {
                    continue;
                }
                bucket.try_add(pk, &node.clone().into());
            }
        }
        trace!("Returning nodes: {:?}", &bucket.nodes);

        bucket.to_packed()
    }

    /**
    Check if `Kbucket` contains [`PackedNode`] with given PK.

    [`PackedNode`]: ./struct.PackedNode.html
    */
    pub fn contains(&self, pk: &PublicKey) -> bool {
        match self.bucket_index(pk) {
            Some(i) => self.buckets[i].contains(&self.pk, pk),
            None => false,
        }
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
        match self.bucket_index(&new_node.pk) {
            None => false,
            Some(i) =>
                self.buckets[i].can_add(&self.pk, new_node),
        }
    }

    /** Check if `Kbucket` is empty.

    Returns `true` if all `buckets` are empty, `false`
    otherwise.
    */
    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(|bucket| bucket.is_empty())
    }

    /// Create iterator over [`DhtNode`](./struct.DhtNode.html)s in `Kbucket`.
    pub fn iter(&self) -> impl Iterator<Item = &DhtNode> {
        self.buckets.iter()
            .flat_map(|bucket| bucket.nodes.iter())
    }

    /// Create mutable iterator over [`DhtNode`](./struct.DhtNode.html)s in
    /// `Kbucket`.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut DhtNode> {
        self.buckets.iter_mut()
            .flat_map(|bucket| bucket.nodes.iter_mut())
    }
}

#[cfg(test)]
extern crate rand;

#[cfg(test)]
mod tests {
    use super::rand::chacha::ChaChaRng;
    use super::*;
    use quickcheck::{Arbitrary, Gen, quickcheck, StdGen, TestResult};
    use byteorder::{BigEndian, WriteBytesExt};
    use std::net::{
        Ipv4Addr,
        SocketAddr,
        SocketAddrV4,
    };
    use std::time::{Duration, Instant};

    use tokio_executor;
    use tokio_timer::clock::*;

    use toxcore::time::ConstNow;

    /// Get a PK from 4 `u64`s.
    fn nums_to_pk(a: u64, b: u64, c: u64, d: u64) -> PublicKey {
        let mut pk_bytes: Vec<u8> = Vec::with_capacity(PUBLICKEYBYTES);
        pk_bytes.write_u64::<BigEndian>(a).unwrap();
        pk_bytes.write_u64::<BigEndian>(b).unwrap();
        pk_bytes.write_u64::<BigEndian>(c).unwrap();
        pk_bytes.write_u64::<BigEndian>(d).unwrap();
        let pk_bytes = &pk_bytes[..];
        PublicKey::from_slice(pk_bytes).expect("Making PK out of bytes failed!")
    }

    // PublicKey::distance()

    #[test]
    // TODO: possible to use quickcheck?
    fn dht_public_key_distance_test() {
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
    fn dht_kbucket_index_test() {
        let pk1 = PublicKey([0b10_10_10_10; PUBLICKEYBYTES]);
        let pk2 = PublicKey([0; PUBLICKEYBYTES]);
        let pk3 = PublicKey([0b00_10_10_10; PUBLICKEYBYTES]);
        assert_eq!(None, kbucket_index(&pk1, &pk1));
        assert_eq!(Some(0), kbucket_index(&pk1, &pk2));
        assert_eq!(Some(2), kbucket_index(&pk2, &pk3));
    }


    // Bucket::

    // Bucket::new()

    #[test]
    fn dht_bucket_new_test() {
        fn check_with_capacity(num: Option<u8>, expected_capacity: usize) {
            let bucket1 = Bucket::new(num);
            assert_eq!(expected_capacity, bucket1.capacity());

            // check if always the same with same parameters
            let bucket2 = Bucket::new(num);
            assert_eq!(bucket1, bucket2);
        }
        check_with_capacity(None, BUCKET_DEFAULT_SIZE);
        check_with_capacity(Some(0), BUCKET_DEFAULT_SIZE);

        fn wrapped_check(num: u8) -> TestResult {
            // check Some(n) where n > 0
            if num == 0 {
                return TestResult::discard()
            }
            check_with_capacity(Some(num), num as usize);
            TestResult::passed()
        }
        quickcheck(wrapped_check as fn(u8) -> TestResult);
        wrapped_check(0);
    }

    // Bucket::try_add()

    #[test]
    fn dht_bucket_try_add_test() {
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

            // TODO: check whether adding a closest node will always work
        }
        quickcheck(with_nodes as fn(PackedNode, PackedNode, PackedNode, PackedNode,
                    PackedNode, PackedNode, PackedNode, PackedNode));
    }

    #[test]
    fn dht_bucket_1_capacity_try_add_test() {
        fn with_nodes(n1: PackedNode, n2: PackedNode) -> TestResult {
            let pk = PublicKey([0; PUBLICKEYBYTES]);
            if pk.distance(&n2.pk, &n1.pk) != Ordering::Greater {
                // n2 should be greater to check we can't add it
                return TestResult::discard()
            }

            let mut bucket = Bucket::new(Some(1));

            assert!(bucket.try_add(&pk, &n1));
            assert!(!bucket.try_add(&pk, &n2));

            // updating node
            assert!(bucket.try_add(&pk, &n1));

            let mut enter = tokio_executor::enter().unwrap();
            let clock = Clock::new_with_now(ConstNow(
                Instant::now() + Duration::from_secs(BAD_NODE_TIMEOUT + 1)
            ));

            // replacing bad node
            with_default(&clock, &mut enter, |_| {
                assert!(bucket.try_add(&pk, &n2));
            });

            TestResult::passed()
        }
        quickcheck(with_nodes as fn(PackedNode, PackedNode) -> TestResult);
    }

    // Bucket::remove()

    #[test]
    fn dht_bucket_remove_test() {
        fn with_nodes(num: u8, bucket_size: u8, rng_num: usize) {
            let mut rng = StdGen::new(ChaChaRng::new_unseeded(), rng_num);

            let base_pk = PublicKey([0; PUBLICKEYBYTES]);
            let mut bucket = Bucket::new(Some(bucket_size));

            let non_existent_node: PackedNode = Arbitrary::arbitrary(&mut rng);
            bucket.remove(&base_pk, &non_existent_node.pk);  // "removing" non-existent node
            assert_eq!(true, bucket.is_empty());

            let nodes = vec![Arbitrary::arbitrary(&mut rng); num as usize];
            for node in &nodes {
                bucket.try_add(&base_pk, node);
            }
            if num == 0 {
                // nothing was added
                assert_eq!(true, bucket.is_empty());
            } else {
                // some nodes were added
                assert_eq!(false, bucket.is_empty());
            }

            for node in &nodes {
                bucket.remove(&base_pk, &node.pk);
            }
            assert_eq!(true, bucket.is_empty());
        }
        quickcheck(with_nodes as fn(u8, u8, usize))
    }


    // Bucket::is_empty()

    #[test]
    fn dht_bucket_is_empty_test() {
        fn with_pns(pns: Vec<PackedNode>, p1: u64, p2: u64, p3: u64, p4: u64) -> TestResult {
            if pns.len() > BUCKET_DEFAULT_SIZE {
                // it's possible that not all nodes will be inserted if
                // len > BUCKET_DEFAULT_SIZE
                return TestResult::discard()
            }

            let mut bucket = Bucket::new(None);
            assert_eq!(true, bucket.is_empty());

            let pk = nums_to_pk(p1, p2, p3, p4);
            for n in &pns {
                assert!(bucket.try_add(&pk, n));
            }
            if !pns.is_empty() {
                assert_eq!(false, bucket.is_empty());
            }
            TestResult::passed()
        }
        quickcheck(with_pns as fn(Vec<PackedNode>, u64, u64, u64, u64) -> TestResult);
    }


    // Kbucket::

    impl Arbitrary for Kbucket {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let mut pk = [0; PUBLICKEYBYTES];
            g.fill_bytes(&mut pk);
            let pk = PublicKey([0; PUBLICKEYBYTES]);

            let mut kbucket = Kbucket::new(&pk);

            // might want to add some buckets
            for _ in 0..(g.gen_range(0, KBUCKET_MAX_ENTRIES as usize *
                            BUCKET_DEFAULT_SIZE as usize * 2)) {
                kbucket.try_add(&Arbitrary::arbitrary(g));
            }
            kbucket
        }
    }

    // Kbucket::new()

    #[test]
    fn dht_kbucket_new_test() {
        fn with_pk(a: u64, b: u64, c: u64, d: u64) {
            let pk = nums_to_pk(a, b, c, d);
            let kbucket = Kbucket::new(&pk);
            assert_eq!(pk, kbucket.pk);
        }
        quickcheck(with_pk as fn(u64, u64, u64, u64));
    }

    // Kbucket::try_add()

    #[test]
    fn dht_kbucket_try_add_test() {
        fn with_pns(pns: Vec<PackedNode>, p1: u64, p2: u64, p3: u64, p4: u64) {
            let pk = nums_to_pk(p1, p2, p3, p4);
            let mut kbucket = Kbucket::new(&pk);
            for node in pns {
                // result may vary, so discard it
                // TODO: can be done better?
                kbucket.try_add(&node);
            }
        }
        quickcheck(with_pns as fn(Vec<PackedNode>, u64, u64, u64, u64));
    }

    // Kbucket::remove()

    #[test]
    fn dht_kbucket_remove_test() {
        fn with_nodes(nodes: Vec<PackedNode>) -> TestResult {
            if nodes.len() > BUCKET_DEFAULT_SIZE {
                // it's possible that not all nodes will be inserted if
                // len > BUCKET_DEFAULT_SIZE
                return TestResult::discard()
            }

            let pk = nums_to_pk(random_u64(), random_u64(), random_u64(),
                    random_u64());

            let mut kbucket = Kbucket::new(&pk);

            // Fill Kbucked with nodes
            for node in &nodes {
                assert!(kbucket.try_add(node));
            }
            if !nodes.is_empty() {
                assert!(!kbucket.is_empty());
            }

            // Check for actual removing
            for node in &nodes {
                kbucket.remove(&node.pk);
            }
            assert!(kbucket.is_empty());
            TestResult::passed()
        }
        quickcheck(with_nodes as fn(Vec<PackedNode>) -> TestResult);
    }

    // Kbucket::get_closest()

    #[test]
    fn dht_kbucket_get_closest_test() {
        fn with_kbucket(kb: Kbucket, a: u64, b: u64, c: u64, d: u64) {
            let mut kb = kb;
            kb.is_ipv6_mode = true;
            let pk = nums_to_pk(a, b, c, d);
            assert!(kb.get_closest(&pk, true).len() <= 4);
            assert_eq!(kb.get_closest(&pk, true), kb.get_closest(&pk, true));
        }
        quickcheck(with_kbucket as fn(Kbucket, u64, u64, u64, u64));


        fn with_nodes(n1: PackedNode, n2: PackedNode, n3: PackedNode,
                        n4: PackedNode, a: u64, b: u64, c: u64, d: u64) {

            if !IsGlobal::is_global(&n1.saddr.ip()) ||
                !IsGlobal::is_global(&n2.saddr.ip()) ||
                !IsGlobal::is_global(&n3.saddr.ip()) ||
                !IsGlobal::is_global(&n4.saddr.ip()) {
                return;
            }

            let pk = nums_to_pk(a, b, c, d);
            let mut kbucket = Kbucket::new(&pk);
            kbucket.is_ipv6_mode = true;

            // check whether number of correct nodes that are returned is right
            let correctness = |should, kbc: &Kbucket| {
                assert_eq!(kbc.get_closest(&pk, true), kbc.get_closest(&kbc.pk, true));

                let got_nodes = kbc.get_closest(&pk, true);
                let mut got_correct = 0;
                for node in got_nodes {
                    if node == n1 || node == n2 || node == n3 || node == n4 {
                        got_correct += 1;
                    }
                }
                assert_eq!(should, got_correct);
            };

            correctness(0, &kbucket);

            assert_eq!(true, kbucket.try_add(&n1));
            correctness(1, &kbucket);
            assert_eq!(true, kbucket.try_add(&n2));
            correctness(2, &kbucket);
            assert_eq!(true, kbucket.try_add(&n3));
            correctness(3, &kbucket);
            assert_eq!(true, kbucket.try_add(&n4));
            correctness(4, &kbucket);
        }
        quickcheck(with_nodes as fn(PackedNode, PackedNode, PackedNode,
                        PackedNode, u64, u64, u64, u64));
    }

     // Kbucket::position()

    #[test]
    fn kbucket_position_test() {
        fn with_data<F>(test_fn: F)
            where F: Fn(&mut Kbucket, // kbucket
                &PackedNode, // n1
                &PackedNode, // n2
                &PackedNode) // n3
        {
            let mut pk_bytes = [3; PUBLICKEYBYTES];

            pk_bytes[0] = 1;
            let base_pk = PublicKey(pk_bytes);

            let mut kbucket = Kbucket::new(&base_pk);

            let addr = Ipv4Addr::new(0, 0, 0, 0);
            let saddr = SocketAddrV4::new(addr, 0);

            let n0_base_pk = PackedNode::new(SocketAddr::V4(saddr), &base_pk);
            assert!(!kbucket.try_add(&n0_base_pk));
            kbucket.remove(&base_pk);

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

            assert_eq!(Some(46), kbucket_index(&base_pk, &pk1));
            assert_eq!(Some(46), kbucket_index(&base_pk, &pk2));
            assert_eq!(Some(46), kbucket_index(&base_pk, &pk3));

            test_fn(&mut kbucket, &n1, &n2, &n3);
        }
        // Check that insertion order does not affect
        // the result order in the kbucket
        with_data(|kbucket, n1, n2, n3| {
            // insert order: n1 n2 n3 maps to position
            // n1 => 0, n2 => 1, n3 => 2
            kbucket.try_add(n1);
            kbucket.try_add(n2);
            kbucket.try_add(n3);
            assert_eq!(Some((46, 0)), kbucket.find(&n1.pk));
            assert_eq!(Some((46, 1)), kbucket.find(&n2.pk));
            assert_eq!(Some((46, 2)), kbucket.find(&n3.pk));
        });
        with_data(|kbucket, n1, n2, n3| {
            // insert order: n3 n2 n1 maps to position
            // n1 => 0, n2 => 1, n3 => 2
            kbucket.try_add(n3);
            kbucket.try_add(n2);
            kbucket.try_add(n1);
            assert_eq!(Some((46, 0)), kbucket.find(&n1.pk));
            assert_eq!(Some((46, 1)), kbucket.find(&n2.pk));
            assert_eq!(Some((46, 2)), kbucket.find(&n3.pk));
        });
        // Check that removing order does not affect
        // the order of nodes inside
        with_data(|kbucket, n1, n2, n3| {
            // prepare kbucket
            kbucket.try_add(n1); // => 0
            kbucket.try_add(n2); // => 1
            kbucket.try_add(n3); // => 2
            // test removing from the beginning (n1 => 0)
            kbucket.remove(&n1.pk);
            assert_eq!(None,          kbucket.find(&n1.pk));
            assert_eq!(Some((46, 0)), kbucket.find(&n2.pk));
            assert_eq!(Some((46, 1)), kbucket.find(&n3.pk));
        });
        with_data(|kbucket, n1, n2, n3| {
            // prepare kbucket
            kbucket.try_add(n1); // => 0
            kbucket.try_add(n2); // => 1
            kbucket.try_add(n3); // => 2
            // test removing from the middle (n2 => 1)
            kbucket.remove(&n2.pk);
            assert_eq!(Some((46, 0)), kbucket.find(&n1.pk));
            assert_eq!(None,          kbucket.find(&n2.pk));
            assert_eq!(Some((46, 1)), kbucket.find(&n3.pk));
        });
        with_data(|kbucket, n1, n2, n3| {
            // prepare kbucket
            kbucket.try_add(n1); // => 0
            kbucket.try_add(n2); // => 1
            kbucket.try_add(n3); // => 2
            // test removing from the end (n3 => 2)
            kbucket.remove(&n3.pk);
            assert_eq!(Some((46, 0)), kbucket.find(&n1.pk));
            assert_eq!(Some((46, 1)), kbucket.find(&n2.pk));
            assert_eq!(None,          kbucket.find(&n3.pk));
        });
    }

    // Kbucket::contains()

    quickcheck! {
        fn kbucket_contains_test(pns: Vec<PackedNode>) -> TestResult {
            if pns.is_empty() { return TestResult::discard() }

            let (pk, _) = gen_keypair();
            let mut kbucket = Kbucket::new(&pk);
            assert!(!kbucket.contains(&pk));
            assert!(pns.iter().all(|pn| !kbucket.contains(&pn.pk)));

            for pn in &pns {
                kbucket.try_add(pn);
            }

            assert!(kbucket.iter().all(|pn| kbucket.contains(&pn.pk)));

            TestResult::passed()
        }
    }

    // Kbucket::can_add()

    quickcheck! {
        fn kbucket_can_add_test(pns: Vec<PackedNode>) -> TestResult {
            if pns.len() < 2 { return TestResult::discard() }

            let (pk, _) = gen_keypair();
            // there should be at least a pair of nodes with same index
            {
                let fitting_nodes = pns.iter().any(|p1| pns.iter()
                    .filter(|p2| p1 != *p2)
                    .any(|p2| kbucket_index(&pk, &p1.pk) == kbucket_index(&pk, &p2.pk)));
                if !fitting_nodes {
                    return TestResult::discard()
                }
            }

            let mut kbucket = Kbucket {
                pk,
                is_ipv6_mode: false,
                buckets: vec![Bucket::new(Some(2)); KBUCKET_MAX_ENTRIES as usize],
            };

            for node in pns {
                if kbucket.try_add(&node) {
                    assert!(!kbucket.can_add(&node));
                }
            }

            TestResult::passed()
        }
    }

    // KbucketIter::next()

    quickcheck! {
        fn kbucket_iter_next_test(pns: Vec<PackedNode>) -> () {
            let (pk, _) = gen_keypair();
            let mut kbucket = Kbucket::new(&pk);
            // empty always returns None
            assert!(kbucket.iter().next().is_none());

            for node in &pns {
                kbucket.try_add(node);
            }

            let mut expect = Vec::new();
            for bucket in &kbucket.buckets {
                for node in &bucket.nodes {
                    expect.push(node.clone());
                }
            }

            let mut e_iter = expect.iter();
            let mut k_iter = kbucket.iter();
            loop {
                let enext = e_iter.next();
                if let Some(knext) = k_iter.next() {
                    let knext = Some(knext);
                    assert_eq!(enext, knext);
                    if enext.is_none() {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
    }

    quickcheck! {
        fn kbucket_iter_mut_next_test(pns: Vec<PackedNode>) -> () {
            let (pk, _) = gen_keypair();
            let mut kbucket = Kbucket::new(&pk);
            // empty always returns None
            assert!(kbucket.iter_mut().next().is_none());

            for node in &pns {
                kbucket.try_add(node);
            }

            let mut expect = Vec::new();
            for bucket in &kbucket.buckets {
                for node in &bucket.nodes {
                    expect.push(node.clone());
                }
            }

            let mut e_iter = expect.iter();
            let mut k_iter = kbucket.iter_mut();
            loop {
                let enext = e_iter.next();
                if let Some(knext) = k_iter.next() {
                    let knext = Some(&*knext);
                    assert_eq!(enext, knext);
                    if enext.is_none() {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
    }

    #[test]
    fn kbucket_to_packed_node_test() {
        let (pk, _) = gen_keypair();
        let mut bucket = Bucket::new(None);

        let pn = PackedNode {
            pk: gen_keypair().0,
            saddr: "127.0.0.1:33445".parse().unwrap(),
        };

        assert!(bucket.try_add(&pk,&pn));

        let res_pn = bucket.to_packed();

        assert_eq!(pn, res_pn[0]);
    }
}
