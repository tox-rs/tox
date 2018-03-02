/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2016-2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2018 Namsoo CHO <nscho66@gmail.com>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
Structure for holding nodes.

Number of nodes it can contain is set during creation. If not set (aka `None`
is supplied), number of nodes defaults to [`BUCKET_DEFAULT_SIZE`]
(./constant.BUCKET_DEFAULT_SIZE.html).

Nodes stored in `Bucket` are in [`PackedNode`](./struct.PackedNode.html)
format.

Used in [`Kbucket`](./struct.Kbucket.html) for storing nodes close to given
PK; and additionally used to store nodes closest to friends.

[Spec definition](https://zetok.github.io/tox-spec#updating-k-buckets).
*/

// ↓ FIXME expand doc
/*! DHT part of the toxcore.
    * takes care of the K-Bucket
*/
use toxcore::crypto_core::*;
use toxcore::dht_new::packed_node::PackedNode;
use std::cmp::{Ord, Ordering};

/** Calculate the [`k-bucket`](./struct.Kbucket.html) index of a PK compared
to "own" PK.

According to the [spec](https://zetok.github.io/tox-spec#bucket-index).

Fails (returns `None`) if supplied keys are the same.
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
is supplied), number of nodes defaults to [`BUCKET_DEFAULT_SIZE`]
(./constant.BUCKET_DEFAULT_SIZE.html).

Nodes stored in `Bucket` are in [`PackedNode`](./struct.PackedNode.html)
format.

Used in [`Kbucket`](./struct.Kbucket.html) for storing nodes close to given
PK; and additionally used to store nodes closest to friends.

[Spec definition](https://zetok.github.io/tox-spec#updating-k-buckets).
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bucket {
    /// Amount of nodes it can hold.
    capacity: u8,
    /// Nodes that bucket has, sorted by distance to PK.
    nodes: Vec<PackedNode>
}

/// Default number of nodes that bucket can hold.
pub const BUCKET_DEFAULT_SIZE: usize = 8;

impl Bucket {
    /** Create a new `Bucket` to store nodes close to the `PublicKey`.

    Can hold up to `num` nodes if number is supplied. If `None` is
    supplied, holds up to [`BUCKET_DEFAULT_SIZE`]
    (./constant.BUCKET_DEFAULT_SIZE.html) nodes. If `Some(0)` is
    supplied, it is treated as `None`.
    */
    pub fn new(num: Option<u8>) -> Self {
        trace!(target: "Bucket", "Creating a new Bucket.");
        match num {
            None => {
                trace!("Creating a new Bucket with default capacity.");
                Bucket {
                    capacity: BUCKET_DEFAULT_SIZE as u8,
                    nodes: Vec::with_capacity(BUCKET_DEFAULT_SIZE)
                }
            },
            Some(0) => {
                error!("Treating Some(0) as None");
                Bucket::new(None)
            },
            Some(n) => {
                trace!("Creating a new Bucket with capacity: {}", n);
                Bucket { capacity: n, nodes: Vec::with_capacity(n as usize) }
            }
        }
    }

    #[cfg(test)]
    fn find(&self, pk: &PublicKey) -> Option<usize> {
        for (n, node) in self.nodes.iter().enumerate() {
            if &node.pk == pk {
                return Some(n)
            }
        }
        None
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

    [`PackedNode`]: ./struct.PackedNode.html
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
                self.nodes.remove(index);
                self.nodes.insert(index, *new_node);
                true
            },
            Err(index) if index == self.nodes.len() => {
                // index is pointing past the end
                if self.is_full() {
                    debug!(target: "Bucket",
                        "Node is too distant to add to the bucket.");
                    false
                } else {
                    // distance to the PK was bigger than the other keys, but
                    // there's still free space in the bucket for a node
                    debug!(target: "Bucket",
                        "Node inserted at the end of the bucket.");
                    self.nodes.push(*new_node);
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
                self.nodes.insert(index, *new_node);
                true
            },
        }
    }

    /** Remove [`PackedNode`](./struct.PackedNode.html) with given PK from the
    `Bucket`.

    Note that you must pass the same `base_pk` each call or the internal
    state will be undefined. Also `base_pk` must be equal to `base_pk` you added
    a node with. Normally you don't call this function on your own but Kbucket does.

    If there's no `PackedNode` with given PK, nothing is being done.
    */
    pub fn remove(&mut self, base_pk: &PublicKey, node_pk: &PublicKey) {
        trace!(target: "Bucket", "Removing PackedNode with PK: {:?}", node_pk);
        match self.nodes.binary_search_by(|n| base_pk.distance(&n.pk, node_pk) ) {
            Ok(index) => {
                self.nodes.remove(index);
            },
            Err(_) => {
                trace!("No PackedNode to remove with PK: {:?}", node_pk);
            }
        }
    }

    /// Check if node with given PK is in the `Bucket`.
    pub fn contains(&self, pk: &PublicKey) -> bool {
        self.nodes.iter().any(|n| &n.pk == pk)
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
}

/**
Equivalent to calling [`Bucket::new()`] with `None`:

```
# use tox::toxcore::dht_new::kbucket::Bucket;
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

Nodes in bucket are sorted by closeness to the PK; closest node is the first,
while furthest is last.

Further reading: [Tox spec](https://zetok.github.io/tox-spec#k-buckets).
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kbucket {
    /// `PublicKey` for which `Kbucket` holds close nodes.
    pk: PublicKey,

    /// List of [`Bucket`](./struct.Bucket.html)s.
    buckets: Vec<Box<Bucket>>,
}

/** Maximum number of [`Bucket`](./struct.Bucket.html)s that [`Kbucket`]
(./struct.Kbucket.html) can hold.

Realistically, not even half of that will be ever used, given how
[index calculation](./fn.kbucket_index.html) works.
*/
pub const KBUCKET_MAX_ENTRIES: u8 = ::std::u8::MAX;

/** Default number of [`Bucket`](./struct.Bucket.html)s that [`Kbucket`]
(./struct.Kbucket.html) holds.
*/
pub const KBUCKET_BUCKETS: u8 = 128;

impl Kbucket {
    /// Create a new `Kbucket`.
    ///
    /// `n` – number of [`Bucket`](./struct.Bucket.html)s held.
    pub fn new(n: u8, pk: &PublicKey) -> Self {
        trace!(target: "Kbucket", "Creating new Kbucket with k: {:?} and PK:
               {:?}", n, pk);
        Kbucket {
            pk: *pk,
            buckets: vec![Box::new(Bucket::new(None)); n as usize]
        }
    }

    /// Number of [`Bucket`](./struct.Bucket.html)s held.
    pub fn size(&self) -> u8 {
        self.buckets.len() as u8
    }

    #[cfg(test)]
    fn find(&self, pk: &PublicKey) -> Option<(usize, usize)> {
        for (bucket_index, bucket) in self.buckets.iter().enumerate() {
            match bucket.find(pk) {
                None => {},
                Some(node_index) => return Some((bucket_index, node_index))
            }
        }
        None
    }

   /** Return the possible internal index of [`Bucket`](./struct.Bucket.html)
        where the key could be inserted/removed.

    Returns `Some(index)` if [`kbucket index`](./fn.kbucket_index.html) is
    defined and it is lower than the number of buckets.

    Returns `None` otherwise.
    */
    fn bucket_index(&self, pubkey: &PublicKey) -> Option<usize> {
        match kbucket_index(&self.pk, pubkey) {
            Some(index) if index < self.size() => Some(index as usize),
            _ => None
        }
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

    /// Remove [`PackedNode`](./struct.PackedNode.html) with given PK from the
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
    */
    pub fn get_closest(&self, pk: &PublicKey) -> Vec<PackedNode> {
        debug!(target: "Kbucket", "Getting closest nodes.");
        trace!(target: "Kbucket", "With PK: {:?} and self: {:?}", pk, self);
        // create a new Bucket with associated pk, and add nodes that are close
        // to the PK
        let mut bucket = Bucket::new(Some(4));
        for buc in &*self.buckets {
            for node in &*buc.nodes {
                bucket.try_add(pk, node);
            }
        }
        trace!("Returning nodes: {:?}", &bucket.nodes);
        bucket.nodes
    }

    /**
    Check if `Kbucket` contains [`PackedNode`] with given PK.

    [`PackedNode`]: ./struct.PackedNode.html
    */
    pub fn contains(&self, pk: &PublicKey) -> bool {
        match self.bucket_index(pk) {
            Some(i) => self.buckets[i].contains(pk),
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
    pub fn can_add(&self, pk: &PublicKey) -> bool {
        match self.bucket_index(pk) {
            None => false,
            Some(i) =>
                !self.buckets[i].is_full() && !self.buckets[i].contains(pk),
        }
    }

    /** Check if `Kbucket` is empty.

    Returns `true` if all `buckets` are empty, `false`
    otherwise.
    */
    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(|bucket| bucket.is_empty())
    }

    /// Create iterator over [`PackedNode`](./struct.PackedNode.html)s in
    /// `Kbucket`.
    pub fn iter(&self) -> KbucketIter {
        KbucketIter {
            pos_b: 0,
            pos_pn: 0,
            buckets: self.buckets.as_slice(),
        }
    }
}

/// Iterator over `PackedNode`s in `Kbucket`.
pub struct KbucketIter<'a> {
    pos_b: usize,
    pos_pn: usize,
    buckets: &'a [Box<Bucket>],
}

impl<'a> Iterator for KbucketIter<'a> {
    type Item = &'a PackedNode;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos_b < self.buckets.len() {
            match self.buckets[self.pos_b].nodes.get(self.pos_pn) {
                Some(s) => {
                    self.pos_pn += 1;
                    Some(s)
                },
                None => {
                    self.pos_b += 1;
                    self.pos_pn = 0;
                    self.next()
                },
            }
        } else {
            None
        }
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

            let mut node = Bucket::new(Some(1));

            assert_eq!(true, node.try_add(&pk, &n1));
            assert_eq!(false, node.try_add(&pk, &n2));

            // updating node
            assert_eq!(true, node.try_add(&pk, &n1));
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

            let mut kbucket = Kbucket::new(g.gen(), &pk);

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
        fn with_pk(a: u64, b: u64, c: u64, d: u64, buckets: u8) {
            let pk = nums_to_pk(a, b, c, d);
            let kbucket = Kbucket::new(buckets, &pk);
            assert_eq!(buckets, kbucket.size());
            assert_eq!(pk, kbucket.pk);
        }
        quickcheck(with_pk as fn(u64, u64, u64, u64, u8));
    }

    // Kbucket::size()

    #[test]
    fn dht_kbucket_size_test() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);

        let k0 = Kbucket::new(0, &pk);
        assert_eq!(0, k0.size());

        let k1 = Kbucket::new(1, &pk);
        assert_eq!(1, k1.size());

        let k255 = Kbucket::new(255, &pk);
        assert_eq!(255, k255.size());
    }

    // Kbucket::try_add()

    #[test]
    fn dht_kbucket_try_add_test() {
        fn with_pns(pns: Vec<PackedNode>, n: u8, p1: u64, p2: u64, p3: u64, p4: u64) {
            let pk = nums_to_pk(p1, p2, p3, p4);
            let mut kbucket = Kbucket::new(n, &pk);
            for node in pns {
                // result may vary, so discard it
                // TODO: can be done better?
                kbucket.try_add(&node);
            }
        }
        quickcheck(with_pns as fn(Vec<PackedNode>, u8, u64, u64, u64, u64));
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

            let mut kbucket = Kbucket::new(KBUCKET_MAX_ENTRIES, &pk);

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
            let pk = nums_to_pk(a, b, c, d);
            assert!(kb.get_closest(&pk).len() <= 4);
            assert_eq!(kb.get_closest(&pk), kb.get_closest(&pk));
        }
        quickcheck(with_kbucket as fn(Kbucket, u64, u64, u64, u64));


        fn with_nodes(n1: PackedNode, n2: PackedNode, n3: PackedNode,
                        n4: PackedNode, a: u64, b: u64, c: u64, d: u64) {

            let pk = nums_to_pk(a, b, c, d);
            let mut kbucket = Kbucket::new(::std::u8::MAX, &pk);

            // check whether number of correct nodes that are returned is right
            let correctness = |should, kbc: &Kbucket| {
                assert_eq!(kbc.get_closest(&pk), kbc.get_closest(&kbc.pk));

                let got_nodes = kbc.get_closest(&pk);
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

            let mut kbucket = Kbucket::new(KBUCKET_MAX_ENTRIES, &base_pk);

            let addr = Ipv4Addr::new(0, 0, 0, 0);
            let saddr = SocketAddrV4::new(addr, 0);

            let n0_base_pk = PackedNode::new(false, SocketAddr::V4(saddr), &base_pk);
            assert!(!kbucket.try_add(&n0_base_pk));
            kbucket.remove(&base_pk);

            pk_bytes[5] = 1;
            let pk1 = PublicKey(pk_bytes);
            let n1 = PackedNode::new(false, SocketAddr::V4(saddr), &pk1);

            pk_bytes[10] = 2;
            let pk2 = PublicKey(pk_bytes);
            let n2 = PackedNode::new(false, SocketAddr::V4(saddr), &pk2);

            pk_bytes[14] = 4;
            let pk3 = PublicKey(pk_bytes);
            let n3 = PackedNode::new(false, SocketAddr::V4(saddr), &pk3);

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
        fn kbucket_contains_test(n: u8, pns: Vec<PackedNode>) -> TestResult {
            if pns.is_empty() { return TestResult::discard() }

            let (pk, _) = gen_keypair();
            let mut kbucket = Kbucket::new(n, &pk);
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
        fn kbucket_can_add_test(n: u8, pns: Vec<PackedNode>) -> TestResult {
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
                pk: pk,
                buckets: vec![Box::new(Bucket::new(Some(1))); n as usize],
            };

            for node in &pns {
                if kbucket.try_add(node) {
                    let index = kbucket_index(&pk, &node.pk);
                    // none of nodes with the same index can be added
                    // to the kbucket
                    assert!(pns.iter()
                        .filter(|pn| kbucket_index(&pk, &pn.pk) == index)
                        .all(|pn| !kbucket.can_add(&pn.pk)));
                }
            }

            TestResult::passed()
        }
    }

    // KbucketIter::next()

    quickcheck! {
        fn kbucket_iter_next_test(n: u8, pns: Vec<PackedNode>) -> () {
            let (pk, _) = gen_keypair();
            let mut kbucket = Kbucket::new(n, &pk);
            // empty always returns None
            assert!(kbucket.iter().next().is_none());

            for node in &pns {
                kbucket.try_add(node);
            }

            let mut expect = Vec::new();
            for bucket in &kbucket.buckets {
                for node in bucket.nodes.iter() {
                    expect.push(*node);
                }
            }

            let mut e_iter = expect.iter();
            let mut k_iter = kbucket.iter();
            loop {
                let enext = e_iter.next();
                let knext = k_iter.next();
                assert_eq!(enext, knext);
                if enext.is_none() {
                    break;
                }
            }
        }
    }
}
