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

use toxcore::crypto_core::*;
use toxcore::dht_new::packet::PackedNode;
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

    for byte in 0..PUBLICKEYBYTES {
        for bit in 0..8 {
            let shift = 7 - bit;
            if (own_pk[byte] >> shift) & 0b1 != (other_pk[byte] >> shift) & 0b1 {
                return Some((byte * 8 + bit) as u8)
            }
        }
    }
    None  // PKs are equal
}

/// Trait for functionality get `PublicKey` from PackedNode.
pub trait GetPk {
    /// Get an IP address from the `PackedNode`.
    fn pk(&self) -> &PublicKey;
}

impl GetPk for PackedNode {
    /// Get an IP address from the `PackedNode`.
    fn pk(&self) -> &PublicKey {
        trace!(target: "PackedNode", "Getting PK from PackedNode.");
        trace!("With address: {:?}", self);
        &self.pk
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

    /**
    Try to get position of [`PackedNode`] in the bucket by PK. Used in
    tests to check whether a `PackedNode` was added or removed.

    This method uses linear search as the simplest one.

    Returns Some(index) if it was found.
    Returns None if there is no a `PackedNode` with the given PK.

    [`PackedNode`]: ./struct.PackedNode.html
    */
    #[cfg(test)]
    fn find(&self, pk: &PublicKey) -> Option<usize> {
        for (n, node) in self.iter().enumerate() {
            if node.pk() == pk {
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

        match self.nodes.binary_search_by(|n| base_pk.distance(n.pk(), new_node.pk())) {
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
        match self.nodes.binary_search_by(|n| base_pk.distance(n.pk(), node_pk) ) {
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
        self.iter().any(|n| n.pk() == pk)
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

    /// Returns an iterator over contained [`PackedNode`]
    /// (./struct.PackedNode.html)s.
    pub fn iter(&self) -> BucketIter {
        BucketIter { iter: self.nodes.iter() }
    }
}

/// Iterator over `Bucket`.
pub struct BucketIter<'a> {
    iter: ::std::slice::Iter<'a, PackedNode>,
}

impl<'a> Iterator for BucketIter<'a> {
    type Item = &'a PackedNode;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

/**
Equivalent to calling [`Bucket::new()`] with `None`:

```
# use tox::toxcore::dht::Bucket;
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

    /// Get the PK of the Kbucket. Used in tests only
    #[cfg(test)]
    pub fn pk(&self) -> PublicKey {
        self.pk
    }

    /**
    Try to get position of [`PackedNode`] in the kbucket by PK. Used in
    tests to check whether a `PackedNode` was added or removed.

    This method uses quadratic search as the simplest one.

    Returns `Some(bucket_index, node_index)` if it was found.
    Returns `None` if there is no a [`PackedNode`] with the given PK.

    [`PackedNode`]: ./struct.PackedNode.html
    */
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

        match self.bucket_index(node.pk()) {
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
            match self.buckets[self.pos_b].iter().nth(self.pos_pn) {
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
