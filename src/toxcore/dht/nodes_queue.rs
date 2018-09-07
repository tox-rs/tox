/*! The implementation of nodes priority queue based on distance between node's
`PublicKey` and some base `PublicKey`.
*/

use std::net::SocketAddr;

use toxcore::crypto_core::*;
use toxcore::dht::kbucket::*;
use toxcore::dht::packed_node::*;

/** `NodesQueue` holds `PackedNode`s that are close to a some `PublicKey`.

Number of nodes it can contain is set during creation.

If `NodesQueue` is full farther nodes will be evicted when adding a closer node.

The difference between `NodesQueue` and `Bucket` structs is that `Bucket` stores
`DhtNode` with a lot of additional info, uses this info to evict bad nodes and
has additional parameter for eviction strategy.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodesQueue {
    /// Amount of nodes it can hold.
    capacity: u8,
    /// Nodes that the queue contains, sorted by distance to PK.
    nodes: Vec<PackedNode>
}

impl NodesQueue {
    /** Create a new `NodesQueue` to store nodes close to the `PublicKey`.

    Can hold up to `capacity` nodes.
    */
    pub fn new(capacity: u8) -> NodesQueue {
        NodesQueue {
            capacity,
            nodes: Vec::with_capacity(capacity as usize),
        }
    }

    /// Get address of node by it's `PublicKey`.
    pub fn get_saddr(&self, base_pk: &PublicKey, pk: &PublicKey) -> Option<SocketAddr> {
        self.nodes.binary_search_by(|n| base_pk.distance(&n.pk, pk)).ok()
            .map(|node_index| self.nodes[node_index].saddr)
    }

    /** Try to add [`PackedNode`] to the queue.

    - If the [`PackedNode`] with given `PublicKey` is already in the `Bucket`,
      its address will be updated.
    - If the queue is not full, node is appended.
    - If the queue is full, node's closeness is compared to nodes already in
      the queue, and if it's closer than some node, it prepends that node, and
      last node is removed from the list.
    - If the node being added is farther away than the nodes in the bucket, it
      isn't added and `false` is returned.

    Note that you must pass the same `base_pk` each call or the internal
    state will be undefined.

    Returns `true` if node was added or updated, `false` otherwise.

    [`PackedNode`]: ../packed_node/struct.PackedNode.html
    */
    pub fn try_add(&mut self, base_pk: &PublicKey, new_node: &PackedNode) -> bool {
        match self.nodes.binary_search_by(|n| base_pk.distance(&n.pk, &new_node.pk)) {
            Ok(index) => {
                self.nodes[index].saddr = new_node.saddr;
                true
            },
            Err(index) if index == self.nodes.len() => {
                if self.is_full() {
                    false
                } else {
                    self.nodes.push(*new_node);
                    true
                }
            },
            Err(index) => {
                if self.is_full() {
                    self.nodes.pop();
                }
                self.nodes.insert(index, *new_node);
                true
            },
        }
    }

    /** Remove [`PackedNode`] with given PK from the queue.

    Note that you must pass the same `base_pk` each call or the internal
    state will be undefined. Also `base_pk` must be equal to `base_pk` you added
    a node with.

    If there's no [`PackedNode`] with given PK, nothing is being done.

    [`PackedNode`]: ../packed_node/struct.PackedNode.html
    */
    pub fn remove(&mut self, base_pk: &PublicKey, node_pk: &PublicKey) -> Option<PackedNode> {
        match self.nodes.binary_search_by(|n| base_pk.distance(&n.pk, node_pk)) {
            Ok(index) => Some(self.nodes.remove(index)),
            Err(_) => {
                trace!("No PackedNode to remove with PK: {:?}", node_pk);
                None
            }
        }
    }

    /// Check if node with given PK is in the queue.
    pub fn contains(&self, base_pk: &PublicKey, pk: &PublicKey) -> bool {
        self.nodes.binary_search_by(|n| base_pk.distance(&n.pk, pk)).is_ok()
    }

    /// Get the capacity of the queue.
    pub fn capacity(&self) -> usize {
        self.capacity as usize
    }

    /** Check if the queue is empty.

    Returns `true` if there are no nodes in the queue, `false`
    otherwise.
    */
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /** Check if the queue is full.

    Returns `true` if there is no free space in the queue, `false`
    otherwise.
    */
    pub fn is_full(&self) -> bool {
        self.nodes.len() == self.capacity()
    }

    /** Check whether a [`PackedNode`] can be added to the queue.

    Returns `true` in one of the next conditions:
      - The queue where node could be placed is not full and node is not
        already in the queue
      - The queue where node could be placed is full but node can evict a
        farther node
      - Node is already in the queue but has different address

    Otherwise `false` is returned.

    [`PackedNode`]: ./struct.PackedNode.html
    */
    pub fn can_add(&self, base_pk: &PublicKey, new_node: &PackedNode) -> bool {
        match self.nodes.binary_search_by(|n| base_pk.distance(&n.pk, &new_node.pk)) {
            Ok(index) => self.nodes[index].saddr != new_node.saddr,
            Err(index) if index == self.nodes.len() => !self.is_full(),
            Err(_index) => true,
        }
    }

    /// Create iterator over `PackedNode`s. Nodes that this iterator produces
    /// are sorted by distance to a base `PublicKey` (in ascending order).
    pub fn iter(&self) -> impl Iterator<Item = &PackedNode> {
        self.nodes.iter()
    }
}

impl Into<Vec<PackedNode>> for NodesQueue {
    fn into(self) -> Vec<PackedNode> {
        self.nodes
    }
}
