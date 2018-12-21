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

The difference between `NodesQueue` and `Kbucket` structs is that `Kbucket` stores
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

    - If the [`PackedNode`] with given `PublicKey` is already in the `Kbucket`,
      its address will be updated.
    - If the queue is not full, node is appended.
    - If the queue is full, node's closeness is compared to nodes already in
      the queue, and if it's closer than some node, it prepends that node, and
      last node is removed from the list.
    - If the node being added is farther away than the nodes in the kbucket, it
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_add() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut queue = NodesQueue::new(8);

        for i in 0 .. 8 {
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + u16::from(i));
            let node = PackedNode::new(addr, &PublicKey([i + 2; PUBLICKEYBYTES]));
            assert!(queue.try_add(&pk, &node));
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
        assert!(!queue.try_add(&pk, &farther_node));
        // can add a new closer node
        assert!(queue.try_add(&pk, &closer_node));
        // can update a node
        assert!(queue.try_add(&pk, &existing_node));
    }

    #[test]
    fn can_add() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut queue = NodesQueue::new(8);

        for i in 0 .. 8 {
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + u16::from(i));
            let node = PackedNode::new(addr, &PublicKey([i + 2; PUBLICKEYBYTES]));
            assert!(queue.try_add(&pk, &node));
        }

        let closer_node = PackedNode::new(
            "1.2.3.5:12345".parse().unwrap(),
            &PublicKey([1; PUBLICKEYBYTES])
        );
        let farther_node = PackedNode::new(
            "1.2.3.5:12346".parse().unwrap(),
            &PublicKey([10; PUBLICKEYBYTES])
        );
        let existing_node_1 = PackedNode::new(
            "1.2.3.4:12345".parse().unwrap(),
            &PublicKey([2; PUBLICKEYBYTES])
        );
        let existing_node_2 = PackedNode::new(
            "1.2.3.5:12347".parse().unwrap(),
            &PublicKey([2; PUBLICKEYBYTES])
        );

        // can't add a new farther node
        assert!(!queue.can_add(&pk, &farther_node));
        // can add a new closer node
        assert!(queue.can_add(&pk, &closer_node));
        // can't add the same node
        assert!(!queue.can_add(&pk, &existing_node_1));
        // can update a node
        assert!(queue.can_add(&pk, &existing_node_2));
    }

    #[test]
    fn remove() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut queue = NodesQueue::new(8);

        let node = PackedNode::new(
            "1.2.3.4:12345".parse().unwrap(),
            &PublicKey([1; PUBLICKEYBYTES])
        );

        // "removing" non-existent node
        assert!(queue.remove(&pk, &node.pk).is_none());
        assert!(queue.is_empty());

        assert!(queue.try_add(&pk, &node));

        assert!(!queue.is_empty());

        assert!(queue.remove(&pk, &node.pk).is_some());

        assert!(queue.is_empty());
    }

    #[test]
    fn is_empty() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut queue = NodesQueue::new(8);

        assert!(queue.is_empty());

        let node = PackedNode::new(
            "1.2.3.4:12345".parse().unwrap(),
            &PublicKey([1; PUBLICKEYBYTES])
        );

        assert!(queue.try_add(&pk, &node));

        assert!(!queue.is_empty());
    }

    #[test]
    fn get_saddr() {
        crypto_init().unwrap();
        let (pk, _) = gen_keypair();
        let mut queue = NodesQueue::new(8);

        let node_saddr = "127.0.0.1:33445".parse().unwrap();
        let node_pk = gen_keypair().0;

        let pn = PackedNode {
            pk: node_pk,
            saddr: node_saddr,
        };

        assert!(queue.try_add(&pk, &pn));
        assert_eq!(queue.get_saddr(&pk, &node_pk), Some(node_saddr));
    }

    #[test]
    fn contains() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut queue = NodesQueue::new(8);

        let node = PackedNode::new(
            "1.2.3.4:12345".parse().unwrap(),
            &PublicKey([1; PUBLICKEYBYTES])
        );

        assert!(!queue.contains(&pk, &node.pk));

        assert!(queue.try_add(&pk, &node));

        assert!(queue.contains(&pk, &node.pk));
    }

    #[test]
    fn capacity() {
        let queue = NodesQueue::new(8);

        assert_eq!(queue.capacity(), 8);
    }

    #[test]
    fn is_full() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut queue = NodesQueue::new(8);

        for i in 0 .. 8 {
            assert!(!queue.is_full());
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + u16::from(i));
            let node = PackedNode::new(addr, &PublicKey([i + 1; PUBLICKEYBYTES]));
            assert!(queue.try_add(&pk, &node));
        }

        assert!(queue.is_full());
    }

    #[test]
    fn iter() {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut queue = NodesQueue::new(8);

        for i in 0 .. 8 {
            let addr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + u16::from(i));
            let node = PackedNode::new(addr, &PublicKey([i + 1; PUBLICKEYBYTES]));
            assert!(queue.try_add(&pk, &node));
        }

        let nodes_1: Vec<PackedNode> = queue.iter().cloned().collect();
        let nodes_2: Vec<PackedNode> = queue.into();
        assert_eq!(nodes_1, nodes_2);
    }
}
