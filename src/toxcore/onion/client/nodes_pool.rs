//! Nodes pool.

use std::collections::VecDeque;

use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packed_node::PackedNode;
use crate::toxcore::onion::client::onion_path::{OnionPath, OnionPathType};

/// Maximum number of nodes that onion can store for building random paths.
const MAX_PATH_NODES: usize = 32;

/// Minimum size of nodes pool to generate random path.
pub const MIN_NODES_POOL_SIZE: usize = 3;

/// Nodes pool for building random onion paths.
#[derive(Clone, Debug)]
pub struct NodesPool {
    // TODO: PackedNode contains SocketAddr which holds additional fields in
    // case of IPv6 - this can lead to the same node being added multiple times
    /// Nodes this cache contains.
    nodes: VecDeque<PackedNode>,
}

impl NodesPool {
    /// Create new `NodesPool`.
    pub fn new() -> Self {
        NodesPool {
            nodes: VecDeque::with_capacity(MAX_PATH_NODES),
        }
    }

    /// Put a new node to the cache.
    pub fn put(&mut self, node: PackedNode) {
        if self.nodes.contains(&node) {
            return;
        }

        if self.nodes.len() == MAX_PATH_NODES {
            self.nodes.pop_front();
        }

        self.nodes.push_back(node);
    }

    /// Get random node from the cache.
    pub fn rand(&self) -> Option<PackedNode> {
        let len = self.nodes.len();
        if len > 0 {
            Some(self.nodes[random_limit_usize(len)])
        } else {
            None
        }
    }

    /// The number of stored nodes in the pool.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Build new random onion path with first UDP node.
    pub fn udp_path(&self) -> Option<OnionPath> {
        if self.len() < MIN_NODES_POOL_SIZE {
            return None;
        }
        // non-empty nodes pool will always return some node
        let node_1 = self.rand().unwrap();
        let mut node_2;
        loop {
            node_2 = self.rand().unwrap();
            if node_2 != node_1 {
                break;
            }
        }
        let mut node_3;
        loop {
            node_3 = self.rand().unwrap();
            if node_3 != node_1 && node_3 != node_2 {
                break;
            }
        }
        Some(OnionPath::new([node_1, node_2, node_3], OnionPathType::UDP))
    }

    /// Build new random onion path with first TCP node.
    pub fn tcp_path(&self, node_1: PackedNode) -> Option<OnionPath> {
        if self.len() < MIN_NODES_POOL_SIZE - 1 {
            return None;
        }
        // non-empty nodes pool will always return some node
        let node_2 = self.rand().unwrap();
        let mut node_3;
        loop {
            node_3 = self.rand().unwrap();
            if node_3 != node_2 {
                break;
            }
        }
        Some(OnionPath::new([node_1, node_2, node_3], OnionPathType::TCP))
    }
}

impl Default for NodesPool {
    fn default() -> Self {
        NodesPool::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;

    #[test]
    fn new() {
        let nodes_pool = NodesPool::new();
        assert_eq!(nodes_pool.len(), 0);
    }

    #[test]
    fn default() {
        let nodes_pool = NodesPool::default();
        assert_eq!(nodes_pool.len(), 0);
    }

    #[test]
    fn put() {
        let mut nodes_pool = NodesPool::new();
        let node = PackedNode::new("127.0.0.1:33445".parse().unwrap(), &gen_keypair().0);
        nodes_pool.put(node);
        assert_eq!(nodes_pool.nodes[0], node);
    }

    #[test]
    fn put_already_exists() {
        let mut nodes_pool = NodesPool::new();
        let node = PackedNode::new("127.0.0.1:33445".parse().unwrap(), &gen_keypair().0);
        nodes_pool.put(node);
        nodes_pool.put(node);
        assert_eq!(nodes_pool.len(), 1);
    }

    #[test]
    fn put_max_nodes() {
        let mut nodes_pool = NodesPool::new();
        let addr = "127.0.0.1".parse().unwrap();
        for i in 0 .. MAX_PATH_NODES {
            let saddr = SocketAddr::new(addr, 33446 + i as u16);
            let node = PackedNode::new(saddr, &gen_keypair().0);
            nodes_pool.put(node);
        }
        assert_eq!(nodes_pool.nodes.len(), MAX_PATH_NODES);
        // adding one more node should evict the oldest node
        let node = PackedNode::new("127.0.0.1:33445".parse().unwrap(), &gen_keypair().0);
        nodes_pool.put(node);
        assert_eq!(nodes_pool.nodes.len(), MAX_PATH_NODES);
    }

    #[test]
    fn rand() {
        let mut nodes_pool = NodesPool::new();
        let node = PackedNode::new("127.0.0.1:33445".parse().unwrap(), &gen_keypair().0);
        nodes_pool.put(node);
        let node = PackedNode::new("127.0.0.1:33446".parse().unwrap(), &gen_keypair().0);
        nodes_pool.put(node);
        assert!(nodes_pool.rand().is_some());
    }

    #[test]
    fn rand_empty() {
        let nodes_pool = NodesPool::new();
        assert!(nodes_pool.rand().is_none());
    }
}
