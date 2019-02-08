//! Nodes pool.

use std::collections::VecDeque;

use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packed_node::PackedNode;

/// Maximum number of nodes that onion can store for building random paths.
const MAX_PATH_NODES: usize = 32;

/// Nodes pool for building random onion paths.
#[derive(Clone, Debug, Eq, PartialEq)]
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
}
