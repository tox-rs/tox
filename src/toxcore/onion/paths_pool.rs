use std::time::{Duration, Instant};

use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packed_node::PackedNode;
use crate::toxcore::onion::nodes_pool::*;
use crate::toxcore::onion::onion_path::*;
use crate::toxcore::time::*;

/// Onion path is considered invalid after this number of unsuccessful attempts
/// to use it.
const ONION_PATH_MAX_NO_RESPONSE_USES: u32 = 4;

/// Maximum number of onion path that can be used at the same time.
const NUMBER_ONION_PATHS: usize = 6;

/// Timeout for path we haven't received any response from.
const ONION_PATH_FIRST_TIMEOUT: u64 = 4;

/// Timeout for path we received at least one response from.
const ONION_PATH_TIMEOUT: u64 = 10;

/// Maximum time for path being used.
const ONION_PATH_MAX_LIFETIME: u64 = 1200;

/// Onion path that is stored for later usage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredOnionPath {
    /// Onion path.
    pub path: OnionPath,
    /// Time when this path was created.
    pub creation_time: Instant,
    /// Time when this path was used to send an onion packet.
    pub last_used: Instant,
    /// Time when this path was successfully used i.e. we received response via
    /// it.
    pub last_success: Option<Instant>,
    /// How many times we attempted to use this path without receiving a
    /// response.
    pub attempts: u32,
}

impl StoredOnionPath {
    /// Create new `StoredOnionPath`.
    pub fn new(path: OnionPath) -> Self {
        let now = clock_now();
        StoredOnionPath {
            path,
            creation_time: now,
            last_used: now,
            last_success: None,
            attempts: ONION_PATH_MAX_NO_RESPONSE_USES / 2,
        }
    }

    /// Update last success time and attempts number.
    pub fn update_success(&mut self) {
        self.last_success = Some(clock_now());
        self.attempts = 0;
    }

    /// Check if we never received a response from this path.
    pub fn is_new(&self) -> bool {
        self.last_success.is_none()
    }

    /// Check if this path is timed out.
    pub fn is_timed_out(&self) -> bool {
        let timeout = if self.is_new() {
            Duration::from_secs(ONION_PATH_FIRST_TIMEOUT)
        } else {
            Duration::from_secs(ONION_PATH_TIMEOUT)
        };

        self.attempts >= ONION_PATH_MAX_NO_RESPONSE_USES && clock_elapsed(self.last_used) >= timeout ||
            clock_elapsed(self.creation_time) >= Duration::from_secs(ONION_PATH_MAX_LIFETIME)
    }

    pub fn use_path(&mut self) {
        self.last_used = clock_now();
        self.attempts += 1;
    }
}

/// Pool of random onion paths.
#[derive(Clone, Debug)]
pub struct PathsPool {
    /// Nodes cache for building random onion paths.
    pub path_nodes: NodesPool,
    /// List of used random onion paths for ourselves announcing.
    self_paths: Vec<StoredOnionPath>,
    /// List of used random onion paths for friends searching.
    friend_paths: Vec<StoredOnionPath>,
}

impl PathsPool {
    /// Create new `PathsPool`.
    pub fn new() -> Self {
        PathsPool {
            path_nodes: NodesPool::new(),
            self_paths: Vec::new(),
            friend_paths: Vec::new(),
        }
    }

    /// Get random path. Can be either one of existent paths or newly generated.
    pub fn random_path(&mut self, friend: bool) -> Option<OnionPath> {
        let paths = if friend {
            &mut self.friend_paths
        } else {
            &mut self.self_paths
        };

        paths.retain(|stored_path| !stored_path.is_timed_out());

        let path_number = random_limit_usize(NUMBER_ONION_PATHS);
        if path_number >= paths.len() {
            let node_1 = if let Some(node) = self.path_nodes.rand() {
                node
            } else {
                return None
            };
            let node_2 = if let Some(node) = self.path_nodes.rand() {
                node
            } else {
                return None
            };
            let node_3 = if let Some(node) = self.path_nodes.rand() {
                node
            } else {
                return None
            };
            let path_id = [node_1.pk, node_2.pk, node_3.pk];
            if let Some(stored_path) = paths.iter_mut().find(|stored_path| stored_path.path.id() == path_id) {
                stored_path.use_path();
                Some(stored_path.path.clone())
            } else {
                let path = OnionPath::new([node_1, node_2, node_3]);
                let stored_path = StoredOnionPath::new(path.clone());
                paths.push(stored_path);
                Some(path)
            }
        } else {
            paths[path_number].use_path();
            Some(paths[path_number].path.clone())
        }
    }

    /// Get `StoredOnionPath` by its `OnionPathId`.
    pub fn get_path(&mut self, path_id: OnionPathId, friend: bool) -> Option<OnionPath> {
        let paths = if friend {
            &mut self.friend_paths
        } else {
            &mut self.self_paths
        };

        let stored_path = paths
            .iter_mut()
            .find(|stored_path| stored_path.path.id() == path_id)
            .filter(|stored_path| !stored_path.is_timed_out());

        if let Some(stored_path) = stored_path {
            stored_path.use_path();
            Some(stored_path.path.clone())
        } else {
            self.random_path(friend)
        }
    }

    /// Update path's timers after receiving a response via it.
    pub fn set_timeouts(&mut self, path_id: OnionPathId, friend: bool) {
        let paths = if friend {
            &mut self.friend_paths
        } else {
            &mut self.self_paths
        };

        if let Some(path) = paths.iter_mut().find(|stored_path| stored_path.path.id() == path_id) {
            path.update_success();
            // re-add path nodes to the cache as they are still valid
            for node in &path.path.nodes {
                self.path_nodes.put(PackedNode::new(node.saddr, &node.public_key));
            }
        }
    }
}
