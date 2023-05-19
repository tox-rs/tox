use std::time::{Duration, Instant};

use crate::dht::server::Server as DhtServer;
use crate::onion::client::nodes_pool::*;
use crate::onion::client::onion_path::*;
use crate::onion::client::TIME_TO_STABLE;
use crate::relay::client::Connections as TcpConnections;
use crate::time::*;
use rand::{thread_rng, Rng};
use tox_packet::dht::packed_node::PackedNode;

/// Onion path is considered invalid after this number of unsuccessful attempts
/// to use it.
const ONION_PATH_MAX_NO_RESPONSE_USES: u32 = 4;

/// Maximum number of onion path that can be used at the same time.
pub const NUMBER_ONION_PATHS: usize = 6;

/// Timeout for path we haven't received any response from.
const ONION_PATH_FIRST_TIMEOUT: Duration = Duration::from_secs(4);

/// Timeout for path we received at least one response from.
const ONION_PATH_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time for path being used.
const ONION_PATH_MAX_LIFETIME: Duration = Duration::from_secs(1200);

/// Onion path that is stored for later usage.
#[derive(Clone)]
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
            ONION_PATH_FIRST_TIMEOUT
        } else {
            ONION_PATH_TIMEOUT
        };

        self.attempts >= ONION_PATH_MAX_NO_RESPONSE_USES && clock_elapsed(self.last_used) >= timeout
            || clock_elapsed(self.creation_time) >= ONION_PATH_MAX_LIFETIME
    }

    /// Path is considered stable after `TIME_TO_STABLE` since it was
    /// added to a close list if we receive responses from it.
    pub fn is_stable(&self) -> bool {
        clock_elapsed(self.creation_time) >= TIME_TO_STABLE
            && (self.attempts == 0 || clock_elapsed(self.last_used) < ONION_PATH_TIMEOUT)
    }

    /// Mark this path each time it was used to send request.
    pub fn use_path(&mut self) {
        self.last_used = clock_now();
        self.attempts += 1;
    }
}

/// Pool of random onion paths.
#[derive(Clone)]
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

    /// Get a random onion path. Can be either one of existent paths or newly
    /// generated. If we are not connected to DHT the first node from this path
    /// will be a TCP node.
    pub async fn random_path(
        &mut self,
        dht: &DhtServer,
        tcp_connections: &TcpConnections,
        friend: bool,
    ) -> Option<OnionPath> {
        let paths = if friend {
            &mut self.friend_paths
        } else {
            &mut self.self_paths
        };

        paths.retain(|stored_path| !stored_path.is_timed_out());

        let path_number = thread_rng().gen_range(0..NUMBER_ONION_PATHS);
        if let Some(stored_path) = paths.get_mut(path_number) {
            stored_path.use_path();
            return Some(stored_path.path.clone());
        }

        let path = if dht.is_connected().await {
            self.path_nodes.udp_path()
        } else if let Some(relay) = tcp_connections.get_random_relay().await {
            self.path_nodes.tcp_path(relay)
        } else {
            None
        };

        if let Some(path) = path {
            let path_id = path.id();
            if let Some(stored_path) = paths.iter_mut().find(|stored_path| stored_path.path.id() == path_id) {
                stored_path.use_path();
            } else {
                let stored_path = StoredOnionPath::new(path.clone());
                paths.push(stored_path);
            }
            Some(path)
        } else {
            None
        }
    }

    /// Get path by its `OnionPathId`. If there is no path with such id a new
    /// path will be generated.
    pub async fn get_or_random_path(
        &mut self,
        dht: &DhtServer,
        tcp_connections: &TcpConnections,
        path_id: OnionPathId,
        friend: bool,
    ) -> Option<OnionPath> {
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
            self.random_path(dht, tcp_connections, friend).await
        }
    }

    /// Get `StoredOnionPath` by its `OnionPathId`.
    pub fn get_stored_path(&self, path_id: OnionPathId, friend: bool) -> Option<&StoredOnionPath> {
        let paths = if friend { &self.friend_paths } else { &self.self_paths };

        paths
            .iter()
            .find(|stored_path| stored_path.path.id() == path_id)
            .filter(|stored_path| !stored_path.is_timed_out())
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
                self.path_nodes
                    .put(PackedNode::new(node.saddr, node.public_key.clone()));
            }
        }
    }
}

impl Default for PathsPool {
    fn default() -> Self {
        PathsPool::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crypto_box::SecretKey;
    use futures::channel::mpsc;

    macro_rules! paths_pool_tests {
        ($mod:ident, $friends:expr, $paths:ident) => {
            mod $mod {
                use super::*;

                #[tokio::test]
                async fn random_path_stored() {
                    let mut rng = thread_rng();
                    let dht_sk = SecretKey::generate(&mut rng);
                    let dht_pk = dht_sk.public_key();
                    let (udp_tx, _udp_rx) = mpsc::channel(1);
                    let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
                    let dht = DhtServer::new(udp_tx, dht_pk.clone(), dht_sk.clone());
                    let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
                    let mut paths_pool = PathsPool::new();
                    for _ in 0..NUMBER_ONION_PATHS {
                        let node_1 = PackedNode::new(
                            "127.0.0.1:12345".parse().unwrap(),
                            SecretKey::generate(&mut rng).public_key(),
                        );
                        let node_2 = PackedNode::new(
                            "127.0.0.1:12346".parse().unwrap(),
                            SecretKey::generate(&mut rng).public_key(),
                        );
                        let node_3 = PackedNode::new(
                            "127.0.0.1:12347".parse().unwrap(),
                            SecretKey::generate(&mut rng).public_key(),
                        );
                        let path = OnionPath::new(
                            [node_1.clone(), node_2.clone(), node_3.clone()],
                            OnionPathType::Udp,
                        );
                        paths_pool.path_nodes.put(node_1);
                        paths_pool.path_nodes.put(node_2);
                        paths_pool.path_nodes.put(node_3);
                        paths_pool.$paths.push(StoredOnionPath::new(path));
                    }

                    assert_eq!(paths_pool.$paths.len(), NUMBER_ONION_PATHS);
                    let path = paths_pool
                        .random_path(&dht, &tcp_connections, $friends)
                        .await
                        .unwrap();
                    assert_eq!(paths_pool.$paths.len(), NUMBER_ONION_PATHS);
                    assert!(paths_pool
                        .$paths
                        .iter()
                        .any(|stored_path| stored_path.path.id() == path.id()));
                }

                #[tokio::test]
                async fn random_path_new_udp_random() {
                    let mut rng = thread_rng();
                    let dht_sk = SecretKey::generate(&mut rng);
                    let dht_pk = dht_sk.public_key();
                    let (udp_tx, _udp_rx) = mpsc::channel(1);
                    let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
                    let dht = DhtServer::new(udp_tx, dht_pk.clone(), dht_sk.clone());
                    // make DHT connected so that we will build UDP onion paths
                    dht.add_node(PackedNode::new(
                        "127.0.0.1:12345".parse().unwrap(),
                        SecretKey::generate(&mut rng).public_key(),
                    ))
                    .await;
                    let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
                    let mut paths_pool = PathsPool::new();
                    for _ in 0..MIN_NODES_POOL_SIZE {
                        let node = PackedNode::new(
                            "127.0.0.1:12345".parse().unwrap(),
                            SecretKey::generate(&mut rng).public_key(),
                        );
                        paths_pool.path_nodes.put(node);
                    }

                    let path = paths_pool
                        .random_path(&dht, &tcp_connections, $friends)
                        .await
                        .unwrap();
                    for i in 0..3 {
                        assert_eq!(
                            path.nodes[i].public_key,
                            paths_pool.$paths[0].path.nodes[i].public_key
                        );
                    }
                    assert_eq!(path.path_type, OnionPathType::Udp);
                }

                #[tokio::test]
                async fn random_path_new_tcp_random() {
                    let mut rng = thread_rng();
                    let dht_sk = SecretKey::generate(&mut rng);
                    let dht_pk = dht_sk.public_key();
                    let (udp_tx, _udp_rx) = mpsc::channel(1);
                    let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
                    let dht = DhtServer::new(udp_tx, dht_pk.clone(), dht_sk.clone());
                    let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
                    // add a relay that will be used as first node for onion path
                    let (_relay_incoming_rx, _relay_outgoing_rx, relay_pk) = tcp_connections.add_client().await;
                    let mut paths_pool = PathsPool::new();
                    for _ in 0..MIN_NODES_POOL_SIZE {
                        let node = PackedNode::new(
                            "127.0.0.1:12345".parse().unwrap(),
                            SecretKey::generate(&mut rng).public_key(),
                        );
                        paths_pool.path_nodes.put(node);
                    }

                    let path = paths_pool
                        .random_path(&dht, &tcp_connections, $friends)
                        .await
                        .unwrap();
                    for i in 0..3 {
                        assert_eq!(
                            path.nodes[i].public_key,
                            paths_pool.$paths[0].path.nodes[i].public_key
                        );
                    }
                    assert_eq!(path.nodes[0].public_key, relay_pk);
                    assert_eq!(path.path_type, OnionPathType::Tcp);
                }

                #[tokio::test]
                async fn get_or_random_path_stored() {
                    let mut rng = thread_rng();
                    let dht_sk = SecretKey::generate(&mut rng);
                    let dht_pk = dht_sk.public_key();
                    let (udp_tx, _udp_rx) = mpsc::channel(1);
                    let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
                    let dht = DhtServer::new(udp_tx, dht_pk.clone(), dht_sk.clone());
                    let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
                    let mut paths_pool = PathsPool::new();
                    let node_1 = PackedNode::new(
                        "127.0.0.1:12345".parse().unwrap(),
                        SecretKey::generate(&mut rng).public_key(),
                    );
                    let node_2 = PackedNode::new(
                        "127.0.0.1:12346".parse().unwrap(),
                        SecretKey::generate(&mut rng).public_key(),
                    );
                    let node_3 = PackedNode::new(
                        "127.0.0.1:12347".parse().unwrap(),
                        SecretKey::generate(&mut rng).public_key(),
                    );
                    let path = OnionPath::new([node_1, node_2, node_3], OnionPathType::Udp);
                    paths_pool.$paths.push(StoredOnionPath::new(path.clone()));

                    let result_path = paths_pool
                        .get_or_random_path(&dht, &tcp_connections, path.id(), $friends)
                        .await
                        .unwrap();
                    for i in 0..3 {
                        assert_eq!(result_path.nodes[i].public_key, path.nodes[i].public_key);
                    }
                    assert_eq!(
                        paths_pool.$paths[0].attempts,
                        ONION_PATH_MAX_NO_RESPONSE_USES / 2 + 1
                    );
                }

                #[tokio::test]
                async fn get_or_random_path_new_udp_random() {
                    let mut rng = thread_rng();
                    let dht_sk = SecretKey::generate(&mut rng);
                    let dht_pk = dht_sk.public_key();
                    let (udp_tx, _udp_rx) = mpsc::channel(1);
                    let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
                    let dht = DhtServer::new(udp_tx, dht_pk.clone(), dht_sk.clone());
                    // make DHT connected so that we will build UDP onion paths
                    dht.add_node(PackedNode::new(
                        "127.0.0.1:12345".parse().unwrap(),
                        SecretKey::generate(&mut rng).public_key(),
                    ))
                    .await;
                    let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
                    let mut paths_pool = PathsPool::new();
                    for _ in 0..MIN_NODES_POOL_SIZE {
                        let node = PackedNode::new(
                            "127.0.0.1:12345".parse().unwrap(),
                            SecretKey::generate(&mut rng).public_key(),
                        );
                        paths_pool.path_nodes.put(node);
                    }

                    let path_id = OnionPathId {
                        keys: [
                            SecretKey::generate(&mut rng).public_key(),
                            SecretKey::generate(&mut rng).public_key(),
                            SecretKey::generate(&mut rng).public_key(),
                        ],
                        path_type: OnionPathType::Udp,
                    };
                    let path = paths_pool
                        .get_or_random_path(&dht, &tcp_connections, path_id.clone(), $friends)
                        .await
                        .unwrap();
                    assert_ne!(path.id(), path_id);
                    for i in 0..3 {
                        assert_eq!(
                            path.nodes[i].public_key,
                            paths_pool.$paths[0].path.nodes[i].public_key
                        );
                    }
                    assert_eq!(path.path_type, OnionPathType::Udp);
                }

                #[tokio::test]
                async fn get_or_random_path_new_tcp_random() {
                    let mut rng = thread_rng();
                    let dht_sk = SecretKey::generate(&mut rng);
                    let dht_pk = dht_sk.public_key();
                    let (udp_tx, _udp_rx) = mpsc::channel(1);
                    let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
                    let dht = DhtServer::new(udp_tx, dht_pk.clone(), dht_sk.clone());
                    let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
                    // add a relay that will be used as first node for onion path
                    let (_relay_incoming_rx, _relay_outgoing_rx, relay_pk) = tcp_connections.add_client().await;
                    let mut paths_pool = PathsPool::new();
                    for _ in 0..MIN_NODES_POOL_SIZE {
                        let node = PackedNode::new(
                            "127.0.0.1:12345".parse().unwrap(),
                            SecretKey::generate(&mut rng).public_key(),
                        );
                        paths_pool.path_nodes.put(node);
                    }

                    let path_id = OnionPathId {
                        keys: [
                            SecretKey::generate(&mut rng).public_key(),
                            SecretKey::generate(&mut rng).public_key(),
                            SecretKey::generate(&mut rng).public_key(),
                        ],
                        path_type: OnionPathType::Tcp,
                    };
                    let path = paths_pool
                        .get_or_random_path(&dht, &tcp_connections, path_id.clone(), $friends)
                        .await
                        .unwrap();
                    assert_ne!(path.id(), path_id);
                    for i in 0..3 {
                        assert_eq!(
                            path.nodes[i].public_key,
                            paths_pool.$paths[0].path.nodes[i].public_key
                        );
                    }
                    assert_eq!(path.nodes[0].public_key, relay_pk);
                    assert_eq!(path.path_type, OnionPathType::Tcp);
                }

                #[test]
                fn get_stored_path() {
                    let mut rng = thread_rng();
                    let mut paths_pool = PathsPool::new();
                    let node_1 = PackedNode::new(
                        "127.0.0.1:12345".parse().unwrap(),
                        SecretKey::generate(&mut rng).public_key(),
                    );
                    let node_2 = PackedNode::new(
                        "127.0.0.1:12346".parse().unwrap(),
                        SecretKey::generate(&mut rng).public_key(),
                    );
                    let node_3 = PackedNode::new(
                        "127.0.0.1:12347".parse().unwrap(),
                        SecretKey::generate(&mut rng).public_key(),
                    );
                    let path = OnionPath::new([node_1, node_2, node_3], OnionPathType::Udp);
                    let path_id = path.id();
                    let stored_path = StoredOnionPath::new(path);
                    paths_pool.$paths.push(stored_path.clone());
                    let result_path = paths_pool.get_stored_path(path_id, $friends).unwrap();
                    for i in 0..3 {
                        assert_eq!(
                            result_path.path.nodes[i].public_key,
                            stored_path.path.nodes[i].public_key
                        );
                    }
                    assert_eq!(result_path.creation_time, stored_path.creation_time);
                }
            }
        };
    }

    paths_pool_tests!(self_tests, false, self_paths);
    paths_pool_tests!(friends_tests, true, friend_paths);
}
