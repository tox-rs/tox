/*! TCP connections handling

TCP connections provides reliable connection to net_crypto via multiple TCP
relays to a friend. When a Tox client connects to a friend via TCP relay,
normally 3 redundant connections are established. One connection is used for
sending/receiving data, 2 others are backup. In toxcore maximum number of
redundant connections is 6. TCP connection can get into sleep mode. Getting
into sleep mode can occur when UDP connection is established, because Tox
prefers UDP over TCP. When established UDP connection is lost, TCP connections
are awaken.

*/

use tokio::sync::RwLock;

use std::collections::{hash_map, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::TryFutureExt;
use futures::channel::mpsc;

use tox_crypto::*;
use tox_packet::dht::packed_node::PackedNode;
use crate::relay::client::client::*;
use tox_packet::relay::*;
use crate::time::*;
use crate::relay::client::errors::*;
use failure::Fail;

/// The amount of maximum connections for each friend.
const MAX_FRIEND_TCP_CONNECTIONS: usize =  6;

/// The amount of recommended connections for each friend.
///   NOTE: Must be at most (MAX_FRIEND_TCP_CONNECTIONS / 2).
const RECOMMENDED_FRIEND_TCP_CONNECTIONS: usize =  MAX_FRIEND_TCP_CONNECTIONS / 2;

/// How many attempts to reconnect to the relay we should make before we
/// consider this relay unreachable and drop it.
const MAX_RECONNECTION_ATTEMPTS: u32 = 1;

const TCP_CONNECTION_ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(10);

/// How often `main_loop` should be run.
const CONNECTIONS_INTERVAL: Duration = Duration::from_secs(1);

/// Connection status shows whether a connection used or not.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NodeConnectionStatus {
    /// We are not connected to the node directly and need active relays to send
    /// packets to this node.
    TCP,
    /// We are connected to the node directly via UDP so all relays used only
    /// for this node connection can go to sleep.
    UDP,
}

/// Contains info about connection to a node via TCP relays.
#[derive(Debug, PartialEq, Clone)]
struct NodeConnection {
    /// Connection status shows whether a connection used or not.
    status: NodeConnectionStatus,
    /// List of relays we are connected to the node through.
    connections: HashSet<PublicKey>,
}

impl NodeConnection {
    /// Create new `NodeConnection` struct.
    fn new() -> NodeConnection {
        NodeConnection {
            status: NodeConnectionStatus::TCP,
            connections: HashSet::new(),
        }
    }

    /// Get an iterator over connected relays.
    fn clients<'c, 'a: 'c, 'b: 'c>(&'a self, clients: &'b HashMap<PublicKey, Client>) -> impl Iterator<Item = &'b Client> + 'c {
        self.connections
            .iter()
            .flat_map(move |relay_pk| clients.get(relay_pk).into_iter())
    }
}

/// TCP connections provides reliable connection to a friend via multiple TCP
/// relays.
#[derive(Clone)]
pub struct Connections {
    /// DHT `PublicKey`
    dht_pk: PublicKey,
    /// DHT `SecretKey`
    dht_sk: SecretKey,
    /// Sink for packets that should be handled somewhere else. `PublicKey` here
    /// belongs to TCP relay we received packet from.
    incoming_tx: mpsc::UnboundedSender<(PublicKey, IncomingPacket)>,
    /// List of TCP relays we are connected to. Key is a `PublicKey` of TCP
    /// relay.
    clients: Arc<RwLock<HashMap<PublicKey, Client>>>,
    /// List of DHT nodes we are connected to via TCP relays. Key is a
    /// `PublicKey` of DHT node.
    connections: Arc<RwLock<HashMap<PublicKey, NodeConnection>>>,
}

impl Connections {
    /// Create new TCP connections object.
    pub fn new(dht_pk: PublicKey, dht_sk: SecretKey, incoming_tx: mpsc::UnboundedSender<(PublicKey, IncomingPacket)>) -> Self {
        Connections {
            dht_pk,
            dht_sk,
            incoming_tx,
            clients: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add relay we are supposed to be connected to. These relays are necessary
    /// for initial connection so that we are able to find friends and to send
    /// them our relays. Later when more relays are received from our friends
    /// they should be added via `add_relay_connection` method.
    pub async fn add_relay_global(&self, relay_addr: SocketAddr, relay_pk: PublicKey) -> Result<(), ConnectionError> {
        if let hash_map::Entry::Vacant(vacant) = self.clients.write().await.entry(relay_pk) {
            let client = Client::new(relay_pk, relay_addr, self.incoming_tx.clone());
            vacant.insert(client.clone());
            client.spawn(self.dht_sk.clone(), self.dht_pk)
                .map_err(|e| e.context(ConnectionErrorKind::Spawn).into()).await
        } else {
            trace!("Attempt to add relay that already exists: {}", relay_addr);
            Ok(())
        }
    }

    /// Add relay that we received from our friend. This relay can be ignored if
    /// we already connected to this friend via at least
    /// `RECOMMENDED_FRIEND_TCP_CONNECTIONS` relays. Connection to our friend
    /// via this relay will be added as well.
    pub async fn add_relay_connection(&self, relay_addr: SocketAddr, relay_pk: PublicKey, node_pk: PublicKey) -> Result<(), ConnectionError> {
        let mut clients = self.clients.write().await;
        if let Some(client) = clients.get(&relay_pk) {
            self.add_connection_inner(client, node_pk).await
        } else {
            let mut connections = self.connections.write().await;
            let connection = connections.entry(node_pk).or_insert_with(NodeConnection::new);

            let connections_count = connection.connections.len();
            let mut online_connections_count = 0;
            for relay_pk in connection.connections.iter() {
                if let Some(client) = clients.get(relay_pk) {
                    if client.is_connection_online(node_pk).await {
                        online_connections_count += 1;
                    }
                }
            }

            if online_connections_count < RECOMMENDED_FRIEND_TCP_CONNECTIONS && connections_count < MAX_FRIEND_TCP_CONNECTIONS {
                let client = Client::new(relay_pk, relay_addr, self.incoming_tx.clone());
                clients.insert(relay_pk, client.clone());
                connection.connections.insert(relay_pk);
                client.add_connection(node_pk).await;
                client.spawn(self.dht_sk.clone(), self.dht_pk).await
                    .map_err(|e| e.context(ConnectionErrorKind::Spawn).into())
            } else {
                Ok(())
            }
        }
    }

    /// Add a connection to our friend via relay. It means that we will send
    /// `RouteRequest` packet to this relay and wait for the friend to become
    /// connected.
    pub async fn add_connection(&self, relay_pk: PublicKey, node_pk: PublicKey) -> Result<(), ConnectionError> {
        if let Some(client) = self.clients.read().await.get(&relay_pk) {
            self.add_connection_inner(client, node_pk).await
        } else {
            Err(ConnectionErrorKind::NoSuchRelay.into())
        }
    }

    /// Remove connection to a friend via relays.
    pub async fn remove_connection(&self, node_pk: PublicKey) -> Result<(), ConnectionError> {
        if let Some(connection) = self.connections.write().await.remove(&node_pk) {
            let clients = self.clients.read().await;
            for client in connection.clients(&clients) {
                client.remove_connection(node_pk).await.ok();
            }
            Ok(())
        } else {
            // TODO: what if we didn't receive relays from friend and delete him?
            Err(ConnectionErrorKind::NoConnection.into())
        }
    }

    /// Inner function to add a connection to our friend via relay.
    async fn add_connection_inner(&self, client: &Client, node_pk: PublicKey) -> Result<(), ConnectionError> {
        // TODO: check MAX_FRIEND_TCP_CONNECTIONS?
        let mut connections = self.connections.write().await;
        let connection = connections.entry(node_pk).or_insert_with(NodeConnection::new);
        connection.connections.insert(client.pk);

        if connection.status == NodeConnectionStatus::TCP && client.is_sleeping().await {
            // unsleep relay
            client.clone().spawn(self.dht_sk.clone(), self.dht_pk).await
                .map_err(|e| ConnectionError::from(e.context(ConnectionErrorKind::Spawn)))?;
        };

        client.add_connection(node_pk).await;

        Ok(())
    }

    /// Send `Data` packet to a node via one of the relays.
    pub async fn send_data(&self, node_pk: PublicKey, data: DataPayload) -> Result<(), ConnectionError> {
        let connections = self.connections.read().await;

        // send packet to the first relay only that can accept it
        // errors are ignored
        // TODO: return error if stream is exhausted?
        if let Some(connection) = connections.get(&node_pk) {
            let clients = self.clients.read().await;

            for c in connection.clients(&*clients) {
                let res = c.send_data(node_pk, data.clone()).await;

                if res.is_ok() { break }
            }
        }

        // TODO: send as OOB?
        Ok(())
    }

    /// Send `OobSend` packet to a node via relay with specified `PublicKey`.
    pub async fn send_oob(&self, relay_pk: PublicKey, node_pk: PublicKey, data: Vec<u8>) -> Result<(), ConnectionError> {
        let clients = self.clients.read().await;
        if let Some(client) = clients.get(&relay_pk) {
            client.send_oob(node_pk, data).await
                .map_err(|e| e.context(ConnectionErrorKind::SendTo).into())
        } else {
            Err(ConnectionErrorKind::NotConnected.into())
        }
    }

    /// Send `OnionRequest` packet to relay with specified `PublicKey`.
    pub async fn send_onion(&self, relay_pk: PublicKey, onion_request: OnionRequest) -> Result<(), ConnectionError> {
        let clients = self.clients.read().await;
        if let Some(client) = clients.get(&relay_pk) {
            client.send_onion(onion_request).await
                .map_err(|e| e.context(ConnectionErrorKind::SendTo).into())
        } else {
            Err(ConnectionErrorKind::NotConnected.into())
        }
    }

    /// Change status of connection to the node. Connections module need to know
    /// whether connection is used to be able to put to sleep relay connections.
    pub async fn set_connection_status(&self, node_pk: PublicKey, status: NodeConnectionStatus) -> Result<(), ConnectionError> {
        if let Some(connection) = self.connections.write().await.get_mut(&node_pk) {
            if status == NodeConnectionStatus::TCP && connection.status == NodeConnectionStatus::UDP {
                // unsleep clients
                let clients = self.clients.read().await;
                for client in connection.clients(&clients) {
                    client.clone().spawn(self.dht_sk.clone(), self.dht_pk).await
                        .map_err(|e| e.context(ConnectionErrorKind::Spawn))?;
                }
            };
            connection.status = status;
            Ok(())
        } else {
            Err(ConnectionErrorKind::NoSuchRelay.into())
        }
    }

    /// Get a random TCP relay we are connected to.
    pub async fn get_random_relay(&self) -> Option<PackedNode> {
        let mut relays = Vec::new();
        for client in self.clients.read().await.values() {
            if client.is_connected().await {
                relays.push(PackedNode::new(client.addr, &client.pk));
            }
        }

        if relays.is_empty() {
            None
        } else {
            Some(relays[random_limit_usize(relays.len())])
        }
    }

    /// Get up to `count` random TCP relays we are connected to.
    pub async fn get_random_relays(&self, count: u8) -> Vec<PackedNode> {
        let mut relays = Vec::new();
        for client in self.clients.read().await.values() {
            if client.is_connected().await {
                relays.push(PackedNode::new(client.addr, &client.pk));
            }
        }

        if relays.is_empty() {
            return Vec::new();
        }

        // TODO: shuffle relays instead
        let skip = random_limit_usize(relays.len());
        let take = (count as usize).min(relays.len());
        relays.into_iter().cycle().skip(skip).take(take).collect()
    }

    /// Main loop that should be run periodically. It removes unreachable and
    /// redundant relays, reconnects to relays if a connection was lost, puts
    /// relays to sleep if they are not used right now.
    async fn main_loop(&self) -> Result<(), ConnectionError> {
        let mut clients = self.clients.write().await;
        let mut connections = self.connections.write().await;

        // If we have at least one connected relay that means that our network
        // connection is fine. So if we can't connect to some relays we can
        // drop them.
        let mut connected = false;
        for client in clients.values() {
            if client.is_connected().await {
                connected = true;
                break;
            }
        }

        let mut to_remove = Vec::new();
        for (&pk, client) in clients.iter() {
            if client.is_disconnected().await {
                if connected && client.connection_attempts().await > MAX_RECONNECTION_ATTEMPTS {
                    to_remove.push(pk);
                } else {
                    client.clone().spawn(self.dht_sk.clone(), self.dht_pk).await
                        .map_err(|e| e.context(ConnectionErrorKind::Spawn))?;
                }
            }
        }

        for pk in to_remove {
            clients.remove(&pk);
        }

        // find out which relays are used right now
        let used_relays = connections.values()
            .filter(|connection| connection.status == NodeConnectionStatus::TCP)
            .flat_map(|connection| connection.connections.iter().cloned())
            .collect::<HashSet<_>>();

        // send to sleep not used right now relays
        for client in clients.values() {
            // only connected relays have connected_time
            if client.connected_time().await.map_or(
                false,
                |connected_time| clock_elapsed(connected_time) > TCP_CONNECTION_ANNOUNCE_TIMEOUT
            ) && !used_relays.contains(&client.pk) {
                client.sleep().await;
            }
        }

        // remove not used relays
        let mut clients_len = clients.len();
        let mut to_remove = Vec::new();
        for (&pk, client) in clients.iter() {
            if clients_len > RECOMMENDED_FRIEND_TCP_CONNECTIONS && client.connections_count().await == 0 {
                clients_len -= 1;
                client.disconnect().await;
                to_remove.push(pk);
            }
        }

        for pk in to_remove {
            clients.remove(&pk);
        }

        // remove deleted relays from connections
        for connection in connections.values_mut() {
            connection.connections.retain(|relay_pk| clients.contains_key(relay_pk));

            // TODO: remove connections if there are too many?
        }

        Ok(())
    }

    /// Run TCP periodical tasks. Result future will never be completed
    /// successfully.
    pub async fn run(&self) -> Result<(), ConnectionError> {
        let mut wakeups = tokio::time::interval(CONNECTIONS_INTERVAL);

        loop {
            wakeups.tick().await;

            self.main_loop().await?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use tox_binary_io::*;
    use tox_packet::dht::CryptoData;
    use tox_packet::ip_port::*;
    use crate::relay::client::client::tests::*;
    use tox_packet::relay::connection_id::ConnectionId;

    impl Connections {
        pub async fn add_client(&self) -> (mpsc::UnboundedReceiver<(PublicKey, IncomingPacket)>, mpsc::Receiver<Packet>, PublicKey) {
            let (incoming_rx, outgoing_rx, client) = create_client().await;
            let relay_pk = client.pk;
            self.clients.write().await.insert(client.pk, client);
            (incoming_rx, outgoing_rx, relay_pk)
        }

        pub async fn has_relay(&self, relay_pk: &PublicKey) -> bool {
            self.clients.read().await.contains_key(relay_pk)
        }

        pub async fn has_connection(&self, node_pk: &PublicKey) -> bool {
            self.connections.read().await.contains_key(node_pk)
        }
    }

    #[tokio::test]
    async fn add_relay_global() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let addr = "0.0.0.0:12347".parse().unwrap();
        let (relay_pk, _relay_sk) = gen_keypair();

        connections.add_relay_global(addr, relay_pk).await.unwrap();

        assert!(connections.clients.read().await.contains_key(&relay_pk));
    }

    #[tokio::test]
    async fn add_relay_global_exists() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx, _outgoing_rx, client) = create_client().await;
        let addr = client.addr;
        let relay_pk = client.pk;

        connections.clients.write().await.insert(relay_pk, client);

        // new connection shouldn't be spawned
        connections.add_relay_global(addr, relay_pk).await.unwrap();
    }

    #[tokio::test]
    async fn add_relay_connection() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let addr = "0.0.0.0:12347".parse().unwrap();
        let (relay_pk, _relay_sk) = gen_keypair();
        let (node_pk, _node_sk) = gen_keypair();

        connections.add_relay_connection(addr, relay_pk, node_pk).await.unwrap();

        let clients = connections.clients.read().await;
        let connections = connections.connections.read().await;

        assert!(clients.contains_key(&relay_pk));
        assert!(clients.get(&relay_pk).unwrap().has_connection(node_pk).await);

        assert!(connections.contains_key(&node_pk));
        assert_eq!(connections.get(&node_pk).unwrap().status, NodeConnectionStatus::TCP);
        assert!(connections.get(&node_pk).unwrap().connections.contains(&relay_pk));
    }

    #[tokio::test]
    async fn add_relay_connection_relay_exists() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx, _outgoing_rx, client) = create_client().await;
        let addr = client.addr;
        let relay_pk = client.pk;

        connections.clients.write().await.insert(relay_pk, client);

        let (node_pk, _node_sk) = gen_keypair();

        // new connection shouldn't be spawned
        connections.add_relay_connection(addr, relay_pk, node_pk).await.unwrap();

        let clients = connections.clients.read().await;
        let connections = connections.connections.read().await;

        assert!(clients.contains_key(&relay_pk));
        assert!(clients.get(&relay_pk).unwrap().has_connection(node_pk).await);

        assert!(connections.contains_key(&node_pk));
        assert_eq!(connections.get(&node_pk).unwrap().status, NodeConnectionStatus::TCP);
        assert!(connections.get(&node_pk).unwrap().connections.contains(&relay_pk));
    }

    #[tokio::test]
    async fn add_connection() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx, _outgoing_rx, client) = create_client().await;
        let relay_pk = client.pk;

        connections.clients.write().await.insert(relay_pk, client);

        let (node_pk, _node_sk) = gen_keypair();

        // new connection shouldn't be spawned
        connections.add_connection(relay_pk, node_pk).await.unwrap();

        let clients = connections.clients.read().await;
        let connections = connections.connections.read().await;

        assert!(clients.contains_key(&relay_pk));
        assert!(clients.get(&relay_pk).unwrap().has_connection(node_pk).await);

        assert!(connections.contains_key(&node_pk));
        assert_eq!(connections.get(&node_pk).unwrap().status, NodeConnectionStatus::TCP);
        assert!(connections.get(&node_pk).unwrap().connections.contains(&relay_pk));
    }

    #[tokio::test]
    async fn add_connection_no_relay() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (relay_pk, _relay_sk) = gen_keypair();
        let (node_pk, _node_sk) = gen_keypair();

        let error = connections.add_connection(relay_pk, node_pk).await.err().unwrap();
        assert_eq!(*error.kind(), ConnectionErrorKind::NoSuchRelay);
    }

    #[tokio::test]
    async fn remove_connection() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (node_pk, _node_sk) = gen_keypair();

        let (_incoming_rx, _outgoing_rx, client) = create_client().await;
        let relay_pk = client.pk;

        client.add_connection(node_pk).await;

        let mut node_connection = NodeConnection::new();
        node_connection.connections.insert(relay_pk);

        connections.clients.write().await.insert(relay_pk, client);
        connections.connections.write().await.insert(node_pk, node_connection);

        connections.remove_connection(node_pk).await.unwrap();

        let clients = connections.clients.read().await;
        let connections = connections.connections.read().await;

        assert!(!clients.get(&relay_pk).unwrap().has_connection(node_pk).await);

        assert!(!connections.contains_key(&node_pk));
    }

    #[tokio::test]
    async fn remove_connection_no_connection() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (node_pk, _node_sk) = gen_keypair();

        let error = connections.remove_connection(node_pk).await.err().unwrap();
        assert_eq!(*error.kind(), ConnectionErrorKind::NoConnection);
    }

    #[tokio::test]
    async fn send_data() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx_0, _outgoing_rx_0, relay_0) = create_client().await;
        let (_incoming_rx_1, outgoing_rx_1, relay_1) = create_client().await;
        let (_incoming_rx_2, outgoing_rx_2, relay_2) = create_client().await;

        let (destination_pk, _destination_sk) = gen_keypair();

        // add connection to destination_pk to be able to send data packets
        relay_1.add_connection(destination_pk).await;
        relay_2.add_connection(destination_pk).await;

        // receive route request
        let outgoing_rx_1 = outgoing_rx_1.into_future().await.1;
        let outgoing_rx_2 = outgoing_rx_2.into_future().await.1;

        // make connections online
        relay_1.handle_packet(Packet::RouteResponse(RouteResponse {
            connection_id: ConnectionId::from_index(42),
            pk: destination_pk,
        })).await.unwrap();
        relay_2.handle_packet(Packet::RouteResponse(RouteResponse {
            connection_id: ConnectionId::from_index(42),
            pk: destination_pk,
        })).await.unwrap();
        relay_1.handle_packet(Packet::ConnectNotification(ConnectNotification {
            connection_id: ConnectionId::from_index(42),
        })).await.unwrap();
        relay_2.handle_packet(Packet::ConnectNotification(ConnectNotification {
            connection_id: ConnectionId::from_index(42),
        })).await.unwrap();

        connections.connections.write().await.insert(destination_pk, NodeConnection {
            status: NodeConnectionStatus::TCP,
            connections: [relay_0.pk, relay_1.pk, relay_2.pk].iter().cloned().collect(),
        });
        connections.clients.write().await.insert(relay_0.pk, relay_0);
        connections.clients.write().await.insert(relay_1.pk, relay_1);
        connections.clients.write().await.insert(relay_2.pk, relay_2);

        let data = DataPayload::CryptoData(CryptoData {
            nonce_last_bytes: 42,
            payload: vec![42; 123],
        });

        connections.send_data(destination_pk, data.clone()).await.unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(connections);

        // data packet should be sent only once
        let packets: Vec<_> = outgoing_rx_1.chain(outgoing_rx_2).collect().await;
        assert_eq!(packets.len(), 1);
        let packet = unpack!(packets[0].clone(), Packet::Data);

        assert_eq!(packet.data, data);
    }

    #[tokio::test]
    async fn send_data_no_connection() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (destination_pk, _destination_sk) = gen_keypair();

        let data = DataPayload::CryptoData(CryptoData {
            nonce_last_bytes: 42,
            payload: vec![42; 123],
        });
        connections.send_data(destination_pk, data).await.unwrap();
    }

    #[tokio::test]
    async fn send_oob() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (destination_pk, _destination_sk) = gen_keypair();

        let (_incoming_rx, outgoing_rx, client) = create_client().await;
        let relay_pk = client.pk;

        connections.clients.write().await.insert(client.pk, client);

        let data = vec![42; 123];

        connections.send_oob(relay_pk, destination_pk, data.clone()).await.unwrap();

        let packet = unpack!(outgoing_rx.into_future().await.0.unwrap(), Packet::OobSend);

        assert_eq!(packet.data, data);
    }

    #[tokio::test]
    async fn send_oob_no_relay() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (destination_pk, _destination_sk) = gen_keypair();
        let (relay_pk, _relay_sk) = gen_keypair();

        let error = connections.send_oob(relay_pk, destination_pk, vec![42; 123]).await.err().unwrap();
        assert_eq!(*error.kind(), ConnectionErrorKind::NotConnected);
    }

    #[tokio::test]
    async fn send_onion() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx, outgoing_rx, client) = create_client().await;
        let relay_pk = client.pk;

        connections.clients.write().await.insert(client.pk, client);

        let onion_request = OnionRequest {
            nonce: gen_nonce(),
            ip_port: IpPort {
                protocol: ProtocolType::TCP,
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345,
            },
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123],
        };

        connections.send_onion(relay_pk, onion_request.clone()).await.unwrap();

        let packet = unpack!(outgoing_rx.into_future().await.0.unwrap(), Packet::OnionRequest);

        assert_eq!(packet, onion_request);
    }

    #[tokio::test]
    async fn send_onion_no_relay() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (relay_pk, _relay_sk) = gen_keypair();

        let onion_request = OnionRequest {
            nonce: gen_nonce(),
            ip_port: IpPort {
                protocol: ProtocolType::TCP,
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345,
            },
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123],
        };

        let error = connections.send_onion(relay_pk, onion_request.clone()).await.err().unwrap();
        assert_eq!(*error.kind(), ConnectionErrorKind::NotConnected);
    }

    #[tokio::test]
    async fn set_connection_status() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (node_pk, _node_sk) = gen_keypair();

        connections.connections.write().await.insert(node_pk, NodeConnection {
            status: NodeConnectionStatus::TCP,
            connections: HashSet::new(),
        });

        connections.set_connection_status(node_pk, NodeConnectionStatus::UDP).await.unwrap();

        assert_eq!(connections.connections.read().await.get(&node_pk).unwrap().status, NodeConnectionStatus::UDP);
    }

    #[tokio::test]
    async fn set_connection_status_no_connection() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (node_pk, _node_sk) = gen_keypair();

        let error = connections.set_connection_status(node_pk, NodeConnectionStatus::UDP).await.err().unwrap();
        assert_eq!(*error.kind(), ConnectionErrorKind::NoSuchRelay);
    }

    #[tokio::test]
    async fn get_random_relay() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx_1, _outgoing_rx_1, relay_1) = create_client().await;
        let relay_pk_1 = relay_1.pk;

        connections.clients.write().await.insert(relay_pk_1, relay_1);

        // add one more disconnected relay to make sure that it won't be
        // included to `get_random_relays` result
        let relay_pk_2 = gen_keypair().0;
        let relay_addr_2 = "127.0.0.1:33445".parse().unwrap();
        let (incoming_tx_2, _incoming_rx_2) = mpsc::unbounded();
        let relay_2 = Client::new(relay_pk_2, relay_addr_2, incoming_tx_2);

        connections.clients.write().await.insert(relay_pk_2, relay_2);

        let relay = connections.get_random_relay().await.unwrap();
        assert_eq!(relay.pk, relay_pk_1);
    }

    #[tokio::test]
    async fn get_random_relays() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx_1, _outgoing_rx_1, relay_1) = create_client().await;
        let (_incoming_rx_2, _outgoing_rx_2, relay_2) = create_client().await;
        let relay_pk_1 = relay_1.pk;
        let relay_pk_2 = relay_2.pk;

        connections.clients.write().await.insert(relay_pk_1, relay_1);
        connections.clients.write().await.insert(relay_pk_2, relay_2);

        // add one more disconnected relay to make sure that it won't be
        // included to `get_random_relays` result
        let relay_pk_3 = gen_keypair().0;
        let relay_addr_3 = "127.0.0.1:33445".parse().unwrap();
        let (incoming_tx_3, _incoming_rx_3) = mpsc::unbounded();
        let relay_3 = Client::new(relay_pk_3, relay_addr_3, incoming_tx_3);

        connections.clients.write().await.insert(relay_pk_3, relay_3);

        let relays = connections.get_random_relays(1).await;
        assert_eq!(relays.len(), 1);
        let relays = connections.get_random_relays(4).await;
        assert_eq!(relays.len(), 2);
    }

    #[tokio::test]
    async fn get_random_relays_empty() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let relays = connections.get_random_relays(1).await;
        assert!(relays.is_empty());
    }

    #[tokio::test]
    async fn main_loop_put_to_sleep() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx_1, _outgoing_rx_1, relay_1) = create_client().await;
        let (_incoming_rx_2, _outgoing_rx_2, relay_2) = create_client().await;
        let relay_pk_1 = relay_1.pk;
        let relay_pk_2 = relay_2.pk;

        let (node_pk_1, _node_sk_1) = gen_keypair();
        let (node_pk_2, _node_sk_2) = gen_keypair();

        connections.connections.write().await.insert(node_pk_1, NodeConnection {
            status: NodeConnectionStatus::TCP,
            connections: [relay_pk_1].iter().cloned().collect(),
        });
        connections.connections.write().await.insert(node_pk_2, NodeConnection {
            status: NodeConnectionStatus::UDP,
            connections: [relay_pk_2].iter().cloned().collect(),
        });

        connections.clients.write().await.insert(relay_pk_1, relay_1);
        connections.clients.write().await.insert(relay_pk_2, relay_2);

        tokio::time::pause();
        // time when we don't wait for connections to appear
        tokio::time::advance(TCP_CONNECTION_ANNOUNCE_TIMEOUT + Duration::from_secs(1)).await;

        connections.main_loop().await.unwrap();

        let clients = connections.clients.read().await;

        assert!(clients.get(&relay_pk_1).unwrap().is_connected().await);
        assert!(clients.get(&relay_pk_2).unwrap().is_sleeping().await);
    }

    #[tokio::test]
    async fn main_loop_remove_unsuccessful() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx_0, _outgoing_rx_0, relay_0) = create_client().await;
        let (_incoming_rx_1, _outgoing_rx_1, relay_1) = create_client().await;
        let (_incoming_rx_2, _outgoing_rx_2, relay_2) = create_client().await;
        let relay_pk_0 = relay_0.pk;
        let relay_pk_1 = relay_1.pk;
        let relay_pk_2 = relay_2.pk;

        relay_1.disconnect().await;
        relay_2.disconnect().await;

        set_connection_attempts(&relay_1, MAX_RECONNECTION_ATTEMPTS + 1).await;

        let (node_pk, _node_sk) = gen_keypair();

        connections.connections.write().await.insert(node_pk, NodeConnection {
            status: NodeConnectionStatus::TCP,
            connections: [relay_pk_0, relay_pk_1, relay_pk_2].iter().cloned().collect(),
        });

        connections.clients.write().await.insert(relay_pk_0, relay_0);
        connections.clients.write().await.insert(relay_pk_1, relay_1);
        connections.clients.write().await.insert(relay_pk_2, relay_2);

        connections.main_loop().await.unwrap();

        let clients = connections.clients.read().await;

        assert!(clients.contains_key(&relay_pk_0));
        assert!(!clients.contains_key(&relay_pk_1));
        assert!(clients.contains_key(&relay_pk_2));

        let connections = connections.connections.read().await;
        let connection = connections.get(&node_pk).unwrap();

        assert!(connection.connections.contains(&relay_pk_0));
        assert!(!connection.connections.contains(&relay_pk_1));
        assert!(connection.connections.contains(&relay_pk_2));
    }

    #[tokio::test]
    async fn main_loop_remove_not_used() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx_0, _outgoing_rx_0, relay_0) = create_client().await;
        let (_incoming_rx_1, _outgoing_rx_1, relay_1) = create_client().await;
        let (_incoming_rx_2, _outgoing_rx_2, relay_2) = create_client().await;
        let (_incoming_rx_3, _outgoing_rx_3, relay_3) = create_client().await;
        let relay_0_c = relay_0.clone();
        let relay_pk_0 = relay_0.pk;
        let relay_pk_1 = relay_1.pk;
        let relay_pk_2 = relay_2.pk;
        let relay_pk_3 = relay_3.pk;

        let (node_pk, _node_sk) = gen_keypair();

        relay_1.add_connection(node_pk).await;
        relay_2.add_connection(node_pk).await;
        relay_3.add_connection(node_pk).await;

        connections.connections.write().await.insert(node_pk, NodeConnection {
            status: NodeConnectionStatus::TCP,
            connections: [relay_pk_1, relay_pk_2, relay_pk_3].iter().cloned().collect(),
        });

        connections.clients.write().await.insert(relay_pk_0, relay_0);
        connections.clients.write().await.insert(relay_pk_1, relay_1);
        connections.clients.write().await.insert(relay_pk_2, relay_2);
        connections.clients.write().await.insert(relay_pk_3, relay_3);

        connections.main_loop().await.unwrap();

        let clients = connections.clients.read().await;

        assert!(!clients.contains_key(&relay_pk_0));
        assert!(clients.contains_key(&relay_pk_1));
        assert!(clients.contains_key(&relay_pk_2));
        assert!(clients.contains_key(&relay_pk_3));

        assert!(relay_0_c.is_disconnected().await);
    }
}
