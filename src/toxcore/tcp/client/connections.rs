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

use parking_lot::RwLock;

use std::collections::{hash_map, HashMap, HashSet};
use std::net::SocketAddr;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{future, stream, Future, Stream};
use futures::future::Either;
use futures::sync::mpsc;
use tokio::timer::Interval;

use toxcore::crypto_core::*;
use toxcore::io_tokio::*;
use toxcore::tcp::client::relay::*;
use toxcore::tcp::packet::*;
use toxcore::time::*;

/// The amount of maximum connections for each friend.
const MAX_FRIEND_TCP_CONNECTIONS: usize =  6;

/// The amount of recommended connections for each friend.
///   NOTE: Must be at most (MAX_FRIEND_TCP_CONNECTIONS / 2).
const RECOMMENDED_FRIEND_TCP_CONNECTIONS: usize =  MAX_FRIEND_TCP_CONNECTIONS / 2;

/// How many attempts to reconnect to the relay we should make before we
/// consider this relay unreachable and drop it.
const MAX_RECONNECTION_ATTEMPTS: u32 = 1;

const TCP_CONNECTION_ANNOUNCE_TIMEOUT: u64 = 10;

/// How often `main_loop` should be run.
const CONNECTIONS_INTERVAL: u64 = 1;

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
    fn relays<'c, 'a: 'c, 'b: 'c>(&'a self, relays: &'b HashMap<PublicKey, Relay>) -> impl Iterator<Item = &'b Relay> + 'c {
        self.connections
            .iter()
            .flat_map(move |relay_pk| relays.get(relay_pk).into_iter())
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
    relays: Arc<RwLock<HashMap<PublicKey, Relay>>>,
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
            relays: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add relay we are supposed to be connected to. These relays are necessary
    /// for initial connection so that we are able to find friends and to send
    /// them our relays. Later when more relays are received from our friends
    /// they should be added via `add_relay_connection` method.
    pub fn add_relay_global(&self, relay_addr: SocketAddr, relay_pk: PublicKey) -> IoFuture<()> {
        if let hash_map::Entry::Vacant(vacant) = self.relays.write().entry(relay_pk) {
            let relay = Relay::new(relay_pk, relay_addr, self.incoming_tx.clone());
            vacant.insert(relay.clone());
            relay.spawn(self.dht_sk.clone(), self.dht_pk)
        } else {
            trace!("Attempt to add relay that already exists: {}", relay_addr);
            Box::new(future::ok(()))
        }
    }

    /// Add relay that we received from our friend. This relay can be ignored if
    /// we already connected to this friend via at least
    /// `RECOMMENDED_FRIEND_TCP_CONNECTIONS` relays. Connection to our friend
    /// via this relay will be added as well.
    pub fn add_relay_connection(&self, relay_addr: SocketAddr, relay_pk: PublicKey, node_pk: PublicKey) -> IoFuture<()> {
        let mut relays = self.relays.write();
        // TODO: NLL
        if relays.contains_key(&relay_pk) {
            let relay = relays.get(&relay_pk).unwrap();
            self.add_connection_inner(relay, node_pk)
        } else {
            let mut connections = self.connections.write();
            let connection = connections.entry(node_pk).or_insert(NodeConnection::new());

            let connections_count = connection.connections.len();
            let online_connections_count = connection.connections.iter().filter(|relay_pk|
                relays.get(relay_pk).map_or(false, |relay| relay.is_connection_online(node_pk))
            ).count();

            if online_connections_count < RECOMMENDED_FRIEND_TCP_CONNECTIONS && connections_count < MAX_FRIEND_TCP_CONNECTIONS {
                let relay = Relay::new(relay_pk, relay_addr, self.incoming_tx.clone());
                relays.insert(relay_pk, relay.clone());
                connection.connections.insert(relay_pk);
                let future = relay.add_connection(node_pk)
                    .join(relay.spawn(self.dht_sk.clone(), self.dht_pk))
                    .map(|_| ());
                Box::new(future)
            } else {
                Box::new(future::ok(()))
            }
        }
    }

    /// Add a connection to our friend via relay. It means that we will send
    /// `RouteRequest` packet to this relay and wait for the friend to become
    /// connected.
    pub fn add_connection(&self, relay_pk: PublicKey, node_pk: PublicKey) -> IoFuture<()> {
        if let Some(relay) = self.relays.read().get(&relay_pk) {
            self.add_connection_inner(relay, node_pk)
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "add_connection: no such relay"
            )))
        }
    }

    /// Remove connection to a friend via relays.
    pub fn remove_connection(&self, node_pk: PublicKey) -> IoFuture<()> {
        if let Some(connection) = self.connections.write().remove(&node_pk) {
            let relays = self.relays.read();
            let futures = connection.relays(&relays)
                .map(|relay| relay.remove_connection(node_pk).then(Ok))
                .collect::<Vec<_>>();
            Box::new(future::join_all(futures).map(|_| ()))
        } else {
            // TODO: what if we didn't receive relays from friend and delete him?
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "remove_connection: no connection to the node"
            )))
        }
    }

    /// Inner function to add a connection to our friend via relay.
    fn add_connection_inner(&self, relay: &Relay, node_pk: PublicKey) -> IoFuture<()> {
        // TODO: check MAX_FRIEND_TCP_CONNECTIONS?
        let mut connections = self.connections.write();
        let connection = connections.entry(node_pk).or_insert(NodeConnection::new());
        connection.connections.insert(relay.pk);
        let future = if connection.status == NodeConnectionStatus::TCP && relay.is_sleeping() {
            // unsleep relay
            Either::A(relay.clone().spawn(self.dht_sk.clone(), self.dht_pk))
        } else {
            Either::B(future::ok(()))
        };
        let future = future.join(relay.add_connection(node_pk)).map(|_| ());
        Box::new(future)
    }

    /// Send `Data` packet to a node via one of the relays.
    pub fn send_data(&self, node_pk: PublicKey, data: Vec<u8>) -> IoFuture<()> {
        let connections = self.connections.read();
        if let Some(connection) = connections.get(&node_pk) {
            let relays = self.relays.read();
            // TODO: shuffle?
            let futures = connection.relays(&relays)
                .map(move |relay| relay.send_data(node_pk, data.clone()));
            // send packet to the first relay only that can accept it
            // errors are ignored
            // TODO: return error if stream is exhausted?
            Box::new(stream::futures_unordered(futures)
                .then(Ok)
                .skip_while(|res| future::ok(res.is_err()))
                .into_future()
                .map(|_| ())
                .map_err(|(e, _)| e))
        } else {
            Box::new(future::ok(()))
        }

        // TODO: send as OOB?
    }

    /// Send `OobSend` packet to a node via relay with specified `PublicKey`.
    pub fn send_oob(&self, relay_pk: PublicKey, node_pk: PublicKey, data: Vec<u8>) -> IoFuture<()> {
        let relays = self.relays.read();
        if let Some(relay) = relays.get(&relay_pk) {
            relay.send_oob(node_pk, data)
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "send_oob: relay is not connected"
            )))
        }
    }

    /// Send `OnionRequest` packet to relay with specified `PublicKey`.
    pub fn send_onion(&self, relay_pk: PublicKey, onion_request: OnionRequest) -> IoFuture<()> {
        let relays = self.relays.read();
        if let Some(relay) = relays.get(&relay_pk) {
            relay.send_onion(onion_request)
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "send_onion: relay is not connected"
            )))
        }
    }

    /// Change status of connection to the node. Connections module need to know
    /// whether connection is used to be able to put to sleep relay connections.
    pub fn set_connection_status(&self, node_pk: PublicKey, status: NodeConnectionStatus) -> IoFuture<()> {
        if let Some(connection) = self.connections.write().get_mut(&node_pk) {
            let future = if status == NodeConnectionStatus::TCP && connection.status == NodeConnectionStatus::UDP {
                // unsleep relays
                let relays = self.relays.read();
                let futures = connection.relays(&relays)
                    .map(|relay| relay.clone().spawn(self.dht_sk.clone(), self.dht_pk))
                    .collect::<Vec<_>>();
                Box::new(future::join_all(futures).map(|_| ())) as IoFuture<()>
            } else {
                Box::new(future::ok(()))
            };
            connection.status = status;
            future
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "set_connection_status: no such connection"
            )))
        }
    }

    /// Main loop that should be run periodically. It removes unreachable and
    /// redundant relays, reconnects to relays if a connection was lost, puts
    /// relays to sleep if they are not used right now.
    fn main_loop(&self) -> IoFuture<()> {
        let mut relays = self.relays.write();
        let mut connections = self.connections.write();

        let mut futures = Vec::new();

        // If we have at least one connected relay that means that our network
        // connection is fine. So if we can't connect to some relays we can
        // drop them.
        let connected = relays.values().any(Relay::is_connected);

        // remove relays we can't connect to (or retry to connect)
        relays.retain(|_, relay|
            if relay.is_disconnected() {
                if connected && relay.connection_attempts() > MAX_RECONNECTION_ATTEMPTS {
                    false
                } else {
                    let future = relay.clone().spawn(self.dht_sk.clone(), self.dht_pk);
                    futures.push(future);
                    true
                }
            } else {
                true
            }
        );

        // find out which relays are used right now
        let used_relays = connections.values()
            .filter(|connection| connection.status == NodeConnectionStatus::TCP)
            .flat_map(|connection| connection.connections.iter().cloned())
            .collect::<HashSet<_>>();

        // send to sleep not used right now relays
        relays.values()
            .filter(move |relay|
                // only connected relays have connected_time
                relay.connected_time().map_or(
                    false,
                    |connected_time| clock_elapsed(connected_time) > Duration::from_secs(TCP_CONNECTION_ANNOUNCE_TIMEOUT)
                ) && !used_relays.contains(&relay.pk)
            )
            .for_each(|relay| relay.sleep());

        // remove not used relays
        let mut relays_len = relays.len();
        relays.retain(|_, relay|
            if relays_len > RECOMMENDED_FRIEND_TCP_CONNECTIONS && relay.connections_count() == 0 {
                relays_len -= 1;
                relay.disconnect();
                false
            } else {
                true
            }
        );

        // remove deleted relays from connections
        for connection in connections.values_mut() {
            connection.connections.retain(|relay_pk| relays.contains_key(relay_pk));

            // TODO: remove connections if there are too many?
        }

        Box::new(future::join_all(futures).map(|_| ()))
    }

    /// Run TCP periodical tasks. Result future will never be completed
    /// successfully.
    pub fn run(self) -> IoFuture<()> {
        let interval = Duration::from_secs(CONNECTIONS_INTERVAL);
        let wakeups = Interval::new(Instant::now(), interval);

        let future = wakeups
            .map_err(|e| Error::new(ErrorKind::Other, format!("TCP connections timer error: {:?}", e)))
            .for_each(move |_instant| self.main_loop());

        Box::new(future)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio_executor;
    use tokio_timer::clock::*;

    use toxcore::tcp::client::relay::tests::*;
    use toxcore::time::ConstNow;
    use toxcore::onion::packet::*;

    #[test]
    fn add_relay_global() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let addr = "0.0.0.0:12347".parse().unwrap();
        let (relay_pk, _relay_sk) = gen_keypair();

        // ignore result future since it spawns the connection which should be
        // executed inside tokio context
        let _ = connections.add_relay_global(addr, relay_pk);

        assert!(connections.relays.read().contains_key(&relay_pk));
    }

    #[test]
    fn add_relay_global_exists() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx, _outgoing_rx, relay) = create_relay();
        let addr = relay.addr;
        let relay_pk = relay.pk;

        connections.relays.write().insert(relay_pk, relay);

        // new connection shouldn't be spawned
        connections.add_relay_global(addr, relay_pk).wait().unwrap();
    }

    #[test]
    fn add_relay_connection() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let addr = "0.0.0.0:12347".parse().unwrap();
        let (relay_pk, _relay_sk) = gen_keypair();
        let (node_pk, _node_sk) = gen_keypair();

        // ignore result future since it spawns the connection which should be
        // executed inside tokio context
        let _ = connections.add_relay_connection(addr, relay_pk, node_pk);

        let relays = connections.relays.read();
        let connections = connections.connections.read();

        assert!(relays.contains_key(&relay_pk));
        assert!(relays.get(&relay_pk).unwrap().has_connection(node_pk));

        assert!(connections.contains_key(&node_pk));
        assert_eq!(connections.get(&node_pk).unwrap().status, NodeConnectionStatus::TCP);
        assert!(connections.get(&node_pk).unwrap().connections.contains(&relay_pk));
    }

    #[test]
    fn add_relay_connection_relay_exists() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx, _outgoing_rx, relay) = create_relay();
        let addr = relay.addr;
        let relay_pk = relay.pk;

        connections.relays.write().insert(relay_pk, relay);

        let (node_pk, _node_sk) = gen_keypair();

        // new connection shouldn't be spawned
        connections.add_relay_connection(addr, relay_pk, node_pk).wait().unwrap();

        let relays = connections.relays.read();
        let connections = connections.connections.read();

        assert!(relays.contains_key(&relay_pk));
        assert!(relays.get(&relay_pk).unwrap().has_connection(node_pk));

        assert!(connections.contains_key(&node_pk));
        assert_eq!(connections.get(&node_pk).unwrap().status, NodeConnectionStatus::TCP);
        assert!(connections.get(&node_pk).unwrap().connections.contains(&relay_pk));
    }

    #[test]
    fn add_connection() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx, _outgoing_rx, relay) = create_relay();
        let relay_pk = relay.pk;

        connections.relays.write().insert(relay_pk, relay);

        let (node_pk, _node_sk) = gen_keypair();

        // new connection shouldn't be spawned
        connections.add_connection(relay_pk, node_pk).wait().unwrap();

        let relays = connections.relays.read();
        let connections = connections.connections.read();

        assert!(relays.contains_key(&relay_pk));
        assert!(relays.get(&relay_pk).unwrap().has_connection(node_pk));

        assert!(connections.contains_key(&node_pk));
        assert_eq!(connections.get(&node_pk).unwrap().status, NodeConnectionStatus::TCP);
        assert!(connections.get(&node_pk).unwrap().connections.contains(&relay_pk));
    }

    #[test]
    fn add_connection_no_relay() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (relay_pk, _relay_sk) = gen_keypair();
        let (node_pk, _node_sk) = gen_keypair();

        assert!(connections.add_connection(relay_pk, node_pk).wait().is_err());
    }

    #[test]
    fn remove_connection() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (node_pk, _node_sk) = gen_keypair();

        let (_incoming_rx, _outgoing_rx, relay) = create_relay();
        let relay_pk = relay.pk;

        relay.add_connection(node_pk).wait().unwrap();

        let mut node_connection = NodeConnection::new();
        node_connection.connections.insert(relay_pk);

        connections.relays.write().insert(relay_pk, relay);
        connections.connections.write().insert(node_pk, node_connection);

        connections.remove_connection(node_pk).wait().unwrap();

        let relays = connections.relays.read();
        let connections = connections.connections.read();

        assert!(!relays.get(&relay_pk).unwrap().has_connection(node_pk));

        assert!(!connections.contains_key(&node_pk));
    }

    #[test]
    fn remove_connection_no_connection() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (node_pk, _node_sk) = gen_keypair();

        assert!(connections.remove_connection(node_pk).wait().is_err());
    }

    #[test]
    fn send_data() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx_0, _outgoing_rx_0, relay_0) = create_relay();
        let (_incoming_rx_1, outgoing_rx_1, relay_1) = create_relay();
        let (_incoming_rx_2, outgoing_rx_2, relay_2) = create_relay();

        let (destination_pk, _destination_sk) = gen_keypair();

        // add connection to destination_pk to be able to send data packets
        relay_1.add_connection(destination_pk).wait().unwrap();
        relay_2.add_connection(destination_pk).wait().unwrap();

        // receive route request
        let outgoing_rx_1 = outgoing_rx_1.into_future().wait().unwrap().1;
        let outgoing_rx_2 = outgoing_rx_2.into_future().wait().unwrap().1;

        // make connections online
        relay_1.handle_packet(Packet::RouteResponse(RouteResponse {
            connection_id: 42,
            pk: destination_pk,
        })).wait().unwrap();
        relay_2.handle_packet(Packet::RouteResponse(RouteResponse {
            connection_id: 42,
            pk: destination_pk,
        })).wait().unwrap();
        relay_1.handle_packet(Packet::ConnectNotification(ConnectNotification {
            connection_id: 42,
        })).wait().unwrap();
        relay_2.handle_packet(Packet::ConnectNotification(ConnectNotification {
            connection_id: 42,
        })).wait().unwrap();

        connections.connections.write().insert(destination_pk, NodeConnection {
            status: NodeConnectionStatus::TCP,
            connections: [relay_0.pk, relay_1.pk, relay_2.pk].iter().cloned().collect(),
        });
        connections.relays.write().insert(relay_0.pk, relay_0);
        connections.relays.write().insert(relay_1.pk, relay_1);
        connections.relays.write().insert(relay_2.pk, relay_2);

        let data = vec![42; 123];

        connections.send_data(destination_pk, data.clone()).wait().unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(connections);

        // data packet should be sent only once
        let packets = outgoing_rx_1.select(outgoing_rx_2).collect().wait().unwrap();
        assert_eq!(packets.len(), 1);
        let packet = unpack!(packets[0].clone(), Packet::Data);

        assert_eq!(packet.data, data);
    }

    #[test]
    fn send_data_no_connection() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (destination_pk, _destination_sk) = gen_keypair();

        connections.send_data(destination_pk, vec![42; 123]).wait().unwrap();
    }

    #[test]
    fn send_oob() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (destination_pk, _destination_sk) = gen_keypair();

        let (_incoming_rx, outgoing_rx, relay) = create_relay();
        let relay_pk = relay.pk;

        connections.relays.write().insert(relay.pk, relay);

        let data = vec![42; 123];

        connections.send_oob(relay_pk, destination_pk, data.clone()).wait().unwrap();

        let packet = unpack!(outgoing_rx.into_future().wait().unwrap().0.unwrap(), Packet::OobSend);

        assert_eq!(packet.data, data);
    }

    #[test]
    fn send_oob_no_relay() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (destination_pk, _destination_sk) = gen_keypair();
        let (relay_pk, _relay_sk) = gen_keypair();

        assert!(connections.send_oob(relay_pk, destination_pk, vec![42; 123]).wait().is_err());
    }

    #[test]
    fn send_onion() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx, outgoing_rx, relay) = create_relay();
        let relay_pk = relay.pk;

        connections.relays.write().insert(relay.pk, relay);

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

        connections.send_onion(relay_pk, onion_request.clone()).wait().unwrap();

        let packet = unpack!(outgoing_rx.into_future().wait().unwrap().0.unwrap(), Packet::OnionRequest);

        assert_eq!(packet, onion_request);
    }

    #[test]
    fn send_onion_no_relay() {
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

        assert!(connections.send_onion(relay_pk, onion_request.clone()).wait().is_err());
    }

    #[test]
    fn set_connection_status() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (node_pk, _node_sk) = gen_keypair();

        connections.connections.write().insert(node_pk, NodeConnection {
            status: NodeConnectionStatus::TCP,
            connections: HashSet::new(),
        });

        connections.set_connection_status(node_pk, NodeConnectionStatus::UDP).wait().unwrap();

        assert_eq!(connections.connections.read().get(&node_pk).unwrap().status, NodeConnectionStatus::UDP);
    }

    #[test]
    fn set_connection_status_no_connection() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (node_pk, _node_sk) = gen_keypair();

        assert!(connections.set_connection_status(node_pk, NodeConnectionStatus::UDP).wait().is_err());
    }

    #[test]
    fn main_loop_put_to_sleep() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx_1, _outgoing_rx_1, relay_1) = create_relay();
        let (_incoming_rx_2, _outgoing_rx_2, relay_2) = create_relay();
        let relay_pk_1 = relay_1.pk;
        let relay_pk_2 = relay_2.pk;

        let (node_pk_1, _node_sk_1) = gen_keypair();
        let (node_pk_2, _node_sk_2) = gen_keypair();

        connections.connections.write().insert(node_pk_1, NodeConnection {
            status: NodeConnectionStatus::TCP,
            connections: [relay_pk_1].iter().cloned().collect(),
        });
        connections.connections.write().insert(node_pk_2, NodeConnection {
            status: NodeConnectionStatus::UDP,
            connections: [relay_pk_2].iter().cloned().collect(),
        });

        connections.relays.write().insert(relay_pk_1, relay_1);
        connections.relays.write().insert(relay_pk_2, relay_2);

        let mut enter = tokio_executor::enter().unwrap();
        // time when we don't wait for connections to appear
        let clock = Clock::new_with_now(ConstNow(
            Instant::now() + Duration::from_secs(TCP_CONNECTION_ANNOUNCE_TIMEOUT + 1)
        ));

        with_default(&clock, &mut enter, |_| {
            connections.main_loop().wait().unwrap();
        });

        let relays = connections.relays.read();

        assert!(relays.get(&relay_pk_1).unwrap().is_connected());
        assert!(relays.get(&relay_pk_2).unwrap().is_sleeping());
    }

    #[test]
    fn main_loop_remove_unsuccessful() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx_0, _outgoing_rx_0, relay_0) = create_relay();
        let (_incoming_rx_1, _outgoing_rx_1, relay_1) = create_relay();
        let (_incoming_rx_2, _outgoing_rx_2, relay_2) = create_relay();
        let relay_pk_0 = relay_0.pk;
        let relay_pk_1 = relay_1.pk;
        let relay_pk_2 = relay_2.pk;

        relay_1.disconnect();
        relay_2.disconnect();

        set_connection_attempts(&relay_1, MAX_RECONNECTION_ATTEMPTS + 1);

        let (node_pk, _node_sk) = gen_keypair();

        connections.connections.write().insert(node_pk, NodeConnection {
            status: NodeConnectionStatus::TCP,
            connections: [relay_pk_0, relay_pk_1, relay_pk_2].iter().cloned().collect(),
        });

        connections.relays.write().insert(relay_pk_0, relay_0);
        connections.relays.write().insert(relay_pk_1, relay_1);
        connections.relays.write().insert(relay_pk_2, relay_2);

        // ignore result future since it spawns the connection which should be
        // executed inside tokio context
        let _ = connections.main_loop();

        let relays = connections.relays.read();

        assert!(relays.contains_key(&relay_pk_0));
        assert!(!relays.contains_key(&relay_pk_1));
        assert!(relays.contains_key(&relay_pk_2));

        let connections = connections.connections.read();
        let connection = connections.get(&node_pk).unwrap();

        assert!(connection.connections.contains(&relay_pk_0));
        assert!(!connection.connections.contains(&relay_pk_1));
        assert!(connection.connections.contains(&relay_pk_2));
    }

    #[test]
    fn main_loop_remove_not_used() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (incoming_tx, _incoming_rx) = mpsc::unbounded();
        let connections = Connections::new(dht_pk, dht_sk, incoming_tx);

        let (_incoming_rx_0, _outgoing_rx_0, relay_0) = create_relay();
        let (_incoming_rx_1, _outgoing_rx_1, relay_1) = create_relay();
        let (_incoming_rx_2, _outgoing_rx_2, relay_2) = create_relay();
        let (_incoming_rx_3, _outgoing_rx_3, relay_3) = create_relay();
        let relay_0_c = relay_0.clone();
        let relay_pk_0 = relay_0.pk;
        let relay_pk_1 = relay_1.pk;
        let relay_pk_2 = relay_2.pk;
        let relay_pk_3 = relay_3.pk;

        let (node_pk, _node_sk) = gen_keypair();

        relay_1.add_connection(node_pk);
        relay_2.add_connection(node_pk);
        relay_3.add_connection(node_pk);

        connections.connections.write().insert(node_pk, NodeConnection {
            status: NodeConnectionStatus::TCP,
            connections: [relay_pk_1, relay_pk_2, relay_pk_3].iter().cloned().collect(),
        });

        connections.relays.write().insert(relay_pk_0, relay_0);
        connections.relays.write().insert(relay_pk_1, relay_1);
        connections.relays.write().insert(relay_pk_2, relay_2);
        connections.relays.write().insert(relay_pk_3, relay_3);

        connections.main_loop().wait().unwrap();

        let relays = connections.relays.read();

        assert!(!relays.contains_key(&relay_pk_0));
        assert!(relays.contains_key(&relay_pk_1));
        assert!(relays.contains_key(&relay_pk_2));
        assert!(relays.contains_key(&relay_pk_3));

        assert!(relay_0_c.is_disconnected());
    }
}
