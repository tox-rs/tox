/*! TCP connections handling

TCP connectins resides between net_crypto and tcp_client.
It serves to net_crypto using tcp_client.
It provides reliable connection to net_crypto via multiple tcp relays to a friend.
When a Tox client connects to a friend via tcp relay, normally 3 redundant connections are established.
One connection is used for data send/recv, 2 others are backup.
In toxcore maximum number of redundant connections is 6.
TCP connection can get into sleep mode.
Getting into sleep mode can occur when UDP connecion is established, because Tox prefer UDP than TCP.
When established UDP connection is disabled, TCP connecions are awaken.

Defintion of struct names.


>   Connections has
         set of ConnOfClient(HashMap)
         set of Connection(HashMap)
     ConnOfClient has
         object of TcpClient processor
         IP, port, PK : to save for sleeping status
     Connection has
         object of 3 to 6 ConnToRelay connections for redundancy
     ConnToRelay has
         id_of_client as a key to ConnOfClient hashmap
         connection_id of Routing Response packet

*/

use parking_lot::RwLock;

use std::sync::Arc;
use std::time::Instant;
use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::io::{Error, ErrorKind};

use futures::sync::mpsc;
use futures::{future, Future, Sink, Stream};

use tokio_codec::Framed;
use tokio::net::TcpStream;

use toxcore::time::*;
use toxcore::io_tokio::*;
use toxcore::crypto_core::*;
use toxcore::tcp::codec::*;
use toxcore::tcp::handshake::make_client_handshake;
use toxcore::tcp::packet::*;

/// The amount of maximum connections for each friend.
pub const MAX_FRIEND_TCP_CONNECTIONS: usize =  6;

/// The amount of recommended connections for each friend.
///   NOTE: Must be at most (MAX_FRIEND_TCP_CONNECTIONS / 2).
pub const RECOMMENDED_FRIEND_TCP_CONNECTIONS: usize =  MAX_FRIEND_TCP_CONNECTIONS / 2;

/// Status of connection to TcpRelay.
#[derive(PartialEq, Clone)]
pub enum ConnectionStatus {
    /// Uninitialized state.
    None,
    /// Connection is registered internally.
    Registered,
    /// Connection is online.
    Online,
}

/// Status of connection to a friend.
#[derive(PartialEq, Clone)]
pub enum ConnOfClientStatus {
    /// Uninitialized state.
    None,
    /// Connection is valid but not connected.
    Valid,
    /// Connection is valid and connected.
    Connected,
    /// Connection is sleeping because UDP is enabled.
    Sleeping,
}

/// Main struct for TCP connections.
/// Holds key_pair for TCP connections, set of TCP connections to relay,
/// set of connections of TcpClient.
/// PublicKey is used as a key of HashMap to avoid ABA problem.
#[derive(Clone)]
pub struct Connections {
    pk: PublicKey,
    sk: SecretKey,
    conns_of_client: Arc<RwLock<HashMap<PublicKey, ConnOfClient>>>,
    connections: Arc<RwLock<HashMap<PublicKey, Connection>>>,
}

/// Connection of a TcpClient processor object.
#[derive(Clone)]
pub struct ConnOfClient {
    status: ConnOfClientStatus,
    to_local_tx: Option<mpsc::UnboundedSender<Packet>>,
    connected_time: Instant,
    lock_count: u32,
    sleep_count: u32,
    onion: bool,
    /// used when sleep.
    ip: IpAddr,
    /// used when sleep.
    port: u16,
    /// used when sleep.
    relay_pk: PublicKey,
    wakeup: bool,
}

/// Connection to a friend.
/// It has 3 to 6 redundant connection to TcpRelays.
#[derive(Clone, PartialEq)]
pub struct Connection {
    status: ConnOfClientStatus,
    friend_dht_pk: PublicKey,
    conn_to_relay: Vec<ConnToRelay>,
}

/// Connection to a relay.
#[derive(Clone, PartialEq)]
pub struct ConnToRelay {
    status: ConnectionStatus,
    /// Public key is used for id to avoid ABA problem.
    id_of_client: PublicKey,
    connection_id: u8,
}

impl Connections {
    /// Create new TCP connections object.
    pub fn new(pk: PublicKey, sk: SecretKey) -> Self {
        Connections {
            pk,
            sk,
            conns_of_client: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn add_entry(&self, socket: Framed<TcpStream, Codec>, server_pk: &PublicKey,
                 from_server_tx: mpsc::UnboundedSender<(Packet, PublicKey)>) -> IoFuture<()> {
        let (to_server, from_server) = socket.split();
        let (to_local_tx, to_local_rx) = mpsc::unbounded();
        let mut connections = self.connections.write();
        let mut conns_of_client = self.conns_of_client.write();

        let relay = ConnToRelay {
            status: ConnectionStatus::None,
            id_of_client: gen_keypair().0,
            connection_id: 0,
        };

        let connection = connections.entry(*server_pk).or_insert(
            Connection {
                status: ConnOfClientStatus::None,
                friend_dht_pk: server_pk.clone(),
                conn_to_relay: vec![relay.clone()],
            }
        );

        if connection.conn_to_relay.contains(&relay) {
            // TODO: return with proper value
            return Box::new(future::ok(()))
        } else {
            connection.conn_to_relay.push(relay.clone());
        }

        let mut conn_of_client = ConnOfClient::new();
        conn_of_client.to_local_tx = Some(to_local_tx);

        conns_of_client.insert(relay.id_of_client, conn_of_client);

        let reader = from_server
            .map(move |packet| (packet, relay.clone().id_of_client))
            .forward(from_server_tx
                .sink_map_err(|e| {
                    Error::new(ErrorKind::Other,
                               format!("Could not forward message from server to connection {:?}", e))
                })
            )
            .map(|_| {
                println!("Connection closed");
            });

        let writer = to_local_rx
            .map_err(|()| Error::from(ErrorKind::UnexpectedEof))
            .forward(to_server)
            .map(|_| ());

        let network = reader.select(writer)
            .map(|_| ())
            .map_err(|(err, _select_next)| Error::new(ErrorKind::Other, err));

        Box::new(network)
    }

    /// Add a new connection of client to tcp server.
    pub fn add_relay(&self, addr: &SocketAddr, server_pk: &PublicKey,
                     from_server_tx: mpsc::UnboundedSender<(Packet, PublicKey)>) -> IoFuture<()> {
        let (pk, sk, server_pk, from_server_tx) =
            (self.pk.clone(), self.sk.clone(), server_pk.clone(), from_server_tx.clone());

        let self_c = self.clone();

        let conn = TcpStream::connect(addr)
            .and_then(move |socket| {
                make_client_handshake(socket, &pk, &sk, &server_pk)
            })
            .and_then(move |(socket, channel)| {
                let secure_socket = Framed::new(socket, Codec::new(channel));
                self_c.add_entry(secure_socket, &server_pk, from_server_tx)
            });

        Box::new(conn)
    }

    /// Send a packet to the tcp server
    pub fn send_packet(&self, connection_id: &PublicKey, packet: Packet) -> IoFuture<()> {
        let connections = self.connections.read();
        let conns_of_connection = self.conns_of_client.read();

        if let Some(conn) = connections.get(connection_id) {
            for relay in &conn.conn_to_relay {
                if let Some(client) = conns_of_connection.get(&relay.id_of_client) {
                    if let Some(ref to_local_tx) = client.to_local_tx {
                        return Box::new(to_local_tx.clone().send(packet)
                            .map(|_| ())
                            .map_err(|e| Error::new(ErrorKind::Other, e))
                        )
                    }
                }
            }
        }
        Box::new(future::ok(()))
    }
}

impl ConnOfClient {
    /// Create new ConnOfClient object.
    pub fn new() -> Self {
        ConnOfClient {
            status: ConnOfClientStatus::None,
            to_local_tx: None,
            connected_time: clock_now(),
            lock_count: 0,
            sleep_count: 0,
            onion: false,
            ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 33445,
            relay_pk: gen_keypair().0,
            wakeup: false,
        }
    }
}
