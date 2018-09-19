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
         id as a key to ConnOfClient hashmap
         connection_id of Routing Response packet

*/

use parking_lot::RwLock;

use std::sync::Arc;
use std::time::Instant;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use toxcore::crypto_core::*;
use toxcore::tcp::client::ClientProcessor;
use toxcore::time::*;

/// The amount of maximum connections for each friend.
pub const MAX_FRIEND_TCP_CONNECTIONS: usize =  6;

/// The amount of recommended connections for each friend.
///   NOTE: Must be at most (MAX_FRIEND_TCP_CONNECTIONS / 2).
pub const RECOMMENDED_FRIEND_TCP_CONNECTIONS: usize =  MAX_FRIEND_TCP_CONNECTIONS / 2;

/// Status of connection to TcpRelay.
pub enum ConnectionStatus {
    /// Uninitialized state.
    None,
    /// Connection is registered internally.
    Registered,
    /// Connection is online.
    Online,
}

/// Status of connection to a friend.
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
pub struct Connections {
    pk: PublicKey,
    sk: SecretKey,
    conns_of_client: Arc<RwLock<HashMap<PublicKey, ConnOfClient>>>,
    connections: Arc<RwLock<HashMap<PublicKey, Connection>>>,
}

/// Connection of a TcpClient processor object.
pub struct ConnOfClient {
    status: ConnOfClientStatus,
    /// Tcp Client.
    client: Option<ClientProcessor>,
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
pub struct Connection {
    status: ConnOfClientStatus,
    friend_dht_pk: PublicKey,
    /// Public key is used for id to avoid ABA problem.
    callback_id: PublicKey,
    conn_to_relay: Vec<ConnToRelay>,
}

/// Connection to a relay.
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
}

impl ConnOfClient {
    /// Create new ConnOfClient object.
    pub fn new() -> Self {
        ConnOfClient {
            status: ConnOfClientStatus::None,
            client: None,
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

impl Connection {
    /// Create new Connection object.
    pub fn new(friend_dht_pk: PublicKey) -> Self {
        Connection {
            status: ConnOfClientStatus::None,
            friend_dht_pk,
            callback_id: gen_keypair().0,
            conn_to_relay: Vec::new(),
        }
    }
}

impl ConnToRelay {
    /// Create new ConnToRelay object
    pub fn new() -> Self {
        ConnToRelay {
            status: ConnectionStatus::None,
            id_of_client: gen_keypair().0,
            connection_id: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connections_new() {
        let (pk, sk) = gen_keypair();
        let _tco_conns = Connections::new(pk, sk);
    }

    #[test]
    fn conn_of_client_new() {
        let _conn_of_client = ConnOfClient::new();
    }

    #[test]
    fn connection_new() {
        let _connection = Connection::new(gen_keypair().0);
    }

    #[test]
    fn conn_to_relay_new() {
        let _conn_to_relay = ConnToRelay::new();
    }
}
