/*! Net crypto module allows to send data between two friends and provides
encryption, ordered delivery, and perfect forward secrecy.

It can use both UDP and TCP (over relays) transport protocols to send data and
can switch between them without the peers needing to disconnect and reconnect.
For example two Tox friends might first connect over TCP and a few seconds later
switch to UDP when a direct UDP connection becomes possible. Direct UDP is
preferred over TCP because it is direct and isn't limited by possibly congested
TCP relays.

*/

mod crypto_connection;
mod packets_array;
pub mod errors;

pub use self::crypto_connection::*;
use self::packets_array::*;
use self::errors::*;

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::u16;

use failure::Fail;
use futures::{TryFutureExt, SinkExt};
use futures::future;
use futures::channel::mpsc;
use tokio::sync::RwLock;

use tox_binary_io::*;
use tox_crypto::*;
use tox_packet::dht::{Packet as DhtPacket, *};
use crate::dht::precomputed_cache::*;
use crate::io_tokio::*;
use tox_packet::relay::DataPayload as TcpDataPayload;
use crate::time::*;

/// Maximum size of `Packet` when we try to send it to UDP address even if
/// it's considered dead.
const DHT_ATTEMPT_MAX_PACKET_LENGTH: usize = 95;

/// If diff between `Nonce` from received data packet and connection `Nonce` is
/// bigger than 2 * `NONCE_DIFF_THRESHOLD` then increase connection `Nonce` by
/// `NONCE_DIFF_THRESHOLD`.
const NONCE_DIFF_THRESHOLD: u16 = u16::MAX / 3;

/// Packet with this ID contains indices of lossless packets that should be
/// resent.
const PACKET_ID_REQUEST: u8 = 1;

/// Packet with this ID means that this crypto connection should be killed.
const PACKET_ID_KILL: u8 = 2;

/// Packets with ID from 0 to `PACKET_ID_CRYPTO_RANGE_END` are reserved for
/// `net_crypto`.
const PACKET_ID_CRYPTO_RANGE_END: u8 = 15;

/// Packets with ID from `PACKET_ID_LOSSY_RANGE_START` to
/// `PACKET_ID_LOSSY_RANGE_END` are considered lossy packets.
const PACKET_ID_LOSSY_RANGE_START: u8 = 192;

/// Packets with ID from `PACKET_ID_LOSSY_RANGE_START` to
/// `PACKET_ID_LOSSY_RANGE_END` are considered lossy packets.
const PACKET_ID_LOSSY_RANGE_END: u8 = 254;

/// Shorthand for the transmit half of the message channel for sending DHT
/// packets.
type UdpTx = mpsc::Sender<(DhtPacket, SocketAddr)>;

/// Shorthand for the transmit half of the message channel for sending TCP
/// packets via relays.
type TcpTx = mpsc::Sender<(TcpDataPayload, PublicKey)>;

/// Shorthand for the transmit half of the message channel for sending DHT
/// `PublicKey` when it gets known. The first key is a long term key, the second
/// key is a DHT key.
type DhtPkTx = mpsc::UnboundedSender<(PublicKey, PublicKey)>;

/// Shorthand for the transmit half of the message channel for sending a
/// connection status when it becomes connected or disconnected. The key is a
/// long term key of the connection.
type ConnectionStatusTx = mpsc::UnboundedSender<(PublicKey, bool)>;

/// Shorthand for the transmit half of the message channel for sending lossless
/// packets. The key is a long term public key of the peer that sent this
/// packet.
type LosslessTx = mpsc::UnboundedSender<(PublicKey, Vec<u8>)>;

/// Shorthand for the transmit half of the message channel for sending lossy
/// packets. The key is a long term public key of the peer that sent this
/// packet.
type LossyTx = mpsc::UnboundedSender<(PublicKey, Vec<u8>)>;

/// Packet that can be sent as UDP packet or as TCP payload via TCP relay. The
/// way it should be sent is determined automatically. It doesn't contain
/// `CookieResponse` variant because `CookieResponse` is always sent via the
/// channel the request packet was received from.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Packet {
    /// `CookieRequest` structure.
    CookieRequest(CookieRequest),
    /// `CryptoHandshake` structure.
    CryptoHandshake(CryptoHandshake),
    /// `CryptoData` structure.
    CryptoData(CryptoData),
}

impl From<StatusPacket> for Packet {
    fn from(packet: StatusPacket) -> Self {
        match packet {
            StatusPacket::CookieRequest(packet) => Packet::CookieRequest(packet),
            StatusPacket::CryptoHandshake(packet) => Packet::CryptoHandshake(packet),
        }
    }
}

impl Into<DhtPacket> for Packet {
    fn into(self) -> DhtPacket {
        match self {
            Packet::CookieRequest(packet) => DhtPacket::CookieRequest(packet),
            Packet::CryptoHandshake(packet) => DhtPacket::CryptoHandshake(packet),
            Packet::CryptoData(packet) => DhtPacket::CryptoData(packet),
        }
    }
}

impl Into<TcpDataPayload> for Packet {
    fn into(self) -> TcpDataPayload {
        match self {
            Packet::CookieRequest(packet) => TcpDataPayload::CookieRequest(packet),
            Packet::CryptoHandshake(packet) => TcpDataPayload::CryptoHandshake(packet),
            Packet::CryptoData(packet) => TcpDataPayload::CryptoData(packet),
        }
    }
}

/// Arguments for creating new `NetCrypto`.
#[derive(Clone)]
pub struct NetCryptoNewArgs {
    /// Sink to send packets to UDP socket.
    pub udp_tx: UdpTx,
    /// Sink to send lossless packets. The key is a long term public key of the
    /// peer that sent this packet.
    pub lossless_tx: LosslessTx,
    /// Sink to send lossy packets. The key is a long term public key of the
    /// peer that sent this packet.
    pub lossy_tx: LossyTx,
    /// Our DHT `PublicKey`
    pub dht_pk: PublicKey,
    /// Our DHT `SecretKey`
    pub dht_sk: SecretKey,
    /// Our real `PublicKey`
    pub real_pk: PublicKey,
    /// Our real `SecretKey`
    pub real_sk: SecretKey,
    /// Lru cache for precomputed keys. It stores precomputed keys to avoid
    /// redundant calculations.
    pub precomputed_keys: PrecomputedCache,
}

/// Struct that manages crypto connections to friends and handles net crypto
/// packets from both UDP and TCP connections.
#[derive(Clone)]
pub struct NetCrypto {
    /// Sink to send packets to UDP socket.
    udp_tx: UdpTx,
    /// Sink to send TCP packets via relays.
    tcp_tx: Arc<RwLock<Option<TcpTx>>>,
    /// Sink to send DHT `PublicKey` when it gets known. The first key is a long
    /// term key, the second key is a DHT key. `NetCrypto` module can learn DHT
    /// `PublicKey` of peer from `Cookie` obtained from `CryptoHandshake`
    /// packet. If key from `Cookie` is not equal to saved key inside
    /// `CryptoConnection` then `NetCrypto` module will send message to this
    /// sink.
    dht_pk_tx: Arc<RwLock<Option<DhtPkTx>>>,
    /// Sink to send a connection status when it becomes connected or
    /// disconnected. The key is a long term key of the connection.
    connection_status_tx: Arc<RwLock<Option<ConnectionStatusTx>>>,
    /// Sink to send lossless packets. The key is a long term public key of the
    /// peer that sent this packet.
    lossless_tx: LosslessTx,
    /// Sink to send lossy packets. The key is a long term public key of the
    /// peer that sent this packet.
    lossy_tx: LossyTx,
    /// Our DHT `PublicKey`
    dht_pk: PublicKey,
    /// Our DHT `SecretKey`
    dht_sk: SecretKey,
    /// Our real `PublicKey`
    real_pk: PublicKey,
    /// Our real `SecretKey`
    real_sk: SecretKey,
    /// Symmetric key used for cookies encryption
    symmetric_key: secretbox::Key,
    /// List of friends used to check whether should we accept an incoming
    /// `NetCrypto` connection.
    friends: Arc<RwLock<HashSet<PublicKey>>>,
    /// Connection by long term public key of DHT node map
    connections: Arc<RwLock<HashMap<PublicKey, Arc<RwLock<CryptoConnection>>>>>,
    /// Long term keys by IP address of DHT node map. `SocketAddr` can't be used
    /// as a key since it contains additional info for `IPv6` address.
    keys_by_addr: Arc<RwLock<HashMap<(IpAddr, /*port*/ u16), PublicKey>>>,
    /// Lru cache for precomputed keys. It stores precomputed keys to avoid
    /// redundant calculations.
    precomputed_keys: PrecomputedCache,
}

impl NetCrypto {
    /// Create new `NetCrypto` object
    pub fn new(args: NetCryptoNewArgs) -> NetCrypto {
        NetCrypto {
            udp_tx: args.udp_tx,
            tcp_tx: Default::default(),
            dht_pk_tx: Default::default(),
            connection_status_tx: Default::default(),
            lossless_tx: args.lossless_tx,
            lossy_tx: args.lossy_tx,
            dht_pk: args.dht_pk,
            dht_sk: args.dht_sk,
            real_pk: args.real_pk,
            real_sk: args.real_sk,
            symmetric_key: secretbox::gen_key(),
            friends: Arc::new(RwLock::new(HashSet::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            keys_by_addr: Arc::new(RwLock::new(HashMap::new())),
            precomputed_keys: args.precomputed_keys,
        }
    }

    /// Add a friend to accept incoming connections from him.
    pub async fn add_friend(&self, real_pk: PublicKey) {
        self.friends.write().await.insert(real_pk);
    }

    /// Remove a friend to stop accepting incoming connections from him.
    pub async fn remove_friend(&self, real_pk: PublicKey) {
        self.friends.write().await.remove(&real_pk);
    }

    /// Add connection to a friend when its DHT `PublicKey` is known.
    pub async fn add_connection(&self, peer_real_pk: PublicKey, peer_dht_pk: PublicKey) {
        let mut connections = self.connections.write().await;

        if connections.contains_key(&peer_real_pk) {
            return;
        }

        let dht_precomputed_key = precompute(&peer_dht_pk, &self.dht_sk);
        let connection = CryptoConnection::new(
            &dht_precomputed_key,
            self.dht_pk,
            self.real_pk,
            peer_real_pk,
            peer_dht_pk
        );
        let connection = Arc::new(RwLock::new(connection));
        connections.insert(peer_real_pk, connection);
    }

    /// Clear stored addresses from `keys_by_addr`.
    async fn clear_keys_by_addr(&self, connection: &CryptoConnection) {
        if connection.udp_addr_v4.is_some() || connection.udp_addr_v6.is_some() {
            let mut keys_by_addr = self.keys_by_addr.write().await;
            if let Some(addr) = connection.get_udp_addr_v4() {
                keys_by_addr.remove(&(addr.ip(), addr.port()));
            }
            if let Some(addr) = connection.get_udp_addr_v6() {
                keys_by_addr.remove(&(addr.ip(), addr.port()));
            }
        }
    }

    /// Send connection status to the appropriate sink when it becomes connected
    /// or disconnected.
    async fn send_connection_status(&self, connection: &CryptoConnection, status: bool) -> Result<(), mpsc::SendError> {
        if connection.is_established() != status {
            let tx = (&*self.connection_status_tx.read().await).clone();
            maybe_send_unbounded(tx, (connection.peer_real_pk, status)).await
        } else {
            Ok(())
        }
    }

    /// Send kill packet to a connection if it's established or not confirmed.
    async fn send_kill_packet(&self, connection: &mut CryptoConnection) -> Result<(), SendDataError> {
        if connection.is_established() || connection.is_not_confirmed() {
            let packet_number = connection.send_array.buffer_end;
            self.send_data_packet(connection, vec![PACKET_ID_KILL], packet_number).await
        } else {
            Ok(())
        }
    }

    /// Kill a connection sending `PACKET_ID_KILL` packet and removing it from
    /// the connections list.
    pub async fn kill_connection(&self, real_pk: PublicKey) -> Result<(), KillConnectionError> {
        if let Some(connection) = self.connections.write().await.remove(&real_pk) {
            let mut connection = connection.write().await;
            self.clear_keys_by_addr(&connection).await;

            self.send_connection_status(&connection, false).await
                .map_err(|e| e.context(KillConnectionErrorKind::SendToConnectionStatus))?;
            self.send_kill_packet(&mut connection).await
                .map_err(|e| e.context(KillConnectionErrorKind::SendTo).into())
        } else {
            Err(KillConnectionErrorKind::NoConnection.into())
        }
    }

    /// Set friend's UDP IP address when it gets known.
    pub async fn set_friend_udp_addr(&self, real_pk: PublicKey, saddr: SocketAddr) {
        let connections = self.connections.read().await;
        let mut connection = if let Some(connection) = connections.get(&real_pk) {
            connection.write().await
        } else {
            return
        };

        if connection.get_udp_addr_v4() == Some(saddr) || connection.get_udp_addr_v6() == Some(saddr) {
            return
        }

        let mut keys_by_addr = self.keys_by_addr.write().await;
        let current_addr = if saddr.is_ipv4() {
            connection.get_udp_addr_v4()
        } else {
            connection.get_udp_addr_v6()
        };
        if let Some(saddr) = current_addr {
            keys_by_addr.remove(&(saddr.ip(), saddr.port()));
        }
        connection.set_udp_addr(saddr);
        keys_by_addr.insert((saddr.ip(), saddr.port()), real_pk);
    }

    /// Send lossless packet to a friend via established connection.
    pub async fn send_lossless(&self, real_pk: PublicKey, packet: Vec<u8>) -> Result<(), SendLosslessPacketError> {
        if packet.first().map_or(true, |&packet_id| packet_id <= PACKET_ID_CRYPTO_RANGE_END || packet_id >= PACKET_ID_LOSSY_RANGE_START) {
            return Err(SendLosslessPacketErrorKind::InvalidPacketId.into());
        }

        if let Some(connection) = self.connections.read().await.get(&real_pk) {
            let mut connection = connection.write().await;
            let packet_number = connection.send_array.buffer_end;
            if let Err(e) = connection.send_array.push_back(SentPacket::new(packet.clone())) {
                Err(e.context(SendLosslessPacketErrorKind::FullSendArray).into())
            } else {
                connection.packets_sent += 1;
                self.send_data_packet(&mut connection, packet, packet_number).await
                    .map_err(|e| e.context(SendLosslessPacketErrorKind::SendTo).into())
            }
        } else {
            Err(SendLosslessPacketErrorKind::NoConnection.into())
        }
    }

    /// Send `Packet` packet to UDP socket
    async fn send_to_udp(&self, addr: SocketAddr, packet: DhtPacket) -> Result<(), mpsc::SendError> {
        self.udp_tx.clone().send((packet, addr)).await
    }

    /// Get long term `PublicKey` of the peer by its UDP address
    async fn key_by_addr(&self, addr: SocketAddr) -> Option<PublicKey> {
        self.keys_by_addr.read().await.get(&(addr.ip(), addr.port())).cloned()
    }

    /// Get crypto connection by long term `PublicKey`
    async fn connection_by_key(&self, pk: PublicKey) -> Option<Arc<RwLock<CryptoConnection>>> {
        self.connections.read().await.get(&pk).cloned()
    }

    /// Get crypto connection by its UDP address
    async fn connection_by_addr(&self, addr: SocketAddr) -> Option<Arc<RwLock<CryptoConnection>>> {
        if let Some(pk) = self.key_by_addr(addr).await {
            self.connection_by_key(pk).await
        } else {
            None
        }
    }

    /// Get crypto connection by long term `PublicKey`
    async fn connection_by_dht_key(&self, pk: PublicKey) -> Option<Arc<RwLock<CryptoConnection>>> {
        // TODO: should it be optimized?
        for connection in self.connections.read().await.values() {
            if connection.read().await.peer_dht_pk == pk {
                return Some(connection.clone());
            }
        }
        None
    }

    /// Create `CookieResponse` packet with `Cookie` requested by `CookieRequest` packet
    async fn handle_cookie_request(&self, packet: &CookieRequest) -> Result<CookieResponse, HandlePacketError> {
        let payload = packet.get_payload(&self.precomputed_keys.get(packet.pk).await)
            .map_err(|e| e.context(HandlePacketErrorKind::GetPayload))?;

        let cookie = Cookie::new(payload.pk, packet.pk);
        let encrypted_cookie = EncryptedCookie::new(&self.symmetric_key, &cookie);

        let response_payload = CookieResponsePayload {
            cookie: encrypted_cookie,
            id: payload.id,
        };
        let precomputed_key = precompute(&packet.pk, &self.dht_sk);
        let response = CookieResponse::new(&precomputed_key, &response_payload);

        Ok(response)
    }

    /// Handle `CookieRequest` packet received from UDP socket
    pub async fn handle_udp_cookie_request(&self, packet: &CookieRequest, addr: SocketAddr) -> Result<(), HandlePacketError> {
        match self.handle_cookie_request(packet).await {
            Ok(response) => self.send_to_udp(addr, DhtPacket::CookieResponse(response)).await
                .map_err(|e| e.context(HandlePacketErrorKind::SendTo).into()),
            Err(e) => Err(e),
        }
    }

    /// Handle `CookieRequest` packet received from TCP socket
    pub async fn handle_tcp_cookie_request(&self, packet: &CookieRequest, sender_pk: PublicKey) -> Result<(), HandlePacketError> {
        match self.handle_cookie_request(packet).await {
            Ok(response) => {
                let msg = (TcpDataPayload::CookieResponse(response), sender_pk);
                maybe_send_bounded(self.tcp_tx.read().await.clone(), msg).await
                    .map_err(|e| e.context(HandlePacketErrorKind::SendTo).into())
            }
            Err(e) => Err(e),
        }
    }

    /// Handle `CookieResponse` and if it's correct change connection status to `HandshakeSending`.
    pub async fn handle_cookie_response(&self, connection: &mut CryptoConnection, packet: &CookieResponse)
        -> Result<(), HandlePacketError> {
        let cookie_request_id = if let ConnectionStatus::CookieRequesting { cookie_request_id, .. } = connection.status {
            cookie_request_id
        } else {
            return Err(HandlePacketError::from(HandlePacketErrorKind::InvalidState))
        };

        let payload = match packet.get_payload(&self.precomputed_keys.get(connection.peer_dht_pk).await) {
            Ok(payload) => payload,
            Err(e) => return Err(e.context(HandlePacketErrorKind::GetPayload).into()),
        };

        if payload.id != cookie_request_id {
            return Err(HandlePacketError::invalid_request_id(cookie_request_id, payload.id))
        }

        let sent_nonce = gen_nonce();
        let our_cookie = Cookie::new(connection.peer_real_pk, connection.peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&self.symmetric_key, &our_cookie);
        let handshake_payload = CryptoHandshakePayload {
            base_nonce: sent_nonce,
            session_pk: connection.session_pk,
            cookie_hash: payload.cookie.hash(),
            cookie: our_encrypted_cookie,
        };
        let handshake = CryptoHandshake::new(&precompute(&connection.peer_real_pk, &self.real_sk), &handshake_payload, payload.cookie);

        connection.status = ConnectionStatus::HandshakeSending {
            sent_nonce,
            packet: StatusPacketWithTime::new_crypto_handshake(handshake)
        };

        self.send_status_packet(connection)
            .map_err(|e| e.context(HandlePacketErrorKind::SendTo).into()).await
    }

    /// Handle `CookieResponse` packet received from UDP socket
    pub async fn handle_udp_cookie_response(&self, packet: &CookieResponse, addr: SocketAddr)
        -> Result<(), HandlePacketError> {
        if let Some(connection) = self.connection_by_addr(addr).await {
            let mut connection = connection.write().await;
            connection.set_udp_addr(addr);
            self.handle_cookie_response(&mut connection, packet).await
        } else {
            Err(HandlePacketError::no_udp_connection(addr))
        }
    }

    /// Handle `CookieResponse` packet received from TCP socket
    pub async fn handle_tcp_cookie_response(&self, packet: &CookieResponse, sender_pk: PublicKey)
        -> Result<(), HandlePacketError> {
        let connection = self.connection_by_dht_key(sender_pk).await;
        if let Some(connection) = connection {
            let mut connection = connection.write().await;
            self.handle_cookie_response(&mut connection, packet).await
        } else {
            Err(HandlePacketError::no_tcp_connection(sender_pk))
        }
    }

    /// Check that incoming `CryptoHandshake` request is valid:
    /// - cookie is not timed out
    /// - hash for the cookie inside the payload is correct
    fn validate_crypto_handshake(&self, packet: &CryptoHandshake)
        -> Result<(Cookie, CryptoHandshakePayload, PrecomputedKey), HandlePacketError> {
        let cookie = match packet.cookie.get_payload(&self.symmetric_key) {
            Ok(cookie) => cookie,
            Err(e) => return Err(e.context(HandlePacketErrorKind::GetPayload).into()),
        };

        if cookie.is_timed_out() {
            return Err(HandlePacketErrorKind::CookieTimedOut.into());
        }

        let real_precomputed_key = precompute(&cookie.real_pk, &self.real_sk);

        let payload = match packet.get_payload(&real_precomputed_key) {
            Ok(payload) => payload,
            Err(e) => return Err(e.context(HandlePacketErrorKind::GetPayload).into()),
        };

        if packet.cookie.hash() != payload.cookie_hash {
            return Err(HandlePacketErrorKind::BadSha512.into());
        }

        Ok((cookie, payload, real_precomputed_key))
    }

    /// Handle `CryptoHandshake` and if it's correct change connection status to `NotConfirmed`.
    pub async fn handle_crypto_handshake(&self, connection: &mut CryptoConnection, packet: &CryptoHandshake)
        -> Result<(), HandlePacketError> {
        if let ConnectionStatus::Established { .. } = connection.status {
            return Err(HandlePacketError::from(HandlePacketErrorKind::InvalidState))
        }

        let (cookie, payload, real_precomputed_key) = match self.validate_crypto_handshake(packet) {
            Ok(result) => result,
            Err(e) => return Err(e),
        };

        if cookie.real_pk != connection.peer_real_pk {
            return Err(HandlePacketError::from(HandlePacketErrorKind::InvalidRealPk))
        }
        if cookie.dht_pk != connection.peer_dht_pk {
            let msg = (connection.peer_real_pk, cookie.dht_pk);

            let dht_pk_future = maybe_send_unbounded(self.dht_pk_tx.read().await.clone(), msg)
                .map_err(|e| e.context(HandlePacketErrorKind::SendToDhtpk).into());

            return dht_pk_future.and_then(|()| future::err(
                HandlePacketError::from(HandlePacketErrorKind::InvalidDhtPk)
            )).await
        }

        connection.status = match connection.status {
            ConnectionStatus::CookieRequesting { .. } => {
                let sent_nonce = gen_nonce();
                let our_cookie = Cookie::new(connection.peer_real_pk, connection.peer_dht_pk);
                let our_encrypted_cookie = EncryptedCookie::new(&self.symmetric_key, &our_cookie);
                let handshake_payload = CryptoHandshakePayload {
                    base_nonce: sent_nonce,
                    session_pk: connection.session_pk,
                    cookie_hash: payload.cookie.hash(),
                    cookie: our_encrypted_cookie,
                };
                let handshake = CryptoHandshake::new(&real_precomputed_key, &handshake_payload, payload.cookie);
                ConnectionStatus::NotConfirmed {
                    sent_nonce,
                    received_nonce: payload.base_nonce,
                    session_precomputed_key: precompute(&payload.session_pk, &connection.session_sk),
                    packet: StatusPacketWithTime::new_crypto_handshake(handshake)
                }
            },
            ConnectionStatus::HandshakeSending { sent_nonce, ref packet, .. }
            | ConnectionStatus::NotConfirmed { sent_nonce, ref packet, .. } => ConnectionStatus::NotConfirmed {
                sent_nonce,
                received_nonce: payload.base_nonce,
                session_precomputed_key: precompute(&payload.session_pk, &connection.session_sk),
                packet: packet.clone()
            },
            ConnectionStatus::Established { .. } => unreachable!("Checked for Established status above"),
        };

        self.send_status_packet(connection).await
            .map_err(|e| e.context(HandlePacketErrorKind::SendTo).into())
    }

    /// Handle incoming `CryptoHandshake` in case when we don't have associated
    /// with sender connection.
    async fn handle_crypto_handshake_new_connection(&self, packet: &CryptoHandshake, addr: Option<SocketAddr>)
        -> Result<(), HandlePacketError> {
        let (cookie, payload, _real_precomputed_key) = match self.validate_crypto_handshake(packet) {
            Ok(result) => result,
            Err(e) => return Err(e),
        };

        if !self.friends.read().await.contains(&cookie.real_pk) {
            return Err(HandlePacketErrorKind::UnexpectedCryptoHandshake.into());
        }

        let mut connections = self.connections.write().await;

        if let Some(connection) = connections.get(&cookie.real_pk) {
            let mut connection = connection.write().await;
            if connection.peer_dht_pk != cookie.dht_pk {
                // We received a handshake packet for an existent connection
                // from a new address and this packet contains a different DHT
                // PublicKey. In this case we kill the old connection and create
                // a new one.

                self.clear_keys_by_addr(&connection).await;
                self.send_connection_status(&connection, false).await
                    .map_err(|e|
                        HandlePacketError::from(e.context(HandlePacketErrorKind::SendToConnectionStatus))
                    )?;
                self.send_kill_packet(&mut connection).await
                    .map_err(|e|
                        HandlePacketError::from(e.context(HandlePacketErrorKind::SendTo))
                    )?;
            } else {
                // We received a handshake packet for an existent connection
                // from a new address and this packet contains the same DHT
                // PublicKey. In this case we reject this packet if we already
                // received a handshake from the old connection and accept it
                // otherwise.

                if connection.is_established() || connection.is_not_confirmed() {
                    return Err(HandlePacketErrorKind::UnexpectedCryptoHandshake.into());
                }

                self.clear_keys_by_addr(&connection).await;
            }
        };

        let mut connection = CryptoConnection::new_not_confirmed(
            &self.real_sk,
            cookie.real_pk,
            cookie.dht_pk,
            payload.base_nonce,
            payload.session_pk,
            payload.cookie,
            &self.symmetric_key,
        );
        if let Some(addr) = addr {
            connection.set_udp_addr(addr);
            self.keys_by_addr.write().await.insert((addr.ip(), addr.port()), cookie.real_pk);
        }
        let connection = Arc::new(RwLock::new(connection));
        connections.insert(cookie.real_pk, connection);

        let msg = (cookie.real_pk, cookie.dht_pk);
        maybe_send_unbounded(self.dht_pk_tx.read().await.clone(), msg).await
            .map_err(|e| e.context(HandlePacketErrorKind::SendToDhtpk).into())
    }

    /// Handle `CryptoHandshake` packet received from UDP socket
    pub async fn handle_udp_crypto_handshake(&self, packet: &CryptoHandshake, addr: SocketAddr)
        -> Result<(), HandlePacketError> {
        if let Some(connection) = self.connection_by_addr(addr).await {
            let mut connection = connection.write().await;
            connection.set_udp_addr(addr);
            self.handle_crypto_handshake(&mut connection, packet).await
        } else {
            self.handle_crypto_handshake_new_connection(packet, Some(addr)).await
        }
    }

    /// Handle `CryptoHandshake` packet received from TCP socket
    pub async fn handle_tcp_crypto_handshake(&self, packet: &CryptoHandshake, sender_pk: PublicKey)
        -> Result<(), HandlePacketError> {
        let connection = self.connection_by_dht_key(sender_pk).await;
        if let Some(connection) = connection {
            let mut connection = connection.write().await;
            self.handle_crypto_handshake(&mut connection, packet).await
        } else {
            self.handle_crypto_handshake_new_connection(packet, None).await
        }
    }

    /** Handle request packet marking requested packets if rtt is elapsed since
    they were sent and removing delivered packets.

    Request array consists of bytes where every byte means offset of the
    requested packet starting from 1. Each 0 means adding 255 to the offset
    until non 0 byte is reached. For example, array of bytes [3 3 0 0 0 253]
    means that packets 2, 5 and 1023 were requested (if the first index is 0).

    */
    fn handle_request_packet(send_array: &mut PacketsArray<SentPacket>, mut data: &[u8], rtt: Duration, last_sent_time: &mut Option<Instant>) {
        // n is a packet number corresponding to numbers from the request
        let mut n = 1;

        // Cycle over sent packets to mark them requested or to delete them if
        // they are not requested which means they are delivered
        for i in send_array.buffer_start .. send_array.buffer_end {
            // Stop if there is no more request numbers to handle
            if data.is_empty() {
                break
            }

            if n == data[0] { // packet is requested
                if let Some(packet) = send_array.get_mut(i) {
                    if clock_elapsed(packet.sent_time) > rtt { // mark it if it wasn't delivered in time
                        packet.requested = true;
                    }
                }
                n = 0;
                data = &data[1..];
            } else if let Some(packet) = send_array.remove(i) { // packet is not requested, delete it
                if last_sent_time.map(|time| time < packet.sent_time).unwrap_or(true) {
                    *last_sent_time = Some(packet.sent_time);
                }
            }

            if n == 255 {
                // n went through all the values except 0
                // which means that request byte is 0
                // which means that requested packet number is greater than 255
                // so just reset n and go farther
                n = 1;
                data = &data[1..];
            } else {
                n += 1;
            }
        }
    }

    /// Build request packet that will contain numbers of missing packets that
    /// we should receive.
    fn generate_request_packet(recv_array: &PacketsArray<RecvPacket>) -> Vec<u8> {
        let mut data = Vec::with_capacity(MAX_CRYPTO_DATA_SIZE);
        data.push(PACKET_ID_REQUEST);

        // n is a packet number relative to the last missing packet
        let mut n = 1;

        // go through all received packets and put numbers of missing packets to the request
        for i in recv_array.buffer_start .. recv_array.buffer_end {
            if !recv_array.contains(i) {
                data.push(n);
                n = 0;
            } else if n == 255 {
                data.push(0);
                n = 0;
            }

            if data.len() == MAX_CRYPTO_DATA_SIZE {
                return data;
            }

            n += 1;
        }

        data
    }

    /// Send received lossless packets from the beginning of the receiving
    /// buffer to lossless sink and delete them
    async fn process_ready_lossless_packets(&self, recv_array: &mut PacketsArray<RecvPacket>, pk: PublicKey)
        -> Result<(), mpsc::SendError> {
        let mut tx = self.lossless_tx.clone();

        while let Some(packet) = recv_array.pop_front() {
            tx.send((pk, packet.data)).await?;
        }

        Ok(())
    }

    /// Find the time when the last acknowledged packet was sent. This time is
    /// used to update rtt
    fn last_sent_time(send_array: &PacketsArray<SentPacket>, index: u32) -> Option<Instant> {
        let mut last_sent_time = None;
        for i in send_array.buffer_start .. index {
            if let Some(packet) = send_array.get(i) {
                if last_sent_time.map(|time| time < packet.sent_time).unwrap_or(true) {
                    last_sent_time = Some(packet.sent_time);
                }
            }
        }
        last_sent_time
    }

    /** Handle `CryptoData` packet

    Every data packet contains `buffer_start` index. All packets with index
    lower than `buffer_start` index were received by other side. So we can
    delete all these packets from sent packets array.

    Then depending on type of the data packet we can do:
    - kill type: kill the connection
    - request type: mark packets from the sent packets buffer that they should
      be sent and delete delivered packets
    - lossless type: add packet to the received packets buffer and process
      packets from the beginning of this buffer
    - lossy type: just process the packet
    */
    async fn handle_crypto_data(&self,
        connection: &mut CryptoConnection,
        packet: &CryptoData,
        udp: bool
    ) -> Result<(), HandlePacketError> {
        let (sent_nonce, mut received_nonce, session_precomputed_key) =
            match connection.status {
                ConnectionStatus::NotConfirmed {
                    sent_nonce,
                    received_nonce,
                    ref session_precomputed_key,
                    ..
                }
                | ConnectionStatus::Established {
                    sent_nonce,
                    received_nonce,
                    ref session_precomputed_key
                } => {
                    (sent_nonce, received_nonce, session_precomputed_key.clone())
                },
                _ => {
                    return Err(HandlePacketError::from(
                        HandlePacketErrorKind::CannotHandleCryptoData)
                    )

                }
            };

        let cur_last_bytes = CryptoData::nonce_last_bytes(received_nonce);
        let (diff, _) = packet.nonce_last_bytes.overflowing_sub(cur_last_bytes);
        let mut packet_nonce = received_nonce;
        increment_nonce_number(&mut packet_nonce, u64::from(diff));

        let payload = match packet.get_payload(&session_precomputed_key, &packet_nonce) {
            Ok(payload) => payload,
            Err(e) => return Err(e.context(HandlePacketErrorKind::GetPayload).into())
        };

        // Find the time when the last acknowledged packet was sent
        let mut last_sent_time = NetCrypto::last_sent_time(
            &connection.send_array,
            payload.buffer_start
        );

        // Remove all acknowledged packets and set new start index to the send buffer
        if let Err(e) = connection.send_array.set_buffer_start(payload.buffer_start) {
            return Err(e.context(HandlePacketErrorKind::PacketsArrayError).into())
        }

        // And get the ID of the packet
        let packet_id = match payload.data.first() {
            Some(&packet_id) => packet_id,
            None => return Err(HandlePacketError::from(HandlePacketErrorKind::DataEmpty))
        };

        if packet_id == PACKET_ID_KILL {
            // Kill the connection
            self.connections.write().await.remove(&connection.peer_real_pk);
            self.clear_keys_by_addr(&connection).await;
            return self.send_connection_status(&connection, false)
                .map_err(|e| e.context(HandlePacketErrorKind::SendToConnectionStatus).into()).await;
        }

        // Update nonce if diff is big enough
        if diff > NONCE_DIFF_THRESHOLD * 2 {
            increment_nonce_number(&mut received_nonce, u64::from(NONCE_DIFF_THRESHOLD));
        }

        self.send_connection_status(&connection, true).await
            .map_err(|e| e.context(HandlePacketErrorKind::SendToConnectionStatus))?;

        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            session_precomputed_key
        };

        if packet_id == PACKET_ID_REQUEST {
            // Use const RTT in case of TCP connection
            let rtt = if udp { connection.rtt } else { TCP_RTT };
            NetCrypto::handle_request_packet(
                &mut connection.send_array,
                &payload.data[1..],
                rtt, &mut last_sent_time
            );
            // Update end index of received buffer ignoring the error - we still
            // want to handle this packet even if connection is too slow
            connection.recv_array.set_buffer_end(payload.packet_number).ok();
        } else if packet_id > PACKET_ID_CRYPTO_RANGE_END && packet_id < PACKET_ID_LOSSY_RANGE_START {
            if let Err(e) = connection.recv_array.insert(payload.packet_number, RecvPacket::new(payload.data)) {
                return Err(e.context(HandlePacketErrorKind::PacketsArrayError).into())
            }
            connection.packets_received += 1;
            self.process_ready_lossless_packets(&mut connection.recv_array, connection.peer_real_pk).await
                .map_err(|e| e.context(HandlePacketErrorKind::SendToLossless))?;
        } else if packet_id >= PACKET_ID_LOSSY_RANGE_START && packet_id <= PACKET_ID_LOSSY_RANGE_END {
            // Update end index of received buffer ignoring the error - we still
            // want to handle this packet even if connection is too slow
            connection.recv_array.set_buffer_end(payload.packet_number).ok();
            let mut tx = self.lossy_tx.clone();
            let peer_real_pk = connection.peer_real_pk;
            let data = payload.data.clone();

            tx.send((peer_real_pk, data)).await
                .map_err(|e| e.context(HandlePacketErrorKind::SendToLossy))?;
        } else {
            return Err(HandlePacketError::packet_id(packet_id))
        };

        // TODO: update rtt only when udp is true?
        if let Some(last_sent_time) = last_sent_time {
            // Update rtt if it's become lower
            let elapsed = clock_elapsed(last_sent_time);
            if elapsed < connection.rtt {
                connection.rtt = elapsed;
            }
        }

        Ok(())
    }

    /// Handle `CryptoData` packet received from UDP socket
    pub async fn handle_udp_crypto_data(&self, packet: &CryptoData, addr: SocketAddr) -> Result<(), HandlePacketError> {
        if let Some(connection) = self.connection_by_addr(addr).await {
            let mut connection = connection.write().await;
            connection.set_udp_addr(addr);
            self.handle_crypto_data(&mut connection, packet, /* udp */ true).await
        } else {
            Err(HandlePacketError::no_udp_connection(addr))
        }
    }

    /// Handle `CryptoData` packet received from TCP socket
    pub async fn handle_tcp_crypto_data(&self, packet: &CryptoData, sender_pk: PublicKey) -> Result<(), HandlePacketError> {
        if let Some(connection) = self.connection_by_dht_key(sender_pk).await {
            let mut connection = connection.write().await;
            self.handle_crypto_data(&mut connection, packet, /* udp */ false).await
        } else {
            Err(HandlePacketError::no_tcp_connection(sender_pk))
        }
    }

    /// Send packet to crypto connection choosing TCP or UDP protocol
    async fn send_packet(&self, packet: Packet, connection: &mut CryptoConnection) -> Result<(), SendPacketError> {
        // TODO: can backpressure be used instead of congestion control? It
        // seems it's possible to implement wrapper for bounded sender with
        // priority queue and just send packets there
        if let Some(addr) = connection.get_udp_addr() {
            if connection.is_udp_alive() {
                return self.send_to_udp(addr, packet.into()).await
                    .map_err(|e| e.context(SendPacketErrorKind::Udp).into())
            }

            let dht_packet: DhtPacket = packet.clone().into();
            let udp_attempt_should_be_made = connection.udp_attempt_should_be_made() && {
                // check if the packet is not too big
                let mut buf = [0; DHT_ATTEMPT_MAX_PACKET_LENGTH];
                dht_packet.to_bytes((&mut buf, 0)).is_ok()
            };

            if udp_attempt_should_be_made {
                connection.update_udp_send_attempt_time();
                self.send_to_udp(addr, dht_packet).await
                    .map_err(|e| e.context(SendPacketErrorKind::Udp))?;
            }
        };

        let tcp_tx = self.tcp_tx.read().await.clone();
        maybe_send_bounded(tcp_tx, (packet.into(), connection.peer_dht_pk)).await
            .map_err(|e| e.context(SendPacketErrorKind::Tcp).into())
    }

    /// Send `CookieRequest` or `CryptoHandshake` packet if needed depending on
    /// connection status and update sent counter
    async fn send_status_packet(&self, connection: &mut CryptoConnection) -> Result<(), SendPacketError> {
        match connection.packet_to_send() {
            Some(packet) => self.send_packet(packet.into(), connection).await,
            None => Ok(()),
        }
    }

    /// Send `CryptoData` packet if the connection is established.
    async fn send_data_packet(&self, connection: &mut CryptoConnection, data: Vec<u8>, packet_number: u32)
        -> Result<(), SendDataError> {
        let packet = match connection.status {
            ConnectionStatus::NotConfirmed { ref mut sent_nonce, ref session_precomputed_key, .. }
            | ConnectionStatus::Established { ref mut sent_nonce, ref session_precomputed_key, .. } => {
                let payload = CryptoDataPayload {
                    buffer_start: connection.recv_array.buffer_start,
                    packet_number,
                    data,
                };
                let packet = CryptoData::new(session_precomputed_key, *sent_nonce, &payload);
                increment_nonce(sent_nonce);
                packet
            },
            _ => return Err(SendDataError::from(SendDataErrorKind::NoConnection)),
        };
        self.send_packet(Packet::CryptoData(packet), connection).await
            .map_err(|e| e.context(SendDataErrorKind::SendTo).into())
    }

    /// Send request packet with indices of not received packets.
    async fn send_request_packet(&self, connection: &mut CryptoConnection) -> Result<(), SendDataError> {
        let data = NetCrypto::generate_request_packet(&connection.recv_array);
        let packet_number = connection.send_array.buffer_end;
        // TODO: set only if packet was sent successfully?
        connection.request_packet_sent_time = Some(clock_now());
        self.send_data_packet(connection, data, packet_number).await
    }

    /// Send packets that were requested.
    async fn send_requested_packets(&self, connection: &mut CryptoConnection) -> Result<(), SendDataError> {
        let now = clock_now();
        let packets = connection.send_array.iter_mut()
            .filter(|(_, packet)| packet.requested)
            .map(|(i, packet)| {
                packet.requested = false;
                packet.sent_time = now;
                (i, packet.data.clone())
            }).collect::<Vec<_>>();

        for (i, data) in packets {
            self.send_data_packet(connection, data, i).await?;
        };

        Ok(())
    }

    /// The main loop that should be run at least 20 times per second
    async fn main_loop(&self) -> Result<(), SendDataError> {
        let mut connections = self.connections.write().await;
        let mut keys_by_addr = self.keys_by_addr.write().await;
        let mut to_remove = Vec::new();

        // Only one cycle over all connections to prevent many lock acquirements
        for (&pk, connection) in connections.iter() {
            let mut connection = connection.write().await;

            if connection.is_timed_out() {
                if let Some(addr) = connection.get_udp_addr_v4() {
                    keys_by_addr.remove(&(addr.ip(), addr.port()));
                }
                if let Some(addr) = connection.get_udp_addr_v6() {
                    keys_by_addr.remove(&(addr.ip(), addr.port()));
                }

                if connection.is_established() {
                    self.send_connection_status(&connection, false).await
                        .map_err(|e| e.context(SendDataErrorKind::SendToConnectionStatus))?;
                }

                if connection.is_established() || connection.is_not_confirmed() {
                    self.send_kill_packet(&mut connection).await?;
                }

                to_remove.push(pk);
            }

            self.send_status_packet(&mut connection).await
                .map_err(|e| e.context(SendDataErrorKind::SendTo))?;

            if connection.is_not_confirmed() || connection.is_established() {
                let should_send = connection.request_packet_sent_time.map_or(true, |time|
                    clock_elapsed(time) > CRYPTO_SEND_PACKET_INTERVAL
                );
                if should_send {
                    self.send_request_packet(&mut connection).await?;
                }
            }

            if connection.is_established() {
                if connection.packet_recv_rate > CRYPTO_PACKET_MIN_RATE {
                    let request_packet_interval = connection.request_packet_interval();
                    let should_send = connection.request_packet_sent_time.map_or(true, |time|
                        clock_elapsed(time) > request_packet_interval
                    );
                    if should_send {
                        self.send_request_packet(&mut connection).await?;
                    }
                }

                // TODO: either use send_rate or remove it
                connection.update_congestion_stats();

                self.send_requested_packets(&mut connection).await?;
            }
        }

        for pk in to_remove {
            connections.remove(&pk);
        }

        Ok(())
    }

    /// Run `net_crypto` periodical tasks. Result future will never be completed
    /// successfully.
    pub async fn run(&self) -> Result<(), RunError> {
        let mut wakeups = tokio::time::interval(PACKET_COUNTER_AVERAGE_INTERVAL);

        loop {
            wakeups.tick().await;

            let fut = tokio::time::timeout(
                PACKET_COUNTER_AVERAGE_INTERVAL, self.main_loop()
            );

            let res =
                match fut.await {
                    Err(e) => Err(e.context(RunErrorKind::SendData).into()),
                    Ok(Err(e)) => Err(e.context(RunErrorKind::SendData).into()),
                    Ok(Ok(_)) => Ok(()),
                };

            if let Err(ref e) = res {
                warn!("Failed to send net crypto packets: {}", e);
                return res
            }
        }
    }

    /// Set sink to send DHT `PublicKey` when it gets known.
    pub async fn set_dht_pk_sink(&self, dht_pk_tx: DhtPkTx) {
        *self.dht_pk_tx.write().await = Some(dht_pk_tx);
    }

    /// Set sink to send a connection status when it becomes connected or
    /// disconnected.
    pub async fn set_connection_status_sink(&self, connection_status_tx: ConnectionStatusTx) {
        *self.connection_status_tx.write().await = Some(connection_status_tx);
    }

    /// Set sink for sending TCP packets via relays.
    pub async fn set_tcp_sink(&self, tcp_tx: TcpTx) {
        *self.tcp_tx.write().await = Some(tcp_tx);
    }
}

#[cfg(test)]
mod tests {
    // https://github.com/rust-lang/rust/issues/61520
    use super::{*, Packet};
    use futures::{Future, StreamExt};

    impl NetCrypto {
        pub async fn has_friend(&self, pk: &PublicKey) -> bool {
            self.friends.read().await.contains(pk)
        }

        pub async fn connection_dht_pk(&self, pk: &PublicKey) -> Option<PublicKey> {
            if let Some(connection) = self.connections.read().await.get(pk) {
                Some(connection.read().await.peer_dht_pk)
            } else {
                None
            }
        }

        pub async fn connection_saddr(&self, pk: &PublicKey) -> Option<SocketAddr> {
            if let Some(connection) = self.connections.read().await.get(pk) {
                connection.read().await.get_udp_addr()
            } else {
                None
            }
        }

        pub async fn add_established_connection(
            &self,
            peer_dht_pk: PublicKey,
            peer_real_pk: PublicKey,
            sent_nonce: Nonce,
            received_nonce: Nonce,
            session_precomputed_key: PrecomputedKey
        ) {
            let dht_precomputed_key = precompute(&peer_dht_pk, &self.dht_sk);
            let mut connection = CryptoConnection::new(&dht_precomputed_key, self.dht_pk, self.real_pk, peer_real_pk, peer_dht_pk);
            connection.status = ConnectionStatus::Established {
                sent_nonce,
                received_nonce,
                session_precomputed_key,
            };
            self.connections.write().await.insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        }

        pub fn get_cookie(&self, real_pk: PublicKey, dht_pk: PublicKey) -> EncryptedCookie {
            let cookie = Cookie::new(real_pk, dht_pk);
            EncryptedCookie::new(&self.symmetric_key, &cookie)
        }

        pub async fn get_session_pk(&self, friend_pk: &PublicKey) -> Option<PublicKey> {
            if let Some(connection) = self.connections.read().await.get(friend_pk) {
                Some(connection.read().await.session_pk)
            } else {
                None
            }
        }
    }

    #[tokio::test]
    async fn add_remove_friend() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_real_pk, _peer_real_sk) = gen_keypair();

        net_crypto.add_friend(peer_real_pk).await;
        assert!(net_crypto.friends.read().await.contains(&peer_real_pk));
        net_crypto.remove_friend(peer_real_pk).await;
        assert!(!net_crypto.friends.read().await.contains(&peer_real_pk));
    }

    #[tokio::test]
    async fn handle_cookie_request() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let cookie_request_id = 12345;

        let cookie_request_payload = CookieRequestPayload {
            pk: peer_real_pk,
            id: cookie_request_id,
        };
        let cookie_request = CookieRequest::new(&precomputed_key, &peer_dht_pk, &cookie_request_payload);

        let cookie_response = net_crypto.handle_cookie_request(&cookie_request).await.unwrap();
        let cookie_response_payload = cookie_response.get_payload(&precomputed_key).unwrap();

        assert_eq!(cookie_response_payload.id, cookie_request_id);

        let cookie = cookie_response_payload.cookie.get_payload(&net_crypto.symmetric_key).unwrap();
        assert_eq!(cookie.dht_pk, peer_dht_pk);
        assert_eq!(cookie.real_pk, peer_real_pk);
    }

    #[tokio::test]
    async fn handle_cookie_request_invalid() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let cookie_request = CookieRequest {
            pk: gen_keypair().0,
            nonce: gen_nonce(),
            payload: vec![42; 88]
        };

        let res = net_crypto.handle_cookie_request(&cookie_request).await;
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::GetPayload);
    }

    #[tokio::test]
    async fn handle_udp_cookie_request() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let cookie_request_id = 12345;

        let cookie_request_payload = CookieRequestPayload {
            pk: peer_real_pk,
            id: cookie_request_id,
        };
        let cookie_request = CookieRequest::new(&precomputed_key, &peer_dht_pk, &cookie_request_payload);

        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.handle_udp_cookie_request(&cookie_request, addr).await.unwrap();

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();
        let cookie_response = unpack!(packet, DhtPacket::CookieResponse);

        assert_eq!(addr_to_send, addr);

        let cookie_response_payload = cookie_response.get_payload(&precomputed_key).unwrap();

        assert_eq!(cookie_response_payload.id, cookie_request_id);

        let cookie = cookie_response_payload.cookie.get_payload(&net_crypto.symmetric_key).unwrap();
        assert_eq!(cookie.dht_pk, peer_dht_pk);
        assert_eq!(cookie.real_pk, peer_real_pk);
    }

    #[tokio::test]
    async fn handle_tcp_cookie_request() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (net_crypto_tcp_tx, net_crypto_tcp_rx) = mpsc::channel(1);
        net_crypto.set_tcp_sink(net_crypto_tcp_tx).await;

        let cookie_request_id = 12345;

        let cookie_request_payload = CookieRequestPayload {
            pk: peer_real_pk,
            id: cookie_request_id,
        };
        let cookie_request = CookieRequest::new(&precomputed_key, &peer_dht_pk, &cookie_request_payload);

        net_crypto.handle_tcp_cookie_request(&cookie_request, peer_dht_pk).await.unwrap();

        let (received, _net_crypto_tcp_rx) = net_crypto_tcp_rx.into_future().await;
        let (packet, pk_to_send) = received.unwrap();
        let cookie_response = unpack!(packet, TcpDataPayload::CookieResponse);

        assert_eq!(pk_to_send, peer_dht_pk);

        let cookie_response_payload = cookie_response.get_payload(&precomputed_key).unwrap();

        assert_eq!(cookie_response_payload.id, cookie_request_id);

        let cookie = cookie_response_payload.cookie.get_payload(&net_crypto.symmetric_key).unwrap();
        assert_eq!(cookie.dht_pk, peer_dht_pk);
        assert_eq!(cookie.real_pk, peer_real_pk);
    }

    #[tokio::test]
    async fn handle_udp_cookie_request_invalid() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let cookie_request = CookieRequest {
            pk: gen_keypair().0,
            nonce: gen_nonce(),
            payload: vec![42; 88]
        };

        let addr = "127.0.0.1:12345".parse().unwrap();

        let res = net_crypto.handle_udp_cookie_request(&cookie_request, addr).await;
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::GetPayload);
    }

    #[tokio::test]
    async fn handle_cookie_response() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let cookie_request_id = unpack!(connection.status, ConnectionStatus::CookieRequesting, cookie_request_id);

        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let cookie_response_payload = CookieResponsePayload {
            cookie: cookie.clone(),
            id: cookie_request_id
        };
        let cookie_response = CookieResponse::new(&dht_precomputed_key, &cookie_response_payload);

        net_crypto.handle_cookie_response(&mut connection, &cookie_response).await.unwrap();

        let packet = unpack!(connection.status, ConnectionStatus::HandshakeSending, packet);
        let packet = unpack!(packet.packet, StatusPacket::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&precompute(&real_pk, &peer_real_sk)).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[tokio::test]
    async fn handle_cookie_response_invalid_status() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk: real_sk.clone(),
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new_not_confirmed(
            &real_sk,
            peer_real_pk,
            peer_dht_pk,
            gen_nonce(),
            gen_keypair().0,
            EncryptedCookie {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; 88]
            },
            &net_crypto.symmetric_key
        );

        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let cookie_response_payload = CookieResponsePayload {
            cookie,
            id: 12345
        };
        let cookie_response = CookieResponse::new(&precompute(&peer_dht_pk, &dht_sk), &cookie_response_payload);

        let res = net_crypto.handle_cookie_response(&mut connection, &cookie_response).await;
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::InvalidState);
    }

    #[tokio::test]
    async fn handle_cookie_response_invalid_request_id() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let cookie_request_id = unpack!(connection.status, ConnectionStatus::CookieRequesting, cookie_request_id);

        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let cookie_response_payload = CookieResponsePayload {
            cookie,
            id: cookie_request_id.overflowing_add(1).0
        };
        let cookie_response = CookieResponse::new(&dht_precomputed_key, &cookie_response_payload);

        assert!(net_crypto.handle_cookie_response(&mut connection, &cookie_response).await.is_err());
    }

    async fn handle_cookie_response_test<'a, R, F>(handle_function: F)
    where
        R: Future<Output=NetCrypto>,
        F: Fn(NetCrypto, CookieResponse, SocketAddr, PublicKey) -> R
    {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let cookie_request_id = unpack!(connection.status, ConnectionStatus::CookieRequesting, cookie_request_id);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        net_crypto.connections.write().await.insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().await.insert((addr.ip(), addr.port()), peer_real_pk);

        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let cookie_response_payload = CookieResponsePayload {
            cookie: cookie.clone(),
            id: cookie_request_id
        };
        let cookie_response = CookieResponse::new(&dht_precomputed_key, &cookie_response_payload);

        let net_crypto = handle_function(net_crypto, cookie_response, addr, peer_dht_pk).await;

        let connections = net_crypto.connections.read().await;
        let connection = connections.get(&peer_real_pk).unwrap().read().await.clone();

        let packet = unpack!(connection.status, ConnectionStatus::HandshakeSending, packet);
        let packet = unpack!(packet.packet, StatusPacket::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&precompute(&real_pk, &peer_real_sk)).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[tokio::test]
    async fn handle_udp_cookie_response() {
        async fn test_me(net_crypto: NetCrypto, packet: CookieResponse, saddr: SocketAddr, _pk: PublicKey) -> NetCrypto {
            net_crypto.handle_udp_cookie_response(&packet, saddr).await.unwrap();
            net_crypto
        }

        handle_cookie_response_test(test_me).await;
    }

    #[tokio::test]
    async fn handle_tcp_cookie_response() {
        async fn test_me(net_crypto: NetCrypto, packet: CookieResponse, _saddr: SocketAddr, pk: PublicKey) -> NetCrypto {
            net_crypto.handle_tcp_cookie_response(&packet, pk).await.unwrap();
            net_crypto
        }

        handle_cookie_response_test(test_me).await;
    }

    #[tokio::test]
    async fn handle_udp_cookie_response_no_connection() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);

        let addr = "127.0.0.1:12345".parse().unwrap();

        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let cookie_response_payload = CookieResponsePayload {
            cookie: cookie.clone(),
            id: 12345
        };
        let cookie_response = CookieResponse::new(&dht_precomputed_key, &cookie_response_payload);

        let res = net_crypto.handle_udp_cookie_response(&cookie_response, addr).await;
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::NoUdpConnection { addr: "127.0.0.1:12345".parse().unwrap() });
    }

    #[tokio::test]
    async fn handle_crypto_handshake_in_cookie_requesting_status() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie: cookie.clone()
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).await.unwrap();

        let received_nonce = unpack!(connection.status, ConnectionStatus::NotConfirmed, received_nonce);
        assert_eq!(received_nonce, base_nonce);

        let packet = unpack!(connection.status, ConnectionStatus::NotConfirmed, packet);
        let packet = unpack!(packet.packet, StatusPacket::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&real_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[tokio::test]
    async fn handle_crypto_handshake_in_not_confirmed_status() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk: real_sk.clone(),
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; 88]
        };
        let mut connection = CryptoConnection::new_not_confirmed(
            &real_sk,
            peer_real_pk,
            peer_dht_pk,
            gen_nonce(),
            gen_keypair().0,
            cookie.clone(),
            &net_crypto.symmetric_key
        );

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let other_cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie: other_cookie
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).await.unwrap();

        // Nonce should be taken from the packet
        let received_nonce = unpack!(connection.status, ConnectionStatus::NotConfirmed, received_nonce);
        assert_eq!(received_nonce, base_nonce);

        // cookie should not be updated
        let packet = unpack!(connection.status, ConnectionStatus::NotConfirmed, packet);
        let packet = unpack!(packet.packet, StatusPacket::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&real_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[tokio::test]
    async fn handle_crypto_handshake_invalid_status() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce: gen_nonce(),
            session_precomputed_key,
        };

        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie
        };
        let crypto_handshake = CryptoHandshake::new(&dht_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let res = net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).await;
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::InvalidState);
    }

    #[tokio::test]
    async fn handle_crypto_handshake_invalid_hash() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: cookie.hash(),
            cookie
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let res = net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).await;
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::BadSha512);
    }

    #[tokio::test]
    async fn handle_crypto_handshake_timed_out_cookie() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let mut our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        our_cookie.time -= COOKIE_TIMEOUT + 1;
        let our_encrypted_cookie = EncryptedCookie::new(&&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let res = net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).await;
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::CookieTimedOut);
    }

    #[tokio::test]
    async fn handle_crypto_handshake_invalid_peer_real_pk() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (another_peer_real_pk, another_peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let real_precomputed_key = precompute(&real_pk, &another_peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(another_peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let res = net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).await;
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::InvalidRealPk);
    }

    #[tokio::test]
    async fn handle_crypto_handshake_invalid_peer_dht_pk() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (dht_pk_tx, dht_pk_rx) = mpsc::unbounded();
        net_crypto.set_dht_pk_sink(dht_pk_tx).await;

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let (new_dht_pk, _new_dht_sk) = gen_keypair();

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, new_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let res = net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).await;
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::InvalidDhtPk);

        let (keys, _dht_pk_rx) = dht_pk_rx.into_future().await;
        let (received_real_pk, received_dht_pk) = keys.unwrap();

        assert_eq!(received_real_pk, peer_real_pk);
        assert_eq!(received_dht_pk, new_dht_pk);
    }

    async fn handle_crypto_handshake_test<'a, R, F>(handle_function: F)
    where
        R: Future<Output=NetCrypto>,
        F: FnOnce(NetCrypto, CryptoHandshake, SocketAddr, PublicKey) -> R
    {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        net_crypto.connections.write().await.insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().await.insert((addr.ip(), addr.port()), peer_real_pk);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie: cookie.clone()
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let net_crypto = handle_function(net_crypto, crypto_handshake, addr, peer_dht_pk).await;

        let connections = net_crypto.connections.read().await;
        let connection = connections.get(&peer_real_pk).unwrap().read().await.clone();

        let received_nonce = unpack!(connection.status, ConnectionStatus::NotConfirmed, received_nonce);
        assert_eq!(received_nonce, base_nonce);

        let packet = unpack!(connection.status, ConnectionStatus::NotConfirmed, packet);
        let packet = unpack!(packet.packet, StatusPacket::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&real_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[tokio::test]
    async fn handle_udp_crypto_handshake() {
        async fn test_me(net_crypto: NetCrypto, packet: CryptoHandshake, saddr: SocketAddr, _pk: PublicKey) -> NetCrypto {
            net_crypto.handle_udp_crypto_handshake(&packet, saddr).await.unwrap();
            net_crypto
        }

        handle_crypto_handshake_test(test_me).await;
    }

    #[tokio::test]
    async fn handle_tcp_crypto_handshake() {
        async fn test_me(net_crypto: NetCrypto, packet: CryptoHandshake, _saddr: SocketAddr, pk: PublicKey) -> NetCrypto {
            net_crypto.handle_tcp_crypto_handshake(&packet, pk).await.unwrap();
            net_crypto
        }

        handle_crypto_handshake_test(test_me).await;
    }

    #[tokio::test]
    async fn handle_udp_crypto_handshake_new_connection() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();

        net_crypto.add_friend(peer_real_pk).await;

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie: cookie.clone()
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.handle_udp_crypto_handshake(&crypto_handshake, addr).await.unwrap();

        let connections = net_crypto.connections.read().await;
        let connection = connections.get(&peer_real_pk).unwrap().read().await.clone();

        assert_eq!(connection.get_udp_addr_v4(), Some(addr));

        let received_nonce = unpack!(connection.status, ConnectionStatus::NotConfirmed, received_nonce);
        assert_eq!(received_nonce, base_nonce);

        let packet = unpack!(connection.status, ConnectionStatus::NotConfirmed, packet);
        let packet = unpack!(packet.packet, StatusPacket::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&real_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[tokio::test]
    async fn handle_udp_crypto_handshake_new_address_new_dht_pk() {
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();

        net_crypto.add_friend(peer_real_pk).await;

        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        net_crypto.connections.write().await.insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().await.insert((addr.ip(), addr.port()), peer_real_pk);

        let (new_peer_dht_pk, _new_peer_dht_sk) = gen_keypair();
        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, new_peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie: cookie.clone()
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let new_addr = "127.0.0.2:12345".parse().unwrap();
        net_crypto.handle_udp_crypto_handshake(&crypto_handshake, new_addr).await.unwrap();

        // the old connection should be replaced with the new one

        let connections = net_crypto.connections.read().await;
        let connection = connections.get(&peer_real_pk).unwrap().read().await.clone();

        assert_eq!(connection.peer_dht_pk, new_peer_dht_pk);
        assert_eq!(connection.get_udp_addr_v4(), Some(new_addr));

        let received_nonce = unpack!(connection.status, ConnectionStatus::NotConfirmed, received_nonce);
        assert_eq!(received_nonce, base_nonce);

        let packet = unpack!(connection.status, ConnectionStatus::NotConfirmed, packet);
        let packet = unpack!(packet.packet, StatusPacket::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&real_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());

        assert!(!net_crypto.keys_by_addr.read().await.contains_key(&(addr.ip(), addr.port())));
        assert!(net_crypto.keys_by_addr.read().await.contains_key(&(new_addr.ip(), new_addr.port())));

        // the old connection should be killed

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, DhtPacket::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 0);
        assert_eq!(payload.packet_number, 0);
        assert_eq!(payload.data, vec![PACKET_ID_KILL]);
    }

    #[tokio::test]
    async fn handle_udp_crypto_handshake_new_address_old_dht_pk() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();

        net_crypto.add_friend(peer_real_pk).await;

        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        net_crypto.connections.write().await.insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().await.insert((addr.ip(), addr.port()), peer_real_pk);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie: cookie.clone()
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let new_addr = "127.0.0.2:12345".parse().unwrap();
        net_crypto.handle_udp_crypto_handshake(&crypto_handshake, new_addr).await.unwrap();

        // the old connection should be updated with a new address

        let connections = net_crypto.connections.read().await;
        let connection = connections.get(&peer_real_pk).unwrap().read().await.clone();

        assert_eq!(connection.get_udp_addr_v4(), Some(new_addr));

        let received_nonce = unpack!(connection.status, ConnectionStatus::NotConfirmed, received_nonce);
        assert_eq!(received_nonce, base_nonce);

        let packet = unpack!(connection.status, ConnectionStatus::NotConfirmed, packet);
        let packet = unpack!(packet.packet, StatusPacket::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&real_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());

        assert!(!net_crypto.keys_by_addr.read().await.contains_key(&(addr.ip(), addr.port())));
        assert!(net_crypto.keys_by_addr.read().await.contains_key(&(new_addr.ip(), new_addr.port())));
    }

    #[tokio::test]
    async fn handle_udp_crypto_handshake_new_address_old_dht_pk_established() {
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();

        net_crypto.add_friend(peer_real_pk).await;

        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        net_crypto.connections.write().await.insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().await.insert((addr.ip(), addr.port()), peer_real_pk);

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie: cookie.clone()
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let new_addr = "127.0.0.2:12345".parse().unwrap();
        let error = net_crypto.handle_udp_crypto_handshake(&crypto_handshake, new_addr).await.err().unwrap();
        assert_eq!(*error.kind(), HandlePacketErrorKind::UnexpectedCryptoHandshake);
    }

    #[tokio::test]
    async fn handle_udp_crypto_handshake_unexpected() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, peer_real_sk) = gen_keypair();

        let real_precomputed_key = precompute(&real_pk, &peer_real_sk);
        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, &our_cookie);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash: our_encrypted_cookie.hash(),
            cookie: cookie.clone()
        };
        let crypto_handshake = CryptoHandshake::new(&real_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        let addr = "127.0.0.1:12345".parse().unwrap();

        let error = net_crypto.handle_udp_crypto_handshake(&crypto_handshake, addr).await.err().unwrap();

        assert_eq!(*error.kind(), HandlePacketErrorKind::UnexpectedCryptoHandshake);
    }

    #[tokio::test]
    async fn handle_crypto_data_lossy() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).await.unwrap();

        // The diff between nonces is not bigger than the threshold so received
        // nonce shouldn't be changed
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);

        let (received, _lossy_rx) = lossy_rx.into_future().await;
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]);
    }

    #[tokio::test]
    async fn handle_crypto_data_lossy_increment_nonce() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        // Make the diff between nonces is bigger than the threshold
        let mut packet_nonce = received_nonce;
        increment_nonce_number(&mut packet_nonce, u64::from(2 * NONCE_DIFF_THRESHOLD + 1));

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, packet_nonce, &crypto_data_payload);

        net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).await.unwrap();

        // The diff between nonces is bigger than the threshold so received
        // nonce should be changed increased
        let mut expected_nonce = received_nonce;
        increment_nonce_number(&mut expected_nonce, u64::from(NONCE_DIFF_THRESHOLD));
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), expected_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);

        let (received, _lossy_rx) = lossy_rx.into_future().await;
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]);
    }

    #[tokio::test]
    async fn handle_crypto_data_lossy_update_rtt() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        tokio::time::pause();
        let now = clock_now();

        let sent_packet = SentPacket {
            data: vec![42; 123],
            sent_time: now,
            requested: false,
        };
        assert!(connection.send_array.insert(0, sent_packet).is_ok());

        connection.rtt = Duration::from_millis(500);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 1,
            packet_number: 0,
            data: vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);


        tokio::time::advance(Duration::from_millis(250)).await;

        net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).await.unwrap();

        // The diff between nonces is not bigger than the threshold so received
        // nonce shouldn't be changed
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 1);
        assert_eq!(connection.send_array.buffer_end, 1);

        let (received, _lossy_rx) = lossy_rx.into_future().await;
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]);

        // avoid problems with floating point arithmetic
        assert!(
            connection.rtt > Duration::from_millis(249)
                && connection.rtt < Duration::from_millis(251)
        );
    }

    #[tokio::test]
    async fn handle_crypto_data_lossy_invalid_buffer_start() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 7, // bigger than end index of sent packets buffer
            packet_number: 0,
            data: vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        let res = net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).await;
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::PacketsArrayError);

        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);
    }

    #[tokio::test]
    async fn handle_crypto_data_lossless() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload_1 = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![PACKET_ID_LOSSY_RANGE_START - 1, 1, 2, 3]
        };
        let crypto_data_1 = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload_1);

        let crypto_data_payload_2 = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 1,
            data: vec![PACKET_ID_LOSSY_RANGE_START - 1, 4, 5, 6]
        };
        let crypto_data_2 = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload_2);

        let crypto_data_payload_3 = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 2,
            data: vec![PACKET_ID_LOSSY_RANGE_START - 1, 7, 8, 9]
        };
        let crypto_data_3 = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload_3);

        // Send packets in random order
        net_crypto.handle_crypto_data(&mut connection, &crypto_data_2, /* udp */ true).await.unwrap();
        net_crypto.handle_crypto_data(&mut connection, &crypto_data_3, /* udp */ true).await.unwrap();
        net_crypto.handle_crypto_data(&mut connection, &crypto_data_1, /* udp */ true).await.unwrap();

        // The diff between nonces is not bigger than the threshold so received
        // nonce shouldn't be changed
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 3);
        assert_eq!(connection.recv_array.buffer_end, 3);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);

        // We should receive lossless packets according to their numbers

        let (received, lossless_rx) = lossless_rx.into_future().await;
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START - 1, 1, 2, 3]);

        let (received, lossless_rx) = lossless_rx.into_future().await;
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START - 1, 4, 5, 6]);

        let (received, _lossless_rx) = lossless_rx.into_future().await;
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START - 1, 7, 8, 9]);
    }

    #[tokio::test]
    async fn handle_crypto_data_lossless_too_big_index() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: CRYPTO_PACKET_BUFFER_SIZE,
            data: vec![PACKET_ID_LOSSY_RANGE_START - 1, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        let res = net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).await;
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::PacketsArrayError);

        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);
    }

    #[tokio::test]
    async fn handle_crypto_data_kill() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let connection = Arc::new(RwLock::new(connection));
        net_crypto.connections.write().await.insert(peer_real_pk, connection.clone());
        net_crypto.keys_by_addr.write().await.insert((addr.ip(), addr.port()), peer_real_pk);

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![PACKET_ID_KILL]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        net_crypto.handle_crypto_data(&mut *connection.write().await, &crypto_data, /* udp */ true).await.unwrap();

        assert!(net_crypto.connections.read().await.is_empty());
        assert!(net_crypto.keys_by_addr.read().await.is_empty());
    }

    #[tokio::test]
    async fn handle_crypto_data_request() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        tokio::time::pause();
        let now = clock_now();

        assert!(connection.send_array.insert(0, SentPacket::new(vec![42; 123])).is_ok());
        // this time will be used to update rtt
        let packet_1 = SentPacket {
            data: vec![43; 123],
            sent_time: now + Duration::from_millis(750),
            requested: false,
        };
        assert!(connection.send_array.insert(1, packet_1).is_ok());
        // this packet will be requested but elapsed time will be less then rtt
        // so it shouldn't be marked
        let packet_5 = SentPacket {
            data: vec![44; 123],
            sent_time: now + Duration::from_millis(750),
            requested: false,
        };
        assert!(connection.send_array.insert(5, packet_5).is_ok());
        assert!(connection.send_array.insert(7, SentPacket::new(vec![45; 123])).is_ok());
        assert!(connection.send_array.insert(1024, SentPacket::new(vec![46; 123])).is_ok());

        connection.rtt = Duration::from_millis(500);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![PACKET_ID_REQUEST, 1, 5, 0, 0, 0, 254] // request 0, 5 and 1024 packets
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        tokio::time::advance(Duration::from_secs(1)).await;

        net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).await.unwrap();

        assert!(connection.send_array.get(0).unwrap().requested);
        assert!(connection.send_array.get(1).is_none());
        assert!(!connection.send_array.get(5).unwrap().requested);
        assert!(connection.send_array.get(7).is_none());
        assert!(connection.send_array.get(1024).unwrap().requested);

        // avoid problems with floating point arithmetic
        assert!(
            connection.rtt > Duration::from_millis(249)
                && connection.rtt < Duration::from_millis(251)
        );
    }

    #[tokio::test]
    async fn handle_crypto_data_empty_request() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        assert!(connection.send_array.insert(0, SentPacket::new(vec![42; 123])).is_ok());
        assert!(connection.send_array.insert(1, SentPacket::new(vec![43; 123])).is_ok());
        assert!(connection.send_array.insert(5, SentPacket::new(vec![44; 123])).is_ok());
        assert!(connection.send_array.insert(7, SentPacket::new(vec![45; 123])).is_ok());
        assert!(connection.send_array.insert(1024, SentPacket::new(vec![46; 123])).is_ok());

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![PACKET_ID_REQUEST]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).await.unwrap();

        assert!(!connection.send_array.get(0).unwrap().requested);
        assert!(!connection.send_array.get(1).unwrap().requested);
        assert!(!connection.send_array.get(5).unwrap().requested);
        assert!(!connection.send_array.get(7).unwrap().requested);
        assert!(!connection.send_array.get(1024).unwrap().requested);
    }

    #[tokio::test]
    async fn handle_crypto_data_invalid_packet_id() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![255, 1, 2, 3] // only 255 is invalid id
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        let res = net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).await;
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::PacketId { id: 255 });

        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);
    }

    #[tokio::test]
    async fn handle_crypto_data_empty_data() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: Vec::new()
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        let res = net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).await;
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::DataEmpty);

        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);
    }

    #[tokio::test]
    async fn handle_crypto_data_invalid_status() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![0, 0, PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        let res = net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).await;
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::CannotHandleCryptoData);
    }

    async fn handle_crypto_data_lossy_test<'a, R, F>(handle_function: F)
    where
        R: Future<Output=NetCrypto>,
        F: Fn(NetCrypto, CryptoData, SocketAddr, PublicKey) -> R
    {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        net_crypto.connections.write().await.insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().await.insert((addr.ip(), addr.port()), peer_real_pk);

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![0, 0, PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        let net_crypto = handle_function(net_crypto, crypto_data, addr, peer_dht_pk).await;

        let connections = net_crypto.connections.read().await;
        let connection = connections.get(&peer_real_pk).unwrap().read().await.clone();

        // The diff between nonces is not bigger than the threshold so received
        // nonce shouldn't be changed
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);

        let (received, _lossy_rx) = lossy_rx.into_future().await;
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]);
    }

    #[tokio::test]
    async fn handle_udp_crypto_data_lossy() {
        async fn test_me(net_crypto: NetCrypto, packet: CryptoData, saddr: SocketAddr, _pk: PublicKey) -> NetCrypto {
            net_crypto.handle_udp_crypto_data(&packet, saddr).await.unwrap();
            net_crypto
        }

        handle_crypto_data_lossy_test(test_me).await;
    }

    #[tokio::test]
    async fn handle_tcp_crypto_data_lossy() {
        async fn test_me(net_crypto: NetCrypto, packet: CryptoData, _saddr: SocketAddr, pk: PublicKey) -> NetCrypto {
            net_crypto.handle_tcp_crypto_data(&packet, pk).await.unwrap();
            net_crypto
        }

        handle_crypto_data_lossy_test(test_me).await;
    }

    #[tokio::test]
    async fn send_status_packet() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        // send status packet first time - it should be sent
        net_crypto.send_status_packet(&mut connection).await.unwrap();

        let packet = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, packet);
        assert_eq!(packet.num_sent, 1);

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(
            unpack!(received, DhtPacket::CookieRequest),
            unpack!(packet.packet.clone(), StatusPacket::CookieRequest)
        );
        assert_eq!(addr_to_send, addr);

        // send status packet again - it shouldn't be sent
        net_crypto.send_status_packet(&mut connection).await.unwrap();

        let packet = unpack!(connection.status, ConnectionStatus::CookieRequesting, packet);
        assert_eq!(packet.num_sent, 1);
    }

    #[tokio::test]
    async fn send_packet_udp() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let packet = CryptoData {
            nonce_last_bytes: 123,
            payload: vec![42; DHT_ATTEMPT_MAX_PACKET_LENGTH]
        };

        net_crypto.send_packet(Packet::CryptoData(packet.clone()), &mut connection).await.unwrap();

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);
        assert_eq!(received, DhtPacket::CryptoData(packet));
    }

    #[tokio::test]
    async fn send_packet_udp_attempt() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (tcp_tx, tcp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        net_crypto.set_tcp_sink(tcp_tx).await;

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let packet = CryptoData {
            nonce_last_bytes: 123,
            payload: vec![42; DHT_ATTEMPT_MAX_PACKET_LENGTH - 3] // 1 byte of packet kind and 2 bytes of nonce
        };

        tokio::time::pause();
        tokio::time::advance(UDP_DIRECT_TIMEOUT + Duration::from_secs(1)).await;

        net_crypto.send_packet(Packet::CryptoData(packet.clone()), &mut connection).await.unwrap();

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);
        assert_eq!(received, DhtPacket::CryptoData(packet.clone()));

        let (received, _tcp_rx) = tcp_rx.into_future().await;
        let (received, key_to_send) = received.unwrap();

        assert_eq!(key_to_send, peer_dht_pk);
        assert_eq!(received, TcpDataPayload::CryptoData(packet));
    }

    #[tokio::test]
    async fn send_packet_no_udp_attempt() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_tx, tcp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        net_crypto.set_tcp_sink(tcp_tx).await;

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let packet = CryptoData {
            nonce_last_bytes: 123,
            payload: vec![42; DHT_ATTEMPT_MAX_PACKET_LENGTH]
        };

        tokio::time::pause();
        tokio::time::advance(UDP_DIRECT_TIMEOUT + Duration::from_secs(1)).await;

        net_crypto.send_packet(Packet::CryptoData(packet.clone()), &mut connection).await.unwrap();

        let (received, _tcp_rx) = tcp_rx.into_future().await;
        let (received, key_to_send) = received.unwrap();

        assert_eq!(key_to_send, peer_dht_pk);
        assert_eq!(received, TcpDataPayload::CryptoData(packet));
    }

    #[tokio::test]
    async fn send_packet_tcp() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let packet = Packet::CryptoData(CryptoData {
            nonce_last_bytes: 123,
            payload: vec![42; DHT_ATTEMPT_MAX_PACKET_LENGTH]
        });

        net_crypto.send_packet(packet.clone(), &mut connection).await.unwrap();

        // TODO: check that TCP received the packet
    }

    #[tokio::test]
    async fn main_loop_sends_status_packets() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let packet = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, packet);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        net_crypto.connections.write().await.insert(peer_real_pk, Arc::new(RwLock::new(connection)));

        net_crypto.main_loop().await.unwrap();

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);
        assert_eq!(
            unpack!(received, DhtPacket::CookieRequest),
            unpack!(packet.packet, StatusPacket::CookieRequest)
        );
    }

    #[tokio::test]
    async fn main_loop_removes_timed_out_connections() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        // make the connection timed out
        let cookie_request_id = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, cookie_request_id);
        let mut packet = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, packet);
        packet.num_sent = MAX_NUM_SENDPACKET_TRIES;
        packet.sent_time -= CRYPTO_SEND_PACKET_INTERVAL + Duration::from_secs(1);
        connection.status = ConnectionStatus::CookieRequesting {
            cookie_request_id,
            packet
        };

        assert!(connection.is_timed_out());

        net_crypto.connections.write().await.insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().await.insert((addr.ip(), addr.port()), peer_real_pk);

        net_crypto.main_loop().await.unwrap();

        assert!(net_crypto.connections.read().await.is_empty());
        assert!(net_crypto.keys_by_addr.read().await.is_empty());
    }

    #[tokio::test]
    async fn main_loop_sends_request_packets() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        net_crypto.connections.write().await.insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().await.insert((addr.ip(), addr.port()), peer_real_pk);

        net_crypto.main_loop().await.unwrap();

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, DhtPacket::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 0);
        assert_eq!(payload.packet_number, 0);
        assert_eq!(payload.data, vec![PACKET_ID_REQUEST]);
    }

    #[tokio::test]
    async fn main_loop_sends_requested_packets() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let now = Instant::now();

        connection.request_packet_sent_time = Some(now);

        let data = vec![42; 123];
        connection.packets_sent = 1;
        connection.send_array.buffer_end = 1;
        assert!(connection.send_array.insert(0, SentPacket {
            data: data.clone(),
            sent_time: now,
            requested: true,
        }).is_ok());

        net_crypto.connections.write().await.insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().await.insert((addr.ip(), addr.port()), peer_real_pk);

        net_crypto.main_loop().await.unwrap();

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, DhtPacket::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 0);
        assert_eq!(payload.packet_number, 0);
        assert_eq!(payload.data, data);
    }

    #[tokio::test]
    async fn send_status_packet_established() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            session_precomputed_key,
        };

        // send status packet with connection.status is Established
        net_crypto.send_status_packet(&mut connection).await.unwrap();

        // Necessary to drop udp_tx so that udp_rx.collect() can be finished
        drop(net_crypto.udp_tx);

        assert!(udp_rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn send_data_packet() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let received_nonce = gen_nonce();
        let mut sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        connection.recv_array.buffer_start = 23;
        connection.recv_array.buffer_end = 25;

        let data = vec![42; 123];
        net_crypto.send_data_packet(&mut connection, data.clone(), 7).await.unwrap();

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, DhtPacket::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 23);
        assert_eq!(payload.packet_number, 7);
        assert_eq!(payload.data, data);

        increment_nonce(&mut sent_nonce);
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, sent_nonce), sent_nonce);
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);
    }

    #[tokio::test]
    async fn send_request_packet() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        connection.recv_array.buffer_end = 270;
        assert!(connection.recv_array.insert(2, RecvPacket {
            data: vec![42; 123],
        }).is_ok());
        for i in 5 .. 269 {
            assert!(connection.recv_array.insert(i, RecvPacket {
                data: vec![42; 123],
            }).is_ok());
        }

        tokio::time::pause();
        let now = clock_now();
        let delay = Duration::from_secs(1);
        tokio::time::advance(delay).await;

        net_crypto.send_request_packet(&mut connection).await.unwrap();

        assert_eq!(connection.request_packet_sent_time, Some(now + delay));

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, DhtPacket::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 0);
        assert_eq!(payload.packet_number, 0);
        assert_eq!(payload.data, vec![PACKET_ID_REQUEST, 1, 1, 2, 1, 0, 10]);
    }

    #[tokio::test]
    async fn send_request_packet_too_many_missing_packets() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        connection.recv_array.buffer_end = MAX_CRYPTO_DATA_SIZE as u32 + 42;

        net_crypto.send_request_packet(&mut connection).await.unwrap();

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, DhtPacket::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 0);
        assert_eq!(payload.packet_number, 0);
        assert_eq!(payload.data.len(), MAX_CRYPTO_DATA_SIZE);
    }

    #[tokio::test]
    async fn send_requested_packets() {
        tokio::time::pause();
        let now = clock_now();

        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(2);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            session_precomputed_key,
        };

        connection.send_array.buffer_end = 7;
        assert!(connection.send_array.insert(2, SentPacket {
            data: vec![42; 123],
            sent_time: now,
            requested: true,
        }).is_ok());
        assert!(connection.send_array.insert(4, SentPacket {
            data: vec![42; 123],
            sent_time: now,
            requested: false,
        }).is_ok());
        assert!(connection.send_array.insert(5, SentPacket {
            data: vec![42; 123],
            sent_time: now,
            requested: true,
        }).is_ok());

        let delay = Duration::from_secs(1);
        tokio::time::advance(delay).await;

        net_crypto.send_requested_packets(&mut connection).await.unwrap();

        assert!(!connection.send_array.get(2).unwrap().requested);
        assert!(!connection.send_array.get(4).unwrap().requested);
        assert!(!connection.send_array.get(5).unwrap().requested);
        assert_eq!(connection.send_array.get(2).unwrap().sent_time, now + delay);
        assert_eq!(connection.send_array.get(4).unwrap().sent_time, now);
        assert_eq!(connection.send_array.get(5).unwrap().sent_time, now + delay);

        // Necessary to drop udp_tx so that udp_rx.collect() can be finished
        drop(net_crypto.udp_tx);

        assert_eq!(udp_rx.collect::<Vec<_>>().await.len(), 2);
    }

    #[tokio::test]
    async fn send_lossless() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(2);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let connection = Arc::new(RwLock::new(connection));
        net_crypto.connections.write().await.insert(peer_real_pk, connection.clone());
        net_crypto.keys_by_addr.write().await.insert((addr.ip(), addr.port()), peer_real_pk);

        let data = vec![16, 42];

        net_crypto.send_lossless(peer_real_pk, data.clone()).await.unwrap();

        let connection = connection.read().await;

        assert_eq!(connection.packets_sent, 1);

        // the packet should be added to send_array

        assert_eq!(connection.send_array.buffer[0].clone().unwrap().data, data);

        // the packet should be sent to node

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, DhtPacket::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 0);
        assert_eq!(payload.packet_number, 0);
        assert_eq!(payload.data, data);
    }

    #[tokio::test]
    async fn send_lossless_no_connection() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(2);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_real_pk, _peer_real_sk) = gen_keypair();

        let error = net_crypto.send_lossless(peer_real_pk, vec![16, 42]).await.err().unwrap();
        assert_eq!(*error.kind(), SendLosslessPacketErrorKind::NoConnection);
    }

    #[tokio::test]
    async fn send_lossless_invalid_packet_id() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(2);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_real_pk, _peer_real_sk) = gen_keypair();

        let error = net_crypto.send_lossless(peer_real_pk, vec![10, 42]).await.err().unwrap();
        assert_eq!(*error.kind(), SendLosslessPacketErrorKind::InvalidPacketId);
    }

    #[tokio::test]
    async fn add_connection() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(2);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (peer_dht_pk, peer_dht_sk) = gen_keypair();
        net_crypto.add_connection(peer_real_pk, peer_dht_pk).await;

        let connections = net_crypto.connections.read().await;
        let connection = connections[&peer_real_pk].read().await;

        assert_eq!(connection.peer_real_pk, peer_real_pk);
        assert_eq!(connection.peer_dht_pk, peer_dht_pk);

        let status_packet = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, packet);
        let cookie_request = unpack!(status_packet.packet, StatusPacket::CookieRequest);
        let cookie_request_payload = cookie_request.get_payload(&precompute(&dht_pk, &peer_dht_sk)).unwrap();

        assert_eq!(cookie_request_payload.pk, real_pk);
    }

    #[tokio::test]
    async fn add_connection_already_exists() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(2);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        net_crypto.add_connection(peer_real_pk, peer_dht_pk).await;

        // adding a friend that already exists won't do anything
        let (another_peer_dht_pk, _another_peer_dht_sk) = gen_keypair();
        net_crypto.add_connection(peer_real_pk, another_peer_dht_pk).await;

        let connections = net_crypto.connections.read().await;
        let connection = connections[&peer_real_pk].read().await;

        assert_eq!(connection.peer_real_pk, peer_real_pk);
        assert_eq!(connection.peer_dht_pk, peer_dht_pk);
    }

    #[tokio::test]
    async fn set_friend_udp_addr() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(2);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        net_crypto.add_connection(peer_real_pk, peer_dht_pk).await;

        let addr_v4 = "127.0.0.1:12345".parse().unwrap();
        net_crypto.set_friend_udp_addr(peer_real_pk, addr_v4).await;
        let addr_v6 = "[::]:12345".parse().unwrap();
        net_crypto.set_friend_udp_addr(peer_real_pk, addr_v6).await;

        let connections = net_crypto.connections.read().await;
        let connection = connections[&peer_real_pk].read().await;

        assert_eq!(connection.get_udp_addr_v4(), Some(addr_v4));
        assert_eq!(connection.get_udp_addr_v6(), Some(addr_v6));
        assert_eq!(net_crypto.keys_by_addr.read().await[&(addr_v4.ip(), addr_v4.port())], peer_real_pk);
        assert_eq!(net_crypto.keys_by_addr.read().await[&(addr_v6.ip(), addr_v6.port())], peer_real_pk);
    }

    #[tokio::test]
    async fn set_friend_udp_addr_update() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(2);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        net_crypto.add_connection(peer_real_pk, peer_dht_pk).await;

        let addr = "127.0.0.1:12345".parse().unwrap();
        net_crypto.set_friend_udp_addr(peer_real_pk, addr).await;
        // setting the same address won't do anything
        net_crypto.set_friend_udp_addr(peer_real_pk, addr).await;

        let addr = "127.0.0.1:12346".parse().unwrap();
        net_crypto.set_friend_udp_addr(peer_real_pk, addr).await;

        let connections = net_crypto.connections.read().await;
        let connection = connections[&peer_real_pk].read().await;

        assert_eq!(connection.get_udp_addr_v4(), Some(addr));

        let keys_by_addr = net_crypto.keys_by_addr.read().await;
        assert_eq!(keys_by_addr[&(addr.ip(), addr.port())], peer_real_pk);
        assert_eq!(keys_by_addr.len(), 1);
    }

    #[tokio::test]
    async fn set_friend_udp_addr_no_connection() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(2);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let addr = "127.0.0.1:12345".parse().unwrap();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();

        // setting an address to nonexistent connection won't do anything
        net_crypto.set_friend_udp_addr(peer_real_pk, addr).await;

        assert!(net_crypto.keys_by_addr.read().await.is_empty());
    }

    #[tokio::test]
    async fn kill_connection() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(2);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        net_crypto.connections.write().await.insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().await.insert((addr.ip(), addr.port()), peer_real_pk);

        net_crypto.kill_connection(peer_real_pk).await.unwrap();

        assert!(!net_crypto.connections.read().await.contains_key(&peer_real_pk));
        assert!(!net_crypto.keys_by_addr.read().await.contains_key(&(addr.ip(), addr.port())));

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, DhtPacket::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 0);
        assert_eq!(payload.packet_number, 0);
        assert_eq!(payload.data, vec![PACKET_ID_KILL]);
    }

    #[tokio::test]
    async fn kill_connection_no_connection() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(2);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_real_pk, _peer_real_sk) = gen_keypair();

        let error = net_crypto.kill_connection(peer_real_pk).await.err().unwrap();
        assert_eq!(*error.kind(), KillConnectionErrorKind::NoConnection);
    }

    #[tokio::test]
    async fn kill_connection_not_established() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(2);
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            real_sk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let mut connection = CryptoConnection::new(&dht_precomputed_key, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.set_udp_addr(addr);

        net_crypto.connections.write().await.insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().await.insert((addr.ip(), addr.port()), peer_real_pk);

        net_crypto.kill_connection(peer_real_pk).await.unwrap();

        assert!(!net_crypto.connections.read().await.contains_key(&peer_real_pk));
        assert!(!net_crypto.keys_by_addr.read().await.contains_key(&(addr.ip(), addr.port())));

        // Necessary to drop udp_tx so that udp_rx.collect() can be finished
        drop(net_crypto.udp_tx);

        assert!(udp_rx.collect::<Vec<_>>().await.is_empty());
    }
}
