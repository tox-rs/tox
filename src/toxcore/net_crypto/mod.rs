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

pub use self::crypto_connection::*;
use self::packets_array::*;

use std::collections::HashMap;
use std::io::{ErrorKind, Error};
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::u16;

use futures::{Future, Stream};
use futures::future;
use futures::sync::mpsc;
use parking_lot::RwLock;
use tokio::timer::Interval;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packet::*;
use crate::toxcore::dht::precomputed_cache::*;
use crate::toxcore::io_tokio::*;
use crate::toxcore::time::*;

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

/// Timeout in seconds for packet sending
const NET_CRYPTO_SEND_TIMEOUT: u64 = 50;

/// Shorthand for the transmit half of the message channel for sending DHT
/// packets.
type UdpTx = mpsc::Sender<(Packet, SocketAddr)>;

/// Shorthand for the transmit half of the message channel for sending DHT
/// `PublicKey` when it gets known. The first key is a long term key, the second
/// key is a DHT key.
type DhtPkTx = mpsc::UnboundedSender<(PublicKey, PublicKey)>;

/// Shorthand for the transmit half of the message channel for sending lossless
/// packets. The key is a long term public key of the peer that sent this
/// packet.
type LosslessTx = mpsc::UnboundedSender<(PublicKey, Vec<u8>)>;

/// Shorthand for the transmit half of the message channel for sending lossy
/// packets. The key is a long term public key of the peer that sent this
/// packet.
type LossyTx = mpsc::UnboundedSender<(PublicKey, Vec<u8>)>;

/// Arguments for creating new `NetCrypto`.
#[derive(Clone)]
pub struct NetCryptoNewArgs {
    /// Sink to send packet to UDP socket
    pub udp_tx: UdpTx,
    /// Sink to send DHT `PublicKey` when it gets known. The first key is a long
    /// term key, the second key is a DHT key. `NetCrypto` module can learn DHT
    /// `PublicKey` of peer from `Cookie` obtained from `CryptoHandshake`
    /// packet. If key from `Cookie` is not equal to saved key inside
    /// `CryptoConnection` then `NetCrypto` module will send message to this
    /// sink.
    pub dht_pk_tx: DhtPkTx,
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
    /// Lru cache for precomputed keys. It stores precomputed keys to avoid
    /// redundant calculations.
    pub precomputed_keys: PrecomputedCache,
}

/// Struct that manages crypto connections to friends and handles net crypto
/// packets from both UDP and TCP connections.
#[derive(Clone)]
pub struct NetCrypto {
    /// Sink to send packet to UDP socket
    udp_tx: UdpTx,
    /// Sink to send DHT `PublicKey` when it gets known. The first key is a long
    /// term key, the second key is a DHT key. `NetCrypto` module can learn DHT
    /// `PublicKey` of peer from `Cookie` obtained from `CryptoHandshake`
    /// packet. If key from `Cookie` is not equal to saved key inside
    /// `CryptoConnection` then `NetCrypto` module will send message to this
    /// sink.
    dht_pk_tx: DhtPkTx,
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
    /// Symmetric key used for cookies encryption
    symmetric_key: secretbox::Key,
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
            dht_pk_tx: args.dht_pk_tx,
            lossless_tx: args.lossless_tx,
            lossy_tx: args.lossy_tx,
            dht_pk: args.dht_pk,
            dht_sk: args.dht_sk,
            real_pk: args.real_pk,
            symmetric_key: secretbox::gen_key(),
            connections: Arc::new(RwLock::new(HashMap::new())),
            keys_by_addr: Arc::new(RwLock::new(HashMap::new())),
            precomputed_keys: args.precomputed_keys,
        }
    }

    /// Send `Packet` packet to UDP socket
    fn send_to_udp(&self, addr: SocketAddr, packet: Packet) -> IoFuture<()> {
        send_to_bounded(&self.udp_tx, (packet, addr), Duration::from_millis(NET_CRYPTO_SEND_TIMEOUT))
    }

    /// Get long term `PublicKey` of the peer by its UDP address
    fn key_by_addr(&self, addr: SocketAddr) -> Option<PublicKey> {
        self.keys_by_addr.read().get(&(addr.ip(), addr.port())).cloned()
    }

    /// Get crypto connection by long term `PublicKey`
    fn connection_by_key(&self, pk: PublicKey) -> Option<Arc<RwLock<CryptoConnection>>> {
        self.connections.read().get(&pk).cloned()
    }

    /// Create `CookieResponse` packet with `Cookie` requested by `CookieRequest` packet
    fn handle_cookie_request(&self, packet: &CookieRequest) -> Result<CookieResponse, Error> {
        let payload = packet.get_payload(&self.precomputed_keys.get(packet.pk))?;

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
    pub fn handle_udp_cookie_request(&self, packet: &CookieRequest, addr: SocketAddr) -> IoFuture<()> {
        match self.handle_cookie_request(packet) {
            Ok(response) => self.send_to_udp(addr, Packet::CookieResponse(response)),
            Err(e) => Box::new(future::err(e))
        }
    }

    /// Handle `CookieResponse` and if it's correct change connection status to `HandshakeSending`.
    pub fn handle_cookie_response(&self, connection: &mut CryptoConnection, packet: &CookieResponse) -> IoFuture<()> {
        let cookie_request_id = if let ConnectionStatus::CookieRequesting { cookie_request_id, .. } = connection.status {
            cookie_request_id
        } else {
            return Box::new(future::err(Error::new(
                ErrorKind::Other,
                "Can't handle CookieResponse in current connection state"
            )))
        };

        let payload = match packet.get_payload(&connection.dht_precomputed_key) {
            Ok(payload) => payload,
            Err(e) => return Box::new(future::err(Error::from(e))),
        };

        if payload.id != cookie_request_id {
            return Box::new(future::err(Error::new(
                ErrorKind::Other,
                format!("Invalid cookie request id: expected {} but got {}", cookie_request_id, payload.id)
            )))
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
        let handshake = CryptoHandshake::new(&connection.dht_precomputed_key, &handshake_payload, payload.cookie);

        connection.status = ConnectionStatus::HandshakeSending {
            sent_nonce,
            packet: StatusPacket::new_crypto_handshake(handshake)
        };

        self.send_status_packet(connection)
    }

    /// Handle `CookieResponse` packet received from UDP socket
    pub fn handle_udp_cookie_response(&self, packet: &CookieResponse, addr: SocketAddr) -> IoFuture<()> {
        let connection = self.key_by_addr(addr).and_then(|pk| self.connection_by_key(pk));
        if let Some(connection) = connection {
            let mut connection = connection.write();
            connection.update_udp_received_time();
            self.handle_cookie_response(&mut connection, packet)
        } else {
            Box::new(future::err(
                Error::new(
                    ErrorKind::Other,
                    format!("No crypto connection for address {}", addr)
                )
            ))
        }
    }

    /// Handle `CryptoHandshake` and if it's correct change connection status to `NotConfirmed`.
    pub fn handle_crypto_handshake(&self, connection: &mut CryptoConnection, packet: &CryptoHandshake) -> IoFuture<()> {
        if let ConnectionStatus::Established { .. } = connection.status {
            return Box::new(future::err(Error::new(
                ErrorKind::Other,
                "Can't handle CryptoHandshake in current connection state"
            )))
        }

        let payload = match packet.get_payload(&connection.dht_precomputed_key) {
            Ok(payload) => payload,
            Err(e) => return Box::new(future::err(Error::from(e))),
        };

        if packet.cookie.hash() != payload.cookie_hash {
            return Box::new(future::err(Error::new(
                ErrorKind::Other,
                "Invalid SHA512 hash of cookie"
            )))
        }

        let cookie = match packet.cookie.get_payload(&self.symmetric_key) {
            Ok(cookie) => cookie,
            Err(e) => return Box::new(future::err(Error::from(e))),
        };

        if cookie.is_timed_out() {
            return Box::new(future::err(Error::new(
                ErrorKind::Other,
                "Cookie is timed out"
            )))
        }
        if cookie.real_pk != connection.peer_real_pk {
            return Box::new(future::err(Error::new(
                ErrorKind::Other,
                "Cookie contains invalid real pk"
            )))
        }
        if cookie.dht_pk != connection.peer_dht_pk {
            return Box::new(
                send_to(&self.dht_pk_tx, (connection.peer_real_pk, cookie.dht_pk))
                    .and_then(|()| future::err(Error::new(
                        ErrorKind::Other,
                        "Cookie contains invalid dht pk"
                    )))
            )
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
                let handshake = CryptoHandshake::new(&connection.dht_precomputed_key, &handshake_payload, payload.cookie);
                ConnectionStatus::NotConfirmed {
                    sent_nonce,
                    received_nonce: payload.base_nonce,
                    peer_session_pk: payload.session_pk,
                    session_precomputed_key: precompute(&payload.session_pk, &connection.session_sk),
                    packet: StatusPacket::new_crypto_handshake(handshake)
                }
            },
            ConnectionStatus::HandshakeSending { sent_nonce, ref packet, .. }
            | ConnectionStatus::NotConfirmed { sent_nonce, ref packet, .. } => ConnectionStatus::NotConfirmed {
                sent_nonce,
                received_nonce: payload.base_nonce,
                peer_session_pk: payload.session_pk,
                session_precomputed_key: precompute(&payload.session_pk, &connection.session_sk),
                packet: packet.clone()
            },
            ConnectionStatus::Established { .. } => unreachable!("Checked for Established status above"),
        };

        self.send_status_packet(connection)
    }

    /// Handle `CryptoHandshake` packet received from UDP socket
    pub fn handle_udp_crypto_handshake(&self, packet: &CryptoHandshake, addr: SocketAddr) -> IoFuture<()> {
        let connection = self.key_by_addr(addr).and_then(|pk| self.connection_by_key(pk));
        if let Some(connection) = connection {
            let mut connection = connection.write();
            connection.update_udp_received_time();
            self.handle_crypto_handshake(&mut connection, packet)
        } else {
            Box::new(future::err( // TODO: create crypto connection
                Error::new(
                    ErrorKind::Other,
                    format!("No crypto connection for address {}", addr)
                )
            ))
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
    fn process_ready_lossless_packets(&self, recv_array: &mut PacketsArray<RecvPacket>, pk: PublicKey) -> IoFuture<()> {
        let mut futures = Vec::new();
        while let Some(packet) = recv_array.pop_front() {
            let future = send_to(&self.lossless_tx, (pk, packet.data));
            futures.push(future);
        }
        Box::new(future::join_all(futures).map(|_| ()))
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
    fn handle_crypto_data(&self, connection: &mut CryptoConnection, packet: &CryptoData, udp: bool) -> IoFuture<()> {
        let (sent_nonce, mut received_nonce, peer_session_pk, session_precomputed_key) = match connection.status {
            ConnectionStatus::NotConfirmed { sent_nonce, received_nonce, peer_session_pk, ref session_precomputed_key, .. }
            | ConnectionStatus::Established { sent_nonce, received_nonce, peer_session_pk, ref session_precomputed_key } => {
                (sent_nonce, received_nonce, peer_session_pk, session_precomputed_key.clone())
            },
            _ => {
                return Box::new(future::err(Error::new(
                    ErrorKind::Other,
                    "Can't handle CryptoData in current connection state"
                )))
            }
        };

        let cur_last_bytes = CryptoData::nonce_last_bytes(received_nonce);
        let (diff, _) = packet.nonce_last_bytes.overflowing_sub(cur_last_bytes);
        let mut packet_nonce = received_nonce;
        increment_nonce_number(&mut packet_nonce, u64::from(diff));

        let payload = match packet.get_payload(&session_precomputed_key, &packet_nonce) {
            Ok(payload) => payload,
            Err(e) => return Box::new(future::err(Error::from(e)))
        };

        // Find the time when the last acknowledged packet was sent
        let mut last_sent_time = NetCrypto::last_sent_time(&connection.send_array, payload.buffer_start);

        // Remove all acknowledged packets and set new start index to the send buffer
        if let Err(e) = connection.send_array.set_buffer_start(payload.buffer_start) {
            return Box::new(future::err(e))
        }

        // And get the ID of the packet
        let packet_id = match payload.data.first() {
            Some(&packet_id) => packet_id,
            None => return Box::new(future::err(Error::new(
                ErrorKind::Other,
                "Real data is empty"
            )))
        };

        if packet_id == PACKET_ID_KILL {
            // Kill the connection
            self.connections.write().remove(&connection.peer_real_pk);
            if let Some(addr) = connection.udp_addr {
                self.keys_by_addr.write().remove(&(addr.ip(), addr.port()));
            }
            return Box::new(future::ok(()));
        }

        // Update nonce if diff is big enough
        if diff > NONCE_DIFF_THRESHOLD * 2 {
            increment_nonce_number(&mut received_nonce, u64::from(NONCE_DIFF_THRESHOLD));
        }

        // TODO: connection status notification

        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            peer_session_pk,
            session_precomputed_key
        };

        let result = if packet_id == PACKET_ID_REQUEST {
            // Use const RTT in case of TCP connection
            let rtt = if udp { connection.rtt } else { Duration::from_millis(TCP_RTT) };
            NetCrypto::handle_request_packet(&mut connection.send_array, &payload.data[1..], rtt, &mut last_sent_time);
            // Update end index of received buffer ignoring the error - we still
            // want to handle this packet even if connection is too slow
            connection.recv_array.set_buffer_end(payload.packet_number).ok();
            Box::new(future::ok(()))
        } else if packet_id > PACKET_ID_CRYPTO_RANGE_END && packet_id < PACKET_ID_LOSSY_RANGE_START {
            if let Err(e) = connection.recv_array.insert(payload.packet_number, RecvPacket::new(payload.data)) {
                return Box::new(future::err(e))
            }
            connection.packets_received += 1;
            self.process_ready_lossless_packets(&mut connection.recv_array, connection.peer_real_pk)
        } else if packet_id >= PACKET_ID_LOSSY_RANGE_START && packet_id <= PACKET_ID_LOSSY_RANGE_END {
            // Update end index of received buffer ignoring the error - we still
            // want to handle this packet even if connection is too slow
            connection.recv_array.set_buffer_end(payload.packet_number).ok();
            send_to(&self.lossy_tx, (connection.peer_real_pk, payload.data))
        } else {
            return Box::new(future::err(Error::new(
                ErrorKind::Other,
                format!("Invalid packet id: {}", packet_id)
            )))
        };

        // TODO: update rtt only when udp is true?
        if let Some(last_sent_time) = last_sent_time {
            // Update rtt if it's become lower
            let elapsed = clock_elapsed(last_sent_time);
            if elapsed < connection.rtt {
                connection.rtt = elapsed;
            }
        }

        result
    }

    /// Handle `CryptoData` packet received from UDP socket
    pub fn handle_udp_crypto_data(&self, packet: &CryptoData, addr: SocketAddr) -> IoFuture<()> {
        let connection = self.key_by_addr(addr).and_then(|pk| self.connection_by_key(pk));
        if let Some(connection) = connection {
            let mut connection = connection.write();
            connection.update_udp_received_time();
            self.handle_crypto_data(&mut connection, packet, /* udp */ true)
        } else {
            Box::new(future::err(
                Error::new(
                    ErrorKind::Other,
                    format!("No crypto connection for address {}", addr)
                )
            ))
        }
    }

    /// Send packet to crypto connection choosing TCP or UDP protocol
    fn send_packet(&self, packet: Packet, connection: &mut CryptoConnection) -> IoFuture<()> {
        // TODO: can backpressure be used instead of congestion control? It
        // seems it's possible to implement wrapper for bounded sender with
        // priority queue and just send packets there
        if let Some(addr) = connection.udp_addr {
            if connection.is_udp_alive() {
                return self.send_to_udp(addr, packet)
            }

            let udp_attempt_should_be_made = connection.udp_attempt_should_be_made() && {
                // check if the packet is not too big
                let mut buf = [0; DHT_ATTEMPT_MAX_PACKET_LENGTH];
                packet.to_bytes((&mut buf, 0)).is_ok()
            };

            if udp_attempt_should_be_made {
                connection.update_udp_send_attempt_time();
                self.send_to_udp(addr, packet)
            } else {
                Box::new(future::ok(()))
            }
        } else {
            Box::new(future::ok(()))
        }

        // TODO: send via TCP relay here
    }

    /// Send `CookieRequest` or `CryptoHandshake` packet if needed depending on
    /// connection status and update sent counter
    fn send_status_packet(&self, connection: &mut CryptoConnection) -> IoFuture<()> {
        match connection.packet_to_send() {
            Some(packet) => self.send_packet(packet, connection),
            None => Box::new(future::ok(())),
        }
    }

    /// Send `CryptoData` packet if the connection is established.
    fn send_data_packet(&self, connection: &mut CryptoConnection, data: Vec<u8>, packet_number: u32) -> IoFuture<()> {
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
            _ => return Box::new(future::err(Error::new(ErrorKind::Other, "Connection is not established"))),
        };
        self.send_packet(Packet::CryptoData(packet), connection)
    }

    /// Send request packet with indices of not received packets.
    fn send_request_packet(&self, connection: &mut CryptoConnection) -> IoFuture<()> {
        let data = NetCrypto::generate_request_packet(&connection.recv_array);
        let packet_number = connection.send_array.buffer_end;
        // TODO: set only if packet was sent successfully?
        connection.request_packet_sent_time = Some(clock_now());
        self.send_data_packet(connection, data, packet_number)
    }

    /// Send packets that were requested.
    fn send_requested_packets(&self, connection: &mut CryptoConnection) -> IoFuture<()> {
        let now = clock_now();
        let packets = connection.send_array.iter_mut()
            .filter(|(_, packet)| packet.requested)
            .map(|(i, packet)| {
                packet.requested = false;
                packet.sent_time = now;
                (i, packet.data.clone())
            }).collect::<Vec<_>>();
        let futures = packets.into_iter().map(|(i, data)|
            self.send_data_packet(connection, data, i)
        ).collect::<Vec<_>>();
        Box::new(future::join_all(futures).map(|_| ()))
    }

    /// The main loop that should be run at least 20 times per second
    fn main_loop(&self) -> IoFuture<()> {
        let connections = self.connections.read();
        let mut futures = Vec::new();
        let mut timed_out = Vec::new();

        // Only one cycle over all connections to prevent many lock acquirements
        for (&pk, connection) in connections.iter() {
            let mut connection = connection.write();

            if connection.is_timed_out() {
                timed_out.push((pk, connection.udp_addr));
                continue;
            }

            let send_future = self.send_status_packet(&mut connection);
            futures.push(send_future);

            if connection.is_not_confirmed() || connection.is_established() {
                let should_send = connection.request_packet_sent_time.map_or(true, |time|
                    clock_elapsed(time) > Duration::from_millis(CRYPTO_SEND_PACKET_INTERVAL)
                );
                if should_send {
                    futures.push(self.send_request_packet(&mut connection));
                }
            }

            if connection.is_established() {
                if connection.packet_recv_rate > CRYPTO_PACKET_MIN_RATE {
                    let request_packet_interval = connection.request_packet_interval();
                    let should_send = connection.request_packet_sent_time.map_or(true, |time|
                        clock_elapsed(time) > request_packet_interval
                    );
                    if should_send {
                        futures.push(self.send_request_packet(&mut connection));
                    }
                }

                // TODO: either use send_rate or remove it
                connection.update_congestion_stats();

                futures.push(self.send_requested_packets(&mut connection));
            }
        }

        // release read lock and acquire write lock if we have to delete some connections
        drop(connections);

        if !timed_out.is_empty() {
            let mut connections = self.connections.write();
            let mut keys_by_addr = self.keys_by_addr.write();
            for (pk, addr) in timed_out {
                connections.remove(&pk);
                if let Some(addr) = addr {
                    keys_by_addr.remove(&(addr.ip(), addr.port()));
                }
            }
        }

        Box::new(future::join_all(futures).map(|_| ()))
    }

    /// Run `net_crypto` periodical tasks. Result future will never be completed
    /// successfully.
    pub fn run(self) -> IoFuture<()> {
        let interval = Duration::from_secs(PACKET_COUNTER_AVERAGE_INTERVAL);
        let wakeups = Interval::new(Instant::now(), interval);

        let future = wakeups
            .map_err(|e| Error::new(ErrorKind::Other, format!("Net crypto timer error: {:?}", e)))
            .for_each(move |_instant| self.main_loop());

        Box::new(future)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::Stream;
    use tokio_executor;
    use tokio_timer::clock::*;

    use crate::toxcore::time::ConstNow;

    #[test]
    fn net_crypto_clone() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            precomputed_keys,
        });

        let _net_crypto_c = net_crypto.clone();
    }

    #[test]
    fn handle_cookie_request() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            precomputed_keys,
        });

        let cookie_request_id = 12345;

        let cookie_request_payload = CookieRequestPayload {
            pk: peer_real_pk,
            id: cookie_request_id,
        };
        let cookie_request = CookieRequest::new(&precomputed_key, &peer_dht_pk, &cookie_request_payload);

        let cookie_response = net_crypto.handle_cookie_request(&cookie_request).unwrap();
        let cookie_response_payload = cookie_response.get_payload(&precomputed_key).unwrap();

        assert_eq!(cookie_response_payload.id, cookie_request_id);

        let cookie = cookie_response_payload.cookie.get_payload(&net_crypto.symmetric_key).unwrap();
        assert_eq!(cookie.dht_pk, peer_dht_pk);
        assert_eq!(cookie.real_pk, peer_real_pk);
    }

    #[test]
    fn handle_cookie_request_invalid() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            precomputed_keys,
        });

        let cookie_request = CookieRequest {
            pk: gen_keypair().0,
            nonce: gen_nonce(),
            payload: vec![42; 88]
        };

        assert!(net_crypto.handle_cookie_request(&cookie_request).is_err());
    }

    #[test]
    fn handle_udp_cookie_request() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            precomputed_keys,
        });

        let cookie_request_id = 12345;

        let cookie_request_payload = CookieRequestPayload {
            pk: peer_real_pk,
            id: cookie_request_id,
        };
        let cookie_request = CookieRequest::new(&precomputed_key, &peer_dht_pk, &cookie_request_payload);

        let addr = "127.0.0.1:12345".parse().unwrap();

        net_crypto.handle_udp_cookie_request(&cookie_request, addr).wait().unwrap();

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();
        let cookie_response = unpack!(packet, Packet::CookieResponse);

        assert_eq!(addr_to_send, addr);

        let cookie_response_payload = cookie_response.get_payload(&precomputed_key).unwrap();

        assert_eq!(cookie_response_payload.id, cookie_request_id);

        let cookie = cookie_response_payload.cookie.get_payload(&net_crypto.symmetric_key).unwrap();
        assert_eq!(cookie.dht_pk, peer_dht_pk);
        assert_eq!(cookie.real_pk, peer_real_pk);
    }

    #[test]
    fn handle_udp_cookie_request_invalid() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            precomputed_keys,
        });

        let cookie_request = CookieRequest {
            pk: gen_keypair().0,
            nonce: gen_nonce(),
            payload: vec![42; 88]
        };

        let addr = "127.0.0.1:12345".parse().unwrap();

        assert!(net_crypto.handle_udp_cookie_request(&cookie_request, addr).wait().is_err());
    }

    #[test]
    fn handle_cookie_response() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let cookie_request_id = unpack!(connection.status, ConnectionStatus::CookieRequesting, cookie_request_id);

        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let cookie_response_payload = CookieResponsePayload {
            cookie: cookie.clone(),
            id: cookie_request_id
        };
        let cookie_response = CookieResponse::new(&connection.dht_precomputed_key, &cookie_response_payload);

        net_crypto.handle_cookie_response(&mut connection, &cookie_response).wait().unwrap();

        let packet = unpack!(connection.status, ConnectionStatus::HandshakeSending, packet);
        let packet = unpack!(packet.dht_packet(), Packet::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&connection.dht_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[test]
    fn handle_cookie_response_invalid_status() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new_not_confirmed(
            &dht_sk,
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
        let cookie_response = CookieResponse::new(&connection.dht_precomputed_key, &cookie_response_payload);

        assert!(net_crypto.handle_cookie_response(&mut connection, &cookie_response).wait().is_err());
    }

    #[test]
    fn handle_cookie_response_invalid_request_id() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let cookie_request_id = unpack!(connection.status, ConnectionStatus::CookieRequesting, cookie_request_id);

        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let cookie_response_payload = CookieResponsePayload {
            cookie,
            id: cookie_request_id.overflowing_add(1).0
        };
        let cookie_response = CookieResponse::new(&connection.dht_precomputed_key, &cookie_response_payload);

        assert!(net_crypto.handle_cookie_response(&mut connection, &cookie_response).wait().is_err());
    }


    #[test]
    fn handle_udp_cookie_response() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let dht_precomputed_key = connection.dht_precomputed_key.clone();
        let cookie_request_id = unpack!(connection.status, ConnectionStatus::CookieRequesting, cookie_request_id);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let cookie_response_payload = CookieResponsePayload {
            cookie: cookie.clone(),
            id: cookie_request_id
        };
        let cookie_response = CookieResponse::new(&dht_precomputed_key, &cookie_response_payload);

        net_crypto.handle_udp_cookie_response(&cookie_response, addr).wait().unwrap();

        let connections = net_crypto.connections.read();
        let connection = connections.get(&peer_real_pk).unwrap().read().clone();

        let packet = unpack!(connection.status, ConnectionStatus::HandshakeSending, packet);
        let packet = unpack!(packet.dht_packet(), Packet::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&dht_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[test]
    fn handle_udp_cookie_response_no_connection() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
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

        assert!(net_crypto.handle_udp_cookie_response(&cookie_response, addr).wait().is_err());
    }

    #[test]
    fn handle_crypto_handshake_in_cookie_requesting_status() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

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
        let crypto_handshake = CryptoHandshake::new(&connection.dht_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).wait().unwrap();

        let received_nonce = unpack!(connection.status, ConnectionStatus::NotConfirmed, received_nonce);
        let peer_session_pk = unpack!(connection.status, ConnectionStatus::NotConfirmed, peer_session_pk);

        assert_eq!(received_nonce, base_nonce);
        assert_eq!(peer_session_pk, session_pk);

        let packet = unpack!(connection.status, ConnectionStatus::NotConfirmed, packet);
        let packet = unpack!(packet.dht_packet(), Packet::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&connection.dht_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[test]
    fn handle_crypto_handshake_in_not_confirmed_status() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; 88]
        };
        let mut connection = CryptoConnection::new_not_confirmed(
            &dht_sk,
            peer_real_pk,
            peer_dht_pk,
            gen_nonce(),
            gen_keypair().0,
            cookie.clone(),
            &net_crypto.symmetric_key
        );

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
        let crypto_handshake = CryptoHandshake::new(&connection.dht_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).wait().unwrap();

        // Nonce and session pk should be taken from the packet
        let received_nonce = unpack!(connection.status, ConnectionStatus::NotConfirmed, received_nonce);
        let peer_session_pk = unpack!(connection.status, ConnectionStatus::NotConfirmed, peer_session_pk);

        assert_eq!(received_nonce, base_nonce);
        assert_eq!(peer_session_pk, session_pk);

        // cookie should not be updated
        let packet = unpack!(connection.status, ConnectionStatus::NotConfirmed, packet);
        let packet = unpack!(packet.dht_packet(), Packet::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&connection.dht_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[test]
    fn handle_crypto_handshake_invalid_status() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce: gen_nonce(),
            peer_session_pk,
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
        let crypto_handshake = CryptoHandshake::new(&connection.dht_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        assert!(net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).wait().is_err());
    }

    #[test]
    fn handle_crypto_handshake_invalid_hash() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

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
        let crypto_handshake = CryptoHandshake::new(&connection.dht_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        assert!(net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).wait().is_err());
    }

    #[test]
    fn handle_crypto_handshake_timed_out_cookie() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

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
        let crypto_handshake = CryptoHandshake::new(&connection.dht_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        assert!(net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).wait().is_err());
    }

    #[test]
    fn handle_crypto_handshake_invalid_peer_real_pk() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_dht_pk, peer_dht_pk);
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
        let crypto_handshake = CryptoHandshake::new(&connection.dht_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        assert!(net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).wait().is_err());
    }

    #[test]
    fn handle_crypto_handshake_invalid_peer_dht_pk() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let (new_dht_pk, _new_dht_sk) = gen_keypair();

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
        let crypto_handshake = CryptoHandshake::new(&connection.dht_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        assert!(net_crypto.handle_crypto_handshake(&mut connection, &crypto_handshake).wait().is_err());

        let (keys, _dht_pk_rx) = dht_pk_rx.into_future().wait().unwrap();
        let (received_real_pk, received_dht_pk) = keys.unwrap();

        assert_eq!(received_real_pk, peer_real_pk);
        assert_eq!(received_dht_pk, new_dht_pk);
    }

    #[test]
    fn handle_udp_crypto_handshake() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let dht_precomputed_key = connection.dht_precomputed_key.clone();

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

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
        let crypto_handshake = CryptoHandshake::new(&dht_precomputed_key, &crypto_handshake_payload, our_encrypted_cookie);

        net_crypto.handle_udp_crypto_handshake(&crypto_handshake, addr).wait().unwrap();

        let connections = net_crypto.connections.read();
        let connection = connections.get(&peer_real_pk).unwrap().read().clone();

        let received_nonce = unpack!(connection.status, ConnectionStatus::NotConfirmed, received_nonce);
        let peer_session_pk = unpack!(connection.status, ConnectionStatus::NotConfirmed, peer_session_pk);

        assert_eq!(received_nonce, base_nonce);
        assert_eq!(peer_session_pk, session_pk);

        let packet = unpack!(connection.status, ConnectionStatus::NotConfirmed, packet);
        let packet = unpack!(packet.dht_packet(), Packet::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&dht_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[test]
    fn handle_crypto_data_lossy() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait().unwrap();

        // The diff between nonces is not bigger than the threshold so received
        // nonce shouldn't be changed
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);

        let (received, _lossy_rx) = lossy_rx.into_future().wait().unwrap();
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]);
    }

    #[test]
    fn handle_crypto_data_lossy_increment_nonce() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
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

        net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait().unwrap();

        // The diff between nonces is bigger than the threshold so received
        // nonce should be changed increased
        let mut expected_nonce = received_nonce;
        increment_nonce_number(&mut expected_nonce, u64::from(NONCE_DIFF_THRESHOLD));
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), expected_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);

        let (received, _lossy_rx) = lossy_rx.into_future().wait().unwrap();
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]);
    }

    #[test]
    fn handle_crypto_data_lossy_update_rtt() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let now = Instant::now();

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
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 1,
            packet_number: 0,
            data: vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(now + Duration::from_millis(250)));

        with_default(&clock, &mut enter, |_| {
            net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait().unwrap();
        });

        // The diff between nonces is not bigger than the threshold so received
        // nonce shouldn't be changed
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 1);
        assert_eq!(connection.send_array.buffer_end, 1);

        let (received, _lossy_rx) = lossy_rx.into_future().wait().unwrap();
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]);

        // avoid problems with floating point arithmetic
        assert!(
            connection.rtt > Duration::from_millis(249)
                && connection.rtt < Duration::from_millis(251)
        );
    }

    #[test]
    fn handle_crypto_data_lossy_invalid_buffer_start() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 7, // bigger than end index of sent packets buffer
            packet_number: 0,
            data: vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        assert!(net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait().is_err());

        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);
    }

    #[test]
    fn handle_crypto_data_lossless() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
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
        net_crypto.handle_crypto_data(&mut connection, &crypto_data_2, /* udp */ true).wait().unwrap();
        net_crypto.handle_crypto_data(&mut connection, &crypto_data_3, /* udp */ true).wait().unwrap();
        net_crypto.handle_crypto_data(&mut connection, &crypto_data_1, /* udp */ true).wait().unwrap();

        // The diff between nonces is not bigger than the threshold so received
        // nonce shouldn't be changed
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 3);
        assert_eq!(connection.recv_array.buffer_end, 3);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);

        // We should receive lossless packets according to their numbers

        let (received, lossless_rx) = lossless_rx.into_future().wait().unwrap();
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START - 1, 1, 2, 3]);

        let (received, lossless_rx) = lossless_rx.into_future().wait().unwrap();
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START - 1, 4, 5, 6]);

        let (received, _lossless_rx) = lossless_rx.into_future().wait().unwrap();
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START - 1, 7, 8, 9]);
    }

    #[test]
    fn handle_crypto_data_lossless_too_big_index() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: CRYPTO_PACKET_BUFFER_SIZE,
            data: vec![PACKET_ID_LOSSY_RANGE_START - 1, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        assert!(net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait().is_err());

        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);
    }

    #[test]
    fn handle_crypto_data_kill() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let connection = Arc::new(RwLock::new(connection));
        net_crypto.connections.write().insert(peer_real_pk, connection.clone());
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![PACKET_ID_KILL]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        net_crypto.handle_crypto_data(&mut connection.write(), &crypto_data, /* udp */ true).wait().unwrap();

        assert!(net_crypto.connections.read().is_empty());
        assert!(net_crypto.keys_by_addr.read().is_empty());
    }

    #[test]
    fn handle_crypto_data_request() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let now = Instant::now();

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
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![PACKET_ID_REQUEST, 1, 5, 0, 0, 0, 254] // request 0, 5 and 1024 packets
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(now + Duration::from_secs(1)));

        with_default(&clock, &mut enter, |_| {
            net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait().unwrap();
        });

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

    #[test]
    fn handle_crypto_data_empty_request() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

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
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![PACKET_ID_REQUEST]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait().unwrap();

        assert!(!connection.send_array.get(0).unwrap().requested);
        assert!(!connection.send_array.get(1).unwrap().requested);
        assert!(!connection.send_array.get(5).unwrap().requested);
        assert!(!connection.send_array.get(7).unwrap().requested);
        assert!(!connection.send_array.get(1024).unwrap().requested);
    }

    #[test]
    fn handle_crypto_data_invalid_packet_id() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![255, 1, 2, 3] // only 255 is invalid id
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        assert!(net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait().is_err());

        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);
    }

    #[test]
    fn handle_crypto_data_empty_data() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: Vec::new()
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        assert!(net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait().is_err());

        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);
    }

    #[test]
    fn handle_crypto_data_invalid_status() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

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

        assert!(net_crypto.handle_crypto_data(&mut connection, &crypto_data, /* udp */ true).wait().is_err());
    }

    #[test]
    fn handle_udp_crypto_data_lossy() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        let crypto_data_payload = CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![0, 0, PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]
        };
        let crypto_data = CryptoData::new(&session_precomputed_key, received_nonce, &crypto_data_payload);

        net_crypto.handle_udp_crypto_data(&crypto_data, addr).wait().unwrap();

        let connections = net_crypto.connections.read();
        let connection = connections.get(&peer_real_pk).unwrap().read().clone();

        // The diff between nonces is not bigger than the threshold so received
        // nonce shouldn't be changed
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);

        assert_eq!(connection.recv_array.buffer_start, 0);
        assert_eq!(connection.recv_array.buffer_end, 0);
        assert_eq!(connection.send_array.buffer_start, 0);
        assert_eq!(connection.send_array.buffer_end, 0);

        let (received, _lossy_rx) = lossy_rx.into_future().wait().unwrap();
        let (received_peer_real_pk, received_data) = received.unwrap();
        assert_eq!(received_peer_real_pk, peer_real_pk);
        assert_eq!(received_data, vec![PACKET_ID_LOSSY_RANGE_START, 1, 2, 3]);
    }

    #[test]
    fn send_status_packet() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);
        connection.update_udp_received_time();

        // send status packet first time - it should be sent
        net_crypto.send_status_packet(&mut connection).wait().unwrap();

        let packet = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, packet);
        assert_eq!(packet.num_sent, 1);

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(received, packet.dht_packet());
        assert_eq!(addr_to_send, addr);

        // send status packet again - it shouldn't be sent
        net_crypto.send_status_packet(&mut connection).wait().unwrap();

        let packet = unpack!(connection.status, ConnectionStatus::CookieRequesting, packet);
        assert_eq!(packet.num_sent, 1);
    }

    #[test]
    fn send_packet_udp() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);
        connection.update_udp_received_time();

        let packet = Packet::CryptoData(CryptoData {
            nonce_last_bytes: 123,
            payload: vec![42; DHT_ATTEMPT_MAX_PACKET_LENGTH]
        });

        net_crypto.send_packet(packet.clone(), &mut connection).wait().unwrap();

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);
        assert_eq!(received, packet);
    }

    #[test]
    fn send_packet_udp_attempt() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);

        let packet = Packet::CryptoData(CryptoData {
            nonce_last_bytes: 123,
            payload: vec![42; DHT_ATTEMPT_MAX_PACKET_LENGTH - 3] // 1 byte of packet kind and 2 bytes of nonce
        });

        net_crypto.send_packet(packet.clone(), &mut connection).wait().unwrap();

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);
        assert_eq!(received, packet);

        // TODO: check that TCP received the packet
    }

    #[test]
    fn send_packet_no_udp_attempt() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);

        let packet = Packet::CryptoData(CryptoData {
            nonce_last_bytes: 123,
            payload: vec![42; DHT_ATTEMPT_MAX_PACKET_LENGTH]
        });

        net_crypto.send_packet(packet.clone(), &mut connection).wait().unwrap();

        // TODO: check that TCP received the packet
    }

    #[test]
    fn send_packet_tcp() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let packet = Packet::CryptoData(CryptoData {
            nonce_last_bytes: 123,
            payload: vec![42; DHT_ATTEMPT_MAX_PACKET_LENGTH]
        });

        net_crypto.send_packet(packet.clone(), &mut connection).wait().unwrap();

        // TODO: check that TCP received the packet
    }

    #[test]
    fn main_loop_sends_status_packets() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let packet = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, packet).dht_packet();

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);
        connection.update_udp_received_time();

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));

        net_crypto.main_loop().wait().unwrap();

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);
        assert_eq!(received, packet);
    }

    #[test]
    fn main_loop_removes_timed_out_connections() {
        crypto_init().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);

        // make the connection timed out
        let cookie_request_id = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, cookie_request_id);
        let mut packet = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, packet);
        packet.num_sent = MAX_NUM_SENDPACKET_TRIES;
        packet.sent_time -= Duration::from_millis(CRYPTO_SEND_PACKET_INTERVAL + 1000);
        connection.status = ConnectionStatus::CookieRequesting {
            cookie_request_id,
            packet
        };

        assert!(connection.is_timed_out());

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        net_crypto.main_loop().wait().unwrap();

        assert!(net_crypto.connections.read().is_empty());
        assert!(net_crypto.keys_by_addr.read().is_empty());
    }

    #[test]
    fn main_loop_sends_request_packets() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);
        connection.update_udp_received_time();

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        net_crypto.main_loop().wait().unwrap();

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, Packet::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 0);
        assert_eq!(payload.packet_number, 0);
        assert_eq!(payload.data, vec![PACKET_ID_REQUEST]);
    }

    #[test]
    fn main_loop_sends_requested_packets() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);
        connection.update_udp_received_time();

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            peer_session_pk,
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

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        net_crypto.main_loop().wait().unwrap();

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, Packet::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 0);
        assert_eq!(payload.packet_number, 0);
        assert_eq!(payload.data, data);
    }

    #[test]
    fn send_status_packet_established() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let received_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce,
            peer_session_pk,
            session_precomputed_key,
        };

        // send status packet with connection.status is Established
        net_crypto.send_status_packet(&mut connection).wait().unwrap();

        // Necessary to drop udp_tx so that udp_rx.collect() can be finished
        drop(net_crypto.udp_tx);

        assert!(udp_rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn send_data_packet() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);
        connection.update_udp_received_time();

        let received_nonce = gen_nonce();
        let mut sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        connection.recv_array.buffer_start = 23;
        connection.recv_array.buffer_end = 25;

        let data = vec![42; 123];
        net_crypto.send_data_packet(&mut connection, data.clone(), 7).wait().unwrap();

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, Packet::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 23);
        assert_eq!(payload.packet_number, 7);
        assert_eq!(payload.data, data);

        increment_nonce(&mut sent_nonce);
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, sent_nonce), sent_nonce);
        assert_eq!(unpack!(connection.status, ConnectionStatus::Established, received_nonce), received_nonce);
    }

    #[test]
    fn send_request_packet() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);
        connection.update_udp_received_time();

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            peer_session_pk,
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

        let now = Instant::now() + Duration::from_secs(1);
        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(now));

        with_default(&clock, &mut enter, |_| {
            net_crypto.send_request_packet(&mut connection).wait().unwrap();
        });

        assert_eq!(connection.request_packet_sent_time, Some(now));

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, Packet::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 0);
        assert_eq!(payload.packet_number, 0);
        assert_eq!(payload.data, vec![PACKET_ID_REQUEST, 1, 1, 2, 1, 0, 10]);
    }

    #[test]
    fn send_request_packet_too_many_missing_packets() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);
        connection.update_udp_received_time();

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            peer_session_pk,
            session_precomputed_key: session_precomputed_key.clone(),
        };

        connection.recv_array.buffer_end = MAX_CRYPTO_DATA_SIZE as u32 + 42;

        net_crypto.send_request_packet(&mut connection).wait().unwrap();

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(received, Packet::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.buffer_start, 0);
        assert_eq!(payload.packet_number, 0);
        assert_eq!(payload.data.len(), MAX_CRYPTO_DATA_SIZE);
    }

    #[test]
    fn send_requested_packets() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(2);
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk: dht_sk.clone(),
            real_pk,
            precomputed_keys,
        });

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(&dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);
        connection.update_udp_received_time();

        let received_nonce = gen_nonce();
        let sent_nonce = gen_nonce();
        let (peer_session_pk, _peer_session_sk) = gen_keypair();
        let (_session_pk, session_sk) = gen_keypair();
        let session_precomputed_key = precompute(&peer_session_pk, &session_sk);
        connection.status = ConnectionStatus::Established {
            sent_nonce,
            received_nonce,
            peer_session_pk,
            session_precomputed_key,
        };

        let now = Instant::now();
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

        let next_now = now + Duration::from_secs(1);
        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(next_now));

        with_default(&clock, &mut enter, |_| {
            net_crypto.send_requested_packets(&mut connection).wait().unwrap();
        });

        assert!(!connection.send_array.get(2).unwrap().requested);
        assert!(!connection.send_array.get(4).unwrap().requested);
        assert!(!connection.send_array.get(5).unwrap().requested);
        assert_eq!(connection.send_array.get(2).unwrap().sent_time, next_now);
        assert_eq!(connection.send_array.get(4).unwrap().sent_time, now);
        assert_eq!(connection.send_array.get(5).unwrap().sent_time, next_now);

        // Necessary to drop udp_tx so that udp_rx.collect() can be finished
        drop(net_crypto.udp_tx);

        assert_eq!(udp_rx.collect().wait().unwrap().len(), 2);
    }
}
