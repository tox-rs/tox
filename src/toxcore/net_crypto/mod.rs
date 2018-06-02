/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2018 Evgeny Kurnevsky <kurnevsky@gmail.com>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

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

pub use self::crypto_connection::*;

use std::collections::HashMap;
use std::io::{ErrorKind, Error};
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;

use futures::Future;
use futures::future;
use futures::sync::mpsc;
use parking_lot::RwLock;

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::dht::packet::*;
use toxcore::io_tokio::*;

/// Maximum size of `DhtPacket` when we try to send it to UDP address even if
/// it's considered dead.
const DHT_ATTEMPT_MAX_PACKET_LENGTH: usize = 95;

/// Shorthand for the transmit half of the message channel for sending DHT
/// packets.
type UdpTx = mpsc::UnboundedSender<(DhtPacket, SocketAddr)>;

/// Shorthand for the transmit half of the message channel for sending DHT
/// `PublicKey` when it gets known. The first key is a long term key, the second
/// key is a DHT key.
type DhtPkTx = mpsc::UnboundedSender<(PublicKey, PublicKey)>;

/** Struct that manages crypto connections to friends and handles net crypto
packets from both UDP and TCP connections.
*/
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
}

impl NetCrypto {
    /// Create new `NetCrypto` object
    pub fn new(udp_tx: UdpTx, dht_pk_tx: DhtPkTx, dht_pk: PublicKey, dht_sk: SecretKey, real_pk: PublicKey) -> NetCrypto {
        NetCrypto {
            udp_tx,
            dht_pk_tx,
            dht_pk,
            dht_sk,
            real_pk,
            symmetric_key: secretbox::gen_key(),
            connections: Arc::new(RwLock::new(HashMap::new())),
            keys_by_addr: Arc::new(RwLock::new(HashMap::new()))
        }
    }

    /// Send `DhtPacket` packet to UDP socket
    fn send_to_udp(&self, addr: SocketAddr, packet: DhtPacket) -> IoFuture<()> {
        send_to(&self.udp_tx, (packet, addr))
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
    fn handle_cookie_request(&self, packet: CookieRequest) -> Result<CookieResponse, Error> {
        let payload = packet.get_payload(&self.dht_sk)?;

        let cookie = Cookie::new(payload.pk, packet.pk);
        let encrypted_cookie = EncryptedCookie::new(&self.symmetric_key, cookie);

        let response_payload = CookieResponsePayload {
            cookie: encrypted_cookie,
            id: payload.id,
        };
        let precomputed_key = precompute(&packet.pk, &self.dht_sk);
        let response = CookieResponse::new(&precomputed_key, response_payload);

        Ok(response)
    }

    /// Handle `CookieRequest` packet received from UDP socket
    pub fn handle_udp_cookie_request(&self, packet: CookieRequest, addr: SocketAddr) -> IoFuture<()> {
        match self.handle_cookie_request(packet) {
            Ok(response) => self.send_to_udp(addr, DhtPacket::CookieResponse(response)),
            Err(e) => Box::new(future::err(e))
        }
    }

    /// Handle `CookieResponse` and if it's correct change connection status to `HandshakeSending`.
    pub fn handle_cookie_response(&self, connection: &mut CryptoConnection, packet: CookieResponse) -> IoFuture<()> {
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
            Err(e) => return Box::new(future::err(e)),
        };

        if payload.id != cookie_request_id {
            return Box::new(future::err(Error::new(
                ErrorKind::Other,
                format!("Invalid cookie request id: expected {} but got {}", cookie_request_id, payload.id)
            )))
        }

        let sent_nonce = gen_nonce();
        let our_cookie = Cookie::new(connection.peer_real_pk, connection.peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&self.symmetric_key, our_cookie);
        let handshake_payload = CryptoHandshakePayload {
            base_nonce: sent_nonce,
            session_pk: connection.session_pk,
            cookie_hash: payload.cookie.hash(),
            cookie: our_encrypted_cookie,
        };
        let handshake = CryptoHandshake::new(&connection.dht_precomputed_key, handshake_payload, payload.cookie);

        connection.status = ConnectionStatus::HandshakeSending {
            sent_nonce,
            packet: StatusPacket::new_crypto_handshake(handshake)
        };

        self.send_status_packet(connection)
    }

    /// Handle `CookieResponse` packet received from UDP socket
    pub fn handle_udp_cookie_response(&self, packet: CookieResponse, addr: SocketAddr) -> IoFuture<()> {
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
    pub fn handle_crypto_handshake(&self, connection: &mut CryptoConnection, packet: CryptoHandshake) -> IoFuture<()> {
        if let ConnectionStatus::Established { .. } = connection.status {
            return Box::new(future::err(Error::new(
                ErrorKind::Other,
                "Can't handle CryptoHandshake in current connection state"
            )))
        }

        let payload = match packet.get_payload(&connection.dht_precomputed_key) {
            Ok(payload) => payload,
            Err(e) => return Box::new(future::err(e)),
        };

        if packet.cookie.hash() != payload.cookie_hash {
            return Box::new(future::err(Error::new(
                ErrorKind::Other,
                "Invalid SHA512 hash of cookie"
            )))
        }

        let cookie = match packet.cookie.get_payload(&self.symmetric_key) {
            Ok(cookie) => cookie,
            Err(e) => return Box::new(future::err(e)),
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
                let our_encrypted_cookie = EncryptedCookie::new(&self.symmetric_key, our_cookie);
                let handshake_payload = CryptoHandshakePayload {
                    base_nonce: sent_nonce,
                    session_pk: connection.session_pk,
                    cookie_hash: payload.cookie.hash(),
                    cookie: our_encrypted_cookie,
                };
                let handshake = CryptoHandshake::new(&connection.dht_precomputed_key, handshake_payload, payload.cookie);
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
    pub fn handle_udp_crypto_handshake(&self, packet: CryptoHandshake, addr: SocketAddr) -> IoFuture<()> {
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

    /// Send packet to crypto connection choosing TCP or UDP protocol
    fn send_packet(&self, packet: DhtPacket, connection: &mut CryptoConnection) -> IoFuture<()> {
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

    /// The main loop that should be run at least 20 times per second
    pub fn main_loop(&self) -> IoFuture<()> {
        let connections = self.connections.read();
        let len = connections.len();
        let mut send_futures = Vec::with_capacity(len);
        let mut timed_out = Vec::with_capacity(len);
        // Only one cycle over all connections to prevent many lock acquirements
        for (&pk, connection) in connections.iter() {
            let mut connection = connection.write();

            if connection.is_timed_out() {
                timed_out.push((pk, connection.udp_addr));
                continue;
            }

            let send_future = self.send_status_packet(&mut connection);
            send_futures.push(send_future);
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
        Box::new(future::join_all(send_futures).map(|_| ()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use futures::Stream;

    macro_rules! unpack {
        ($variable:expr, $variant:path, $name:ident) => (
            match $variable {
                $variant { $name, .. } => $name,
                other => panic!("Expected {} but got {:?}", stringify!($variant), other),
            }
        );
        ($variable:expr, $variant:path) => (
            match $variable {
                $variant(inner) => inner,
                other => panic!("Expected {} but got {:?}", stringify!($variant), other),
            }
        )
    }

    #[test]
    fn net_crypto_clone() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let _net_crypto_c = net_crypto.clone();
    }

    #[test]
    fn handle_cookie_request() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let cookie_request_id = 12345;

        let cookie_request_payload = CookieRequestPayload {
            pk: peer_real_pk,
            id: cookie_request_id,
        };
        let cookie_request = CookieRequest::new(&precomputed_key, &peer_dht_pk, cookie_request_payload);

        let cookie_response = net_crypto.handle_cookie_request(cookie_request).unwrap();
        let cookie_response_payload = cookie_response.get_payload(&precomputed_key).unwrap();

        assert_eq!(cookie_response_payload.id, cookie_request_id);

        let cookie = cookie_response_payload.cookie.get_payload(&net_crypto.symmetric_key).unwrap();
        assert_eq!(cookie.dht_pk, peer_dht_pk);
        assert_eq!(cookie.real_pk, peer_real_pk);
    }

    #[test]
    fn handle_cookie_request_invalid() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let cookie_request = CookieRequest {
            pk: gen_keypair().0,
            nonce: gen_nonce(),
            payload: vec![42; 88]
        };

        assert!(net_crypto.handle_cookie_request(cookie_request).is_err());
    }

    #[test]
    fn handle_udp_cookie_request() {
        let (udp_tx, udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let cookie_request_id = 12345;

        let cookie_request_payload = CookieRequestPayload {
            pk: peer_real_pk,
            id: cookie_request_id,
        };
        let cookie_request = CookieRequest::new(&precomputed_key, &peer_dht_pk, cookie_request_payload);

        let addr = "127.0.0.1:12345".parse().unwrap();

        assert!(net_crypto.handle_udp_cookie_request(cookie_request, addr).wait().is_ok());

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();
        let cookie_response = unpack!(packet, DhtPacket::CookieResponse);

        assert_eq!(addr_to_send, addr);

        let cookie_response_payload = cookie_response.get_payload(&precomputed_key).unwrap();

        assert_eq!(cookie_response_payload.id, cookie_request_id);

        let cookie = cookie_response_payload.cookie.get_payload(&net_crypto.symmetric_key).unwrap();
        assert_eq!(cookie.dht_pk, peer_dht_pk);
        assert_eq!(cookie.real_pk, peer_real_pk);
    }

    #[test]
    fn handle_udp_cookie_request_invalid() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let cookie_request = CookieRequest {
            pk: gen_keypair().0,
            nonce: gen_nonce(),
            payload: vec![42; 88]
        };

        let addr = "127.0.0.1:12345".parse().unwrap();

        assert!(net_crypto.handle_udp_cookie_request(cookie_request, addr).wait().is_err());
    }

    #[test]
    fn handle_cookie_response() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let cookie_request_id = unpack!(connection.status, ConnectionStatus::CookieRequesting, cookie_request_id);

        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let cookie_response_payload = CookieResponsePayload {
            cookie: cookie.clone(),
            id: cookie_request_id
        };
        let cookie_response = CookieResponse::new(&connection.dht_precomputed_key, cookie_response_payload);

        assert!(net_crypto.handle_cookie_response(&mut connection, cookie_response).wait().is_ok());

        let packet = unpack!(connection.status, ConnectionStatus::HandshakeSending, packet);
        let packet = unpack!(packet.dht_packet(), DhtPacket::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&connection.dht_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[test]
    fn handle_cookie_response_invalid_status() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new_not_confirmed(
            dht_sk,
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
        let cookie_response = CookieResponse::new(&connection.dht_precomputed_key, cookie_response_payload);

        assert!(net_crypto.handle_cookie_response(&mut connection, cookie_response).wait().is_err());
    }

    #[test]
    fn handle_cookie_response_invalid_request_id() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let cookie_request_id = unpack!(connection.status, ConnectionStatus::CookieRequesting, cookie_request_id);

        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let cookie_response_payload = CookieResponsePayload {
            cookie,
            id: cookie_request_id.overflowing_add(1).0
        };
        let cookie_response = CookieResponse::new(&connection.dht_precomputed_key, cookie_response_payload);

        assert!(net_crypto.handle_cookie_response(&mut connection, cookie_response).wait().is_err());
    }


    #[test]
    fn handle_udp_cookie_response() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

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
        let cookie_response = CookieResponse::new(&dht_precomputed_key, cookie_response_payload);

        assert!(net_crypto.handle_udp_cookie_response(cookie_response, addr).wait().is_ok());

        let connections = net_crypto.connections.read();
        let connection = connections.get(&peer_real_pk).unwrap().read().clone();

        let packet = unpack!(connection.status, ConnectionStatus::HandshakeSending, packet);
        let packet = unpack!(packet.dht_packet(), DhtPacket::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&dht_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[test]
    fn handle_udp_cookie_response_no_connection() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

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
        let cookie_response = CookieResponse::new(&dht_precomputed_key, cookie_response_payload);

        assert!(net_crypto.handle_udp_cookie_response(cookie_response, addr).wait().is_err());
    }

    #[test]
    fn handle_crypto_handshake_in_cookie_requesting_status() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, our_cookie);
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
        let crypto_handshake = CryptoHandshake::new(&connection.dht_precomputed_key, crypto_handshake_payload, our_encrypted_cookie);

        assert!(net_crypto.handle_crypto_handshake(&mut connection, crypto_handshake).wait().is_ok());

        let received_nonce = unpack!(connection.status, ConnectionStatus::NotConfirmed, received_nonce);
        let peer_session_pk = unpack!(connection.status, ConnectionStatus::NotConfirmed, peer_session_pk);

        assert_eq!(received_nonce, base_nonce);
        assert_eq!(peer_session_pk, session_pk);

        let packet = unpack!(connection.status, ConnectionStatus::NotConfirmed, packet);
        let packet = unpack!(packet.dht_packet(), DhtPacket::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&connection.dht_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[test]
    fn handle_crypto_handshake_in_not_confirmed_status() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; 88]
        };
        let mut connection = CryptoConnection::new_not_confirmed(
            dht_sk,
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
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, our_cookie);
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
        let crypto_handshake = CryptoHandshake::new(&connection.dht_precomputed_key, crypto_handshake_payload, our_encrypted_cookie);

        assert!(net_crypto.handle_crypto_handshake(&mut connection, crypto_handshake).wait().is_ok());

        // Nonce and session pk should be taken from the packet
        let received_nonce = unpack!(connection.status, ConnectionStatus::NotConfirmed, received_nonce);
        let peer_session_pk = unpack!(connection.status, ConnectionStatus::NotConfirmed, peer_session_pk);

        assert_eq!(received_nonce, base_nonce);
        assert_eq!(peer_session_pk, session_pk);

        // cookie should not be updated
        let packet = unpack!(connection.status, ConnectionStatus::NotConfirmed, packet);
        let packet = unpack!(packet.dht_packet(), DhtPacket::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&connection.dht_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[test]
    fn handle_crypto_handshake_invalid_status() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

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
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, our_cookie);
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
        let crypto_handshake = CryptoHandshake::new(&connection.dht_precomputed_key, crypto_handshake_payload, our_encrypted_cookie);

        assert!(net_crypto.handle_crypto_handshake(&mut connection, crypto_handshake).wait().is_err());
    }

    #[test]
    fn handle_crypto_handshake_invalid_hash() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, our_cookie);
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
        let crypto_handshake = CryptoHandshake::new(&connection.dht_precomputed_key, crypto_handshake_payload, our_encrypted_cookie);

        assert!(net_crypto.handle_crypto_handshake(&mut connection, crypto_handshake).wait().is_err());
    }

    #[test]
    fn handle_crypto_handshake_timed_out_cookie() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let mut our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        our_cookie.time -= COOKIE_TIMEOUT + 1;
        let our_encrypted_cookie = EncryptedCookie::new(&&net_crypto.symmetric_key, our_cookie);
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
        let crypto_handshake = CryptoHandshake::new(&connection.dht_precomputed_key, crypto_handshake_payload, our_encrypted_cookie);

        assert!(net_crypto.handle_crypto_handshake(&mut connection, crypto_handshake).wait().is_err());
    }

    #[test]
    fn handle_crypto_handshake_invalid_peer_real_pk() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_dht_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, our_cookie);
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
        let crypto_handshake = CryptoHandshake::new(&connection.dht_precomputed_key, crypto_handshake_payload, our_encrypted_cookie);

        assert!(net_crypto.handle_crypto_handshake(&mut connection, crypto_handshake).wait().is_err());
    }

    #[test]
    fn handle_crypto_handshake_invalid_peer_dht_pk() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let (new_dht_pk, _new_dht_sk) = gen_keypair();

        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, new_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, our_cookie);
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
        let crypto_handshake = CryptoHandshake::new(&connection.dht_precomputed_key, crypto_handshake_payload, our_encrypted_cookie);

        assert!(net_crypto.handle_crypto_handshake(&mut connection, crypto_handshake).wait().is_err());

        let (keys, _dht_pk_rx) = dht_pk_rx.into_future().wait().unwrap();
        let (received_real_pk, received_dht_pk) = keys.unwrap();

        assert_eq!(received_real_pk, peer_real_pk);
        assert_eq!(received_dht_pk, new_dht_pk);
    }

    #[test]
    fn handle_udp_crypto_handshake() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let dht_precomputed_key = connection.dht_precomputed_key.clone();

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        let base_nonce = gen_nonce();
        let session_pk = gen_keypair().0;
        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(&net_crypto.symmetric_key, our_cookie);
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
        let crypto_handshake = CryptoHandshake::new(&dht_precomputed_key, crypto_handshake_payload, our_encrypted_cookie);

        assert!(net_crypto.handle_udp_crypto_handshake(crypto_handshake, addr).wait().is_ok());

        let connections = net_crypto.connections.read();
        let connection = connections.get(&peer_real_pk).unwrap().read().clone();

        let received_nonce = unpack!(connection.status, ConnectionStatus::NotConfirmed, received_nonce);
        let peer_session_pk = unpack!(connection.status, ConnectionStatus::NotConfirmed, peer_session_pk);

        assert_eq!(received_nonce, base_nonce);
        assert_eq!(peer_session_pk, session_pk);

        let packet = unpack!(connection.status, ConnectionStatus::NotConfirmed, packet);
        let packet = unpack!(packet.dht_packet(), DhtPacket::CryptoHandshake);
        assert_eq!(packet.cookie, cookie);

        let payload = packet.get_payload(&dht_precomputed_key).unwrap();
        assert_eq!(payload.cookie_hash, cookie.hash());
    }

    #[test]
    fn send_status_packet() {
        let (udp_tx, udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);
        connection.update_udp_received_time();

        // send status packet first time - it should be sent
        assert!(net_crypto.send_status_packet(&mut connection).wait().is_ok());

        let packet = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, packet);
        assert_eq!(packet.num_sent, 1);

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(received, packet.dht_packet());
        assert_eq!(addr_to_send, addr);
        
        // send status packet again - it shouldn't be sent
        assert!(net_crypto.send_status_packet(&mut connection).wait().is_ok());

        let packet = unpack!(connection.status, ConnectionStatus::CookieRequesting, packet);
        assert_eq!(packet.num_sent, 1);
    }

    #[test]
    fn send_packet_udp() {
        let (udp_tx, udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);
        connection.update_udp_received_time();

        let packet = DhtPacket::CryptoData(CryptoData {
            nonce_last_bytes: 123,
            payload: vec![42; DHT_ATTEMPT_MAX_PACKET_LENGTH]
        });

        assert!(net_crypto.send_packet(packet.clone(), &mut connection).wait().is_ok());

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);
        assert_eq!(received, packet);
    }

    #[test]
    fn send_packet_udp_attempt() {
        let (udp_tx, udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);

        let packet = DhtPacket::CryptoData(CryptoData {
            nonce_last_bytes: 123,
            payload: vec![42; DHT_ATTEMPT_MAX_PACKET_LENGTH - 3] // 1 byte of packet kind and 2 bytes of nonce
        });

        assert!(net_crypto.send_packet(packet.clone(), &mut connection).wait().is_ok());

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);
        assert_eq!(received, packet);

        // TODO: check that TCP received the packet
    }

    #[test]
    fn send_packet_no_udp_attempt() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);

        let packet = DhtPacket::CryptoData(CryptoData {
            nonce_last_bytes: 123,
            payload: vec![42; DHT_ATTEMPT_MAX_PACKET_LENGTH]
        });

        assert!(net_crypto.send_packet(packet.clone(), &mut connection).wait().is_ok());

        // TODO: check that TCP received the packet
    }

    #[test]
    fn send_packet_tcp() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let packet = DhtPacket::CryptoData(CryptoData {
            nonce_last_bytes: 123,
            payload: vec![42; DHT_ATTEMPT_MAX_PACKET_LENGTH]
        });

        assert!(net_crypto.send_packet(packet.clone(), &mut connection).wait().is_ok());

        // TODO: check that TCP received the packet
    }

    #[test]
    fn main_loop_sends_status_packets() {
        let (udp_tx, udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let packet = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, packet).dht_packet();

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);
        connection.update_udp_received_time();

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));

        assert!(net_crypto.main_loop().wait().is_ok());

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);
        assert_eq!(received, packet);
    }

    #[test]
    fn main_loop_removes_timed_out_connections() {
        let (udp_tx, _udp_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let net_crypto = NetCrypto::new(udp_tx, dht_pk_tx, dht_pk, dht_sk.clone(), real_pk);

        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let addr = "127.0.0.1:12345".parse().unwrap();
        connection.udp_addr = Some(addr);

        // make the connection timed out
        let cookie_request_id = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, cookie_request_id);
        let mut packet = unpack!(connection.status.clone(), ConnectionStatus::CookieRequesting, packet);
        packet.num_sent = MAX_NUM_SENDPACKET_TRIES;
        packet.sent_time -= Duration::from_secs(CRYPTO_SEND_PACKET_INTERVAL + 1);
        connection.status = ConnectionStatus::CookieRequesting {
            cookie_request_id,
            packet
        };

        assert!(connection.is_timed_out());

        net_crypto.connections.write().insert(peer_real_pk, Arc::new(RwLock::new(connection)));
        net_crypto.keys_by_addr.write().insert((addr.ip(), addr.port()), peer_real_pk);

        assert!(net_crypto.main_loop().wait().is_ok());

        assert!(net_crypto.connections.read().is_empty());
        assert!(net_crypto.keys_by_addr.read().is_empty());
    }
}
