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

//! Crypto connection implementation.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use toxcore::crypto_core::*;
use toxcore::dht::packet::*;

/// How often in seconds `CookieRequest` or `CryptoHandshake` packets should be
/// sent
pub const CRYPTO_SEND_PACKET_INTERVAL: u64 = 1;

/// The maximum number of times we try to send the cookie request and handshake
/// before giving up
pub const MAX_NUM_SENDPACKET_TRIES: u8 = 8;

/// If we don't receive UDP packets for this amount of time in seconds the
/// direct UDP connection is considered dead
pub const UDP_DIRECT_TIMEOUT: u64 = 8;

/// Packet that should be sent every second. Depending on `ConnectionStatus` it
/// can be `CookieRequest` or `CryptoHandshake`
#[derive(Clone, Debug, Eq, PartialEq)]
enum StatusPacketEnum {
    /// `CookieRequest` packet
    CookieRequest(CookieRequest),
    /// `CryptoHandshake` packet
    CryptoHandshake(CryptoHandshake),
}

/// Packet that should be sent to the peer every second together with info how
/// many times it was sent and when it was sent last time
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusPacket {
    /// Packet that should be sent every second. Depending on `ConnectionStatus`
    /// it can be `CookieRequest` or `CryptoHandshake`
    packet: StatusPacketEnum,
    /// When packet was sent last time
    pub sent_time: SystemTime,
    /// How many times packet was sent
    pub num_sent: u8
}

impl StatusPacket {
    /// Create new `StatusPacket` with `CookieRequest` packet
    pub fn new_cookie_request(packet: CookieRequest) -> StatusPacket {
        StatusPacket {
            packet: StatusPacketEnum::CookieRequest(packet),
            sent_time: SystemTime::now(),
            num_sent: 0
        }
    }

    /// Create new `StatusPacket` with `CryptoHandshake` packet
    pub fn new_crypto_handshake(packet: CryptoHandshake) -> StatusPacket {
        StatusPacket {
            packet: StatusPacketEnum::CryptoHandshake(packet),
            sent_time: SystemTime::now(),
            num_sent: 0
        }
    }

    /// Get `DhtPacket` that should be sent every second
    pub fn dht_packet(&self) -> DhtPacket {
        match self.packet {
            StatusPacketEnum::CookieRequest(ref packet) => DhtPacket::CookieRequest(packet.clone()),
            StatusPacketEnum::CryptoHandshake(ref packet) => DhtPacket::CryptoHandshake(packet.clone()),
        }
    }

    /// Check if one second is elapsed since last time when the packet was sent
    fn is_time_elapsed(&self) -> bool {
        self.sent_time.elapsed().unwrap_or(Duration::from_secs(0)) > Duration::from_secs(CRYPTO_SEND_PACKET_INTERVAL)
    }

    /// Check if packet should be sent to the peer
    pub fn should_be_sent(&self) -> bool {
        self.num_sent == 0 || self.is_time_elapsed() && self.num_sent < MAX_NUM_SENDPACKET_TRIES
    }

    /// Check if we didn't receive response to this packet on time
    pub fn is_timed_out(&self) -> bool {
        self.num_sent >= MAX_NUM_SENDPACKET_TRIES && self.is_time_elapsed()
    }
}

/** Status of crypto connection.

Initial state is `CookieRequesting`. In this status we send up to 8
`CookieRequest` packets every second and waiting for a `CookieResponse` packet.
After receiving a `CookieResponse` packet we change the status to
`HandshakeSending` in which we send up to 8 `CryptoHandshake` packets every
second and waiting for `CryptoHandshake` packet from the other side. When we
received `CryptoHandshake` packet we change the status to `NotConfirmed` and
continue sending `CryptoHandshake` packets because we don't know if the other
side received our `CryptoHandshake` packet. Only after receiving first
`CryptoData` packet we change status to `Established` and stop sending
`CryptoHandshake` packets. In this status connection is considered as fully
established.

It's also possible that we received `CryptoHandshake` packet but didn't create
crypto connection yet. This means that we should skip first two states and use
`NotConfirmed` state as initial. We can do it because `CryptoHandshake` contains
`Cookie` that we can use to send our `CryptoHandshake`.

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionStatus {
    /// We are sending cookie request packets and haven't received cookie
    /// response yet.
    CookieRequesting {
        /// ID used in the cookie request packets for this connection
        cookie_request_id: u64,
        /// Packet that should be sent every second
        packet: StatusPacket,
    },
    /// We are sending handshake packets and haven't received handshake from the
    /// other side yet.
    HandshakeSending {
        /// Nonce that should be used to encrypt outgoing packets
        sent_nonce: Nonce,
        /// Packet that should be sent every second
        packet: StatusPacket,
    },
    /// A handshake packet has been received from the other side but no
    /// encrypted packets. Continue sending handshake packets because we can't
    /// know if the other side has received them.
    NotConfirmed {
        /// Nonce that should be used to encrypt outgoing packets
        sent_nonce: Nonce,
        /// Nonce that should be used to decrypt incoming packets
        received_nonce: Nonce,
        /// `PublicKey` of the other side for this session
        peer_session_pk: PublicKey,
        /// Packet that should be sent every second
        packet: StatusPacket,
    },
    /// A valid encrypted packet has been received from the other side.
    /// Connection is fully established.
    Established {
        /// Nonce that should be used to encrypt outgoing packets
        sent_nonce: Nonce,
        /// Nonce that should be used to decrypt incoming packets
        received_nonce: Nonce,
        /// `PublicKey` of the other side for this session
        peer_session_pk: PublicKey,
    },
}

/** Secure connection to send data between two friends that provides encryption,
ordered delivery, and perfect forward secrecy.

It can use both UDP and TCP (over relays) transport protocols to send data and
can switch between them without the peers needing to disconnect and reconnect.

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptoConnection {
    /// Precomputed key of our DHT `SecretKey` and peer's DHT `PublicKey`
    pub dht_precomputed_key: PrecomputedKey,
    /// Long term `PublicKey` of the peer we are connected to
    pub peer_real_pk: PublicKey,
    /// DHT `PublicKey` of the peer we are connected to
    pub peer_dht_pk: PublicKey,
    /// `SecretKey` for this session
    pub session_sk: SecretKey,
    /// `PublicKey` for this session
    pub session_pk: PublicKey,
    /// Current connection status
    pub status: ConnectionStatus,
    /// Address to send UDP packets directly to the peer
    pub udp_addr: Option<SocketAddr>, // TODO: separate v4 and v6?
    /// Time when last UDP packet was received
    pub udp_received_time: Option<SystemTime>,
    /// Time when we made an attempt to send UDP packet
    pub udp_send_attempt_time: Option<SystemTime>,
}

impl CryptoConnection {
    /// Create new `CryptoConnection` with `CookieRequesting` status. This
    /// function is used when we initiate crypto connection with a friend.
    pub fn new(dht_sk: SecretKey, dht_pk: PublicKey, real_pk: PublicKey, peer_real_pk: PublicKey, peer_dht_pk: PublicKey) -> CryptoConnection {
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let (session_pk, session_sk) = gen_keypair();

        let cookie_request_id = random_u64();
        let cookie_request_payload = CookieRequestPayload {
            pk: real_pk,
            id: cookie_request_id
        };
        let cookie_request = CookieRequest::new(&dht_precomputed_key, &dht_pk, cookie_request_payload);
        let status = ConnectionStatus::CookieRequesting {
            cookie_request_id,
            packet: StatusPacket::new_cookie_request(cookie_request)
        };

        CryptoConnection {
            dht_precomputed_key,
            peer_real_pk,
            peer_dht_pk,
            session_sk,
            session_pk,
            status,
            udp_addr: None,
            udp_received_time: None,
            udp_send_attempt_time: None
        }
    }

    /// Create new `CryptoConnection` with `NotConfirmed` status. This function
    /// is used when we got `CryptoHandshake` packet from a friend but didn't
    /// create `CryptoConnection` yet.
    pub fn new_not_confirmed(
        dht_sk: SecretKey,
        peer_real_pk: PublicKey,
        peer_dht_pk: PublicKey,
        received_nonce: Nonce,
        peer_session_pk: PublicKey,
        cookie: EncryptedCookie,
        symmetric_key: &secretbox::Key
    ) -> CryptoConnection {
        let dht_precomputed_key = precompute(&peer_dht_pk, &dht_sk);
        let (session_pk, session_sk) = gen_keypair();
        let sent_nonce = gen_nonce();

        let our_cookie = Cookie::new(peer_real_pk, peer_dht_pk);
        let our_encrypted_cookie = EncryptedCookie::new(symmetric_key, our_cookie);
        let handshake_payload = CryptoHandshakePayload {
            base_nonce: sent_nonce,
            session_pk,
            cookie_hash: cookie.hash(),
            cookie: our_encrypted_cookie,
        };
        let handshake = CryptoHandshake::new(&dht_precomputed_key, handshake_payload, cookie);
        let status = ConnectionStatus::NotConfirmed {
            sent_nonce,
            received_nonce,
            peer_session_pk,
            packet: StatusPacket::new_crypto_handshake(handshake)
        };

        CryptoConnection {
            dht_precomputed_key,
            peer_real_pk,
            peer_dht_pk,
            session_sk,
            session_pk,
            status,
            udp_addr: None,
            udp_received_time: None,
            udp_send_attempt_time: None
        }
    }

    /// Get `CookieRequest` or `CryptoHandshake` if it should be sent depending
    /// on connection status and update sent counter
    pub fn packet_to_send(&mut self) -> Option<DhtPacket> {
        match self.status {
            ConnectionStatus::CookieRequesting { ref mut packet, .. }
            | ConnectionStatus::HandshakeSending { ref mut packet, .. }
            | ConnectionStatus::NotConfirmed { ref mut packet, .. } => {
                if packet.should_be_sent() {
                    packet.num_sent += 1;
                    packet.sent_time = SystemTime::now();
                    Some(packet.dht_packet())
                } else {
                    None
                }
            },
            ConnectionStatus::Established { .. } => None,
        }
    }

    /// Check if this connection is timed out, i.e. we didn't receive expected
    /// packet in time
    pub fn is_timed_out(&self) -> bool {
        match self.status {
            ConnectionStatus::CookieRequesting { ref packet, .. }
            | ConnectionStatus::HandshakeSending { ref packet, .. }
            | ConnectionStatus::NotConfirmed { ref packet, .. } => packet.is_timed_out(),
            ConnectionStatus::Established { .. } => false, // TODO: timeout?
        }
    }

    /// Set time when last UDP packet was received to now
    pub fn update_udp_received_time(&mut self) {
        self.udp_received_time = Some(SystemTime::now())
    }

    /// Set time when we made an attempt to send UDP packet
    pub fn update_udp_send_attempt_time(&mut self) {
        self.udp_send_attempt_time = Some(SystemTime::now())
    }

    /// Check if we received the last UDP packet not later than 8 seconds ago
    pub fn is_udp_alive(&self) -> bool {
        self.udp_received_time
            .and_then(|time| time.elapsed().ok())
            .map(|duration| duration < Duration::from_secs(UDP_DIRECT_TIMEOUT))
            .unwrap_or(false)
    }

    /// Check if we should send UDP packet regardless of whether UDP is dead or
    /// alive. In this case we shouldn't rely on UDP only and send the same
    /// packet via TCP relay
    pub fn udp_attempt_should_be_made(&self) -> bool {
        self.udp_send_attempt_time
            .and_then(|time| time.elapsed().ok())
            .map(|duration| duration >= Duration::from_secs(UDP_DIRECT_TIMEOUT / 2))
            .unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_packet_should_be_sent() {
        // just created packet should be sent
        let mut packet = StatusPacket::new_cookie_request(CookieRequest {
            pk: gen_keypair().0,
            nonce: gen_nonce(),
            payload: vec![42; 88]
        });
        assert!(packet.should_be_sent());
        // packet shouldn't be sent if it was sent not earlier than 1 second ago
        packet.num_sent += 1;
        assert!(!packet.should_be_sent());
        // packet should be sent if it was sent earlier than 1 second ago
        packet.sent_time -= Duration::from_secs(CRYPTO_SEND_PACKET_INTERVAL + 1);
        assert!(packet.should_be_sent());
        // packet shouldn't be sent if it was sent 8 times or more
        packet.num_sent += MAX_NUM_SENDPACKET_TRIES;
        assert!(!packet.should_be_sent());
    }

    #[test]
    fn status_packet_is_timed_out() {
        // just created packet isn't timed out
        let mut packet = StatusPacket::new_cookie_request(CookieRequest {
            pk: gen_keypair().0,
            nonce: gen_nonce(),
            payload: vec![42; 88]
        });
        assert!(!packet.is_timed_out());
        // packet is timed out if it was sent 8 times and 1 second elapsed since last sending
        packet.num_sent += MAX_NUM_SENDPACKET_TRIES;
        packet.sent_time -= Duration::from_secs(CRYPTO_SEND_PACKET_INTERVAL + 1);
        assert!(packet.is_timed_out());
    }

    #[test]
    fn crypto_connection_clone() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, _real_sk) = gen_keypair();
        let (peer_dht_pk, _peer_dht_sk) = gen_keypair();
        let (peer_real_pk, _peer_real_sk) = gen_keypair();
        let mut connection = CryptoConnection::new(dht_sk, dht_pk, real_pk, peer_real_pk, peer_dht_pk);

        let connection_c = connection.clone();
        assert_eq!(connection_c, connection);

        let crypto_handshake = CryptoHandshake {
            cookie: EncryptedCookie {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; 88]
            },
            nonce: gen_nonce(),
            payload: vec![42; 248]
        };

        connection.status = ConnectionStatus::HandshakeSending {
            sent_nonce: gen_nonce(),
            packet: StatusPacket::new_crypto_handshake(crypto_handshake.clone())
        };

        let connection_c = connection.clone();
        assert_eq!(connection_c, connection);

        connection.status = ConnectionStatus::NotConfirmed {
            sent_nonce: gen_nonce(),
            received_nonce: gen_nonce(),
            peer_session_pk: gen_keypair().0,
            packet: StatusPacket::new_crypto_handshake(crypto_handshake),
        };

        let connection_c = connection.clone();
        assert_eq!(connection_c, connection);

        connection.status = ConnectionStatus::Established {
            sent_nonce: gen_nonce(),
            received_nonce: gen_nonce(),
            peer_session_pk: gen_keypair().0,
        };

        let connection_c = connection.clone();
        assert_eq!(connection_c, connection);
    }
}
