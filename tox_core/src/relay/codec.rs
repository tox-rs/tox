/*! Codec implementation for encoding/decoding TCP Packets in terms of tokio-io
*/

use std::io::Error as IoError;

use crate::relay::secure::*;
use crate::stats::*;
use tox_binary_io::*;
use tox_packet::relay::*;

use bytes::{Buf, BytesMut};
use nom::{error::ErrorKind, Err, Needed, Offset};
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

/// Error that can happen when decoding `Packet` from bytes
#[derive(Debug, Error)]
pub enum DecodeError {
    /// Error indicates that received encrypted packet can't be parsed
    #[error("Deserialize EncryptedPacket error: {:?}, buffer: {:?}", error, buf)]
    DeserializeEncryptedError {
        /// Parsing error
        error: ErrorKind,
        /// TCP buffer
        buf: Vec<u8>,
    },
    /// Error indicates that received encrypted packet can't be decrypted
    #[error("Decrypt EncryptedPacket error")]
    DecryptError,
    /// Error indicates that more data is needed to parse decrypted packet
    #[error("Decrypted packet should not be incomplete: {:?}, packet: {:?}", needed, packet)]
    IncompleteDecryptedPacket {
        /// Required data size to be parsed
        needed: Needed,
        /// Received packet
        packet: Vec<u8>,
    },
    /// Error indicates that decrypted packet can't be parsed
    #[error("Deserialize decrypted packet error: {:?}, packet: {:?}", error, packet)]
    DeserializeDecryptedError {
        /// Parsing error
        error: ErrorKind,
        /// Received packet
        packet: Vec<u8>,
    },
    /// General IO error
    #[error("IO error: {:?}", error)]
    IoError {
        /// IO error
        error: IoError,
    },
}

impl From<IoError> for DecodeError {
    fn from(error: IoError) -> DecodeError {
        DecodeError::IoError { error }
    }
}

/// Error that can happen when encoding `Packet` to bytes
#[derive(Debug, Error)]
pub enum EncodeError {
    /// Error indicates that `Packet` is invalid and can't be serialized
    #[error("Serialize Packet error: {:?}", error)]
    SerializeError {
        /// Serialization error
        error: GenError,
    },
    /// General IO error
    #[error("IO error: {:?}", error)]
    IoError {
        /// IO error
        error: IoError,
    },
}

impl From<IoError> for EncodeError {
    fn from(error: IoError) -> EncodeError {
        EncodeError::IoError { error }
    }
}

/// implements tokio-io's Decoder and Encoder to deal with Packet
pub struct Codec {
    channel: Channel,
    stats: Stats,
}

impl Codec {
    /// create a new Codec with the given Channel
    pub fn new(channel: Channel, stats: Stats) -> Codec {
        Codec { channel, stats }
    }
}

impl Decoder for Codec {
    type Item = Packet;
    type Error = DecodeError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // deserialize EncryptedPacket
        let (consumed, encrypted_packet) = match EncryptedPacket::from_bytes(buf) {
            Err(Err::Incomplete(_)) => return Ok(None),
            Err(Err::Error(error)) => {
                return Err(DecodeError::DeserializeEncryptedError {
                    error: error.code,
                    buf: buf.to_vec(),
                })
            }
            Err(Err::Failure(error)) => {
                return Err(DecodeError::DeserializeEncryptedError {
                    error: error.code,
                    buf: buf.to_vec(),
                })
            }
            Ok((i, encrypted_packet)) => (buf.offset(i), encrypted_packet),
        };

        // decrypt payload
        let decrypted_data = self
            .channel
            .decrypt(&encrypted_packet.payload)
            .map_err(|()| DecodeError::DecryptError)?;

        // deserialize Packet
        match Packet::from_bytes(&decrypted_data) {
            Err(Err::Incomplete(needed)) => Err(DecodeError::IncompleteDecryptedPacket {
                needed,
                packet: decrypted_data,
            }),
            Err(Err::Error(error)) => Err(DecodeError::DeserializeDecryptedError {
                error: error.code,
                packet: decrypted_data,
            }),
            Err(Err::Failure(error)) => Err(DecodeError::DeserializeDecryptedError {
                error: error.code,
                packet: decrypted_data,
            }),
            Ok((_i, packet)) => {
                // Add 1 to incoming counter
                self.stats.counters.increase_incoming();

                buf.advance(consumed);
                Ok(Some(packet))
            }
        }
    }
}

impl Encoder<Packet> for Codec {
    type Error = EncodeError;

    fn encode(&mut self, packet: Packet, buf: &mut BytesMut) -> Result<(), Self::Error> {
        // Add 1 to outgoing counter
        self.stats.counters.increase_outgoing();

        // serialize Packet
        let mut packet_buf = [0; MAX_TCP_PACKET_SIZE];
        let (_, packet_size) = packet
            .to_bytes((&mut packet_buf, 0))
            .map_err(|error| EncodeError::SerializeError { error })?;

        // encrypt it
        let encrypted = self.channel.encrypt(&packet_buf[..packet_size]);

        // create EncryptedPacket
        let encrypted_packet = EncryptedPacket { payload: encrypted };

        // serialize EncryptedPacket to binary form
        let mut encrypted_packet_buf = [0; MAX_TCP_ENC_PACKET_SIZE];
        let (_, encrypted_packet_size) = encrypted_packet
            .to_bytes((&mut encrypted_packet_buf, 0))
            .expect("EncryptedPacket serialize failed"); // there is nothing to fail since
                                                         // serialized Packet is not longer than 2032 bytes
                                                         // and we provided 2050 bytes for EncryptedPacket
        buf.extend_from_slice(&encrypted_packet_buf[..encrypted_packet_size]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::relay::codec::*;
    use crypto_box::{
        aead::{generic_array::typenum::marker_traits::Unsigned, Aead, AeadCore},
        SalsaBox, SecretKey,
    };
    use rand::thread_rng;
    use tox_packet::dht::CryptoData;
    use tox_packet::ip_port::*;
    use tox_packet::onion::*;
    use tox_packet::relay::connection_id::ConnectionId;

    use std::io::ErrorKind as IoErrorKind;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn decode_error_from_io() {
        let error = IoError::new(IoErrorKind::Other, "io error");
        let decode_error = DecodeError::from(error);
        assert_eq!(
            unpack!(decode_error, DecodeError::IoError, error).kind(),
            IoErrorKind::Other
        );
    }

    #[test]
    fn encode_error_from_io() {
        let error = IoError::new(IoErrorKind::Other, "io error");
        let encode_error = EncodeError::from(error);
        assert_eq!(
            unpack!(encode_error, EncodeError::IoError, error).kind(),
            IoErrorKind::Other
        );
    }

    fn create_channels() -> (Channel, Channel) {
        let alice_session = Session::random();
        let bob_session = Session::random();

        // assume we got Alice's PK & Nonce via handshake
        let alice_pk = alice_session.pk().clone();
        let alice_nonce = *alice_session.nonce();

        // assume we got Bob's PK & Nonce via handshake
        let bob_pk = bob_session.pk().clone();
        let bob_nonce = *bob_session.nonce();

        // Now both Alice and Bob may create secure Channels
        let alice_channel = Channel::new(&alice_session, &bob_pk, &bob_nonce);
        let bob_channel = Channel::new(&bob_session, &alice_pk, &alice_nonce);

        (alice_channel, bob_channel)
    }

    #[test]
    fn encode_decode() {
        let mut rng = thread_rng();
        let pk = SecretKey::generate(&mut rng).public_key();
        let (alice_channel, bob_channel) = create_channels();
        let mut buf = BytesMut::new();
        let stats = Stats::new();
        let mut alice_codec = Codec::new(alice_channel, stats.clone());
        let mut bob_codec = Codec::new(bob_channel, stats);

        let test_packets = vec![
            Packet::RouteRequest(RouteRequest { pk: pk.clone() }),
            Packet::RouteResponse(RouteResponse {
                connection_id: ConnectionId::from_index(42),
                pk: pk.clone(),
            }),
            Packet::ConnectNotification(ConnectNotification {
                connection_id: ConnectionId::from_index(42),
            }),
            Packet::DisconnectNotification(DisconnectNotification {
                connection_id: ConnectionId::from_index(42),
            }),
            Packet::PingRequest(PingRequest { ping_id: 4242 }),
            Packet::PongResponse(PongResponse { ping_id: 4242 }),
            Packet::OobSend(OobSend {
                destination_pk: pk.clone(),
                data: vec![13; 42],
            }),
            Packet::OobReceive(OobReceive {
                sender_pk: pk,
                data: vec![13; 24],
            }),
            Packet::OnionRequest(OnionRequest {
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                ip_port: IpPort {
                    protocol: ProtocolType::Tcp,
                    ip_addr: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
                    port: 12345,
                },
                temporary_pk: SecretKey::generate(&mut rng).public_key(),
                payload: vec![13; 207],
            }),
            Packet::OnionRequest(OnionRequest {
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                ip_port: IpPort {
                    protocol: ProtocolType::Tcp,
                    ip_addr: IpAddr::V6(Ipv6Addr::new(5, 6, 7, 8, 5, 6, 7, 8)),
                    port: 54321,
                },
                temporary_pk: SecretKey::generate(&mut rng).public_key(),
                payload: vec![13; 201],
            }),
            Packet::OnionResponse(OnionResponse {
                payload: InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
                    sendback_data: 12345,
                    nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                    payload: vec![42; 123],
                }),
            }),
            Packet::OnionResponse(OnionResponse {
                payload: InnerOnionResponse::OnionDataResponse(OnionDataResponse {
                    nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                    temporary_pk: SecretKey::generate(&mut rng).public_key(),
                    payload: vec![42; 123],
                }),
            }),
            Packet::Data(Data {
                connection_id: ConnectionId::from_index(42),
                data: DataPayload::CryptoData(CryptoData {
                    nonce_last_bytes: 42,
                    payload: vec![42; 123],
                }),
            }),
        ];
        for packet in test_packets {
            alice_codec
                .encode(packet.clone(), &mut buf)
                .expect("Alice should encode");
            let res = bob_codec.decode(&mut buf).unwrap().expect("Bob should decode");
            assert_eq!(packet, res);

            bob_codec.encode(packet.clone(), &mut buf).expect("Bob should encode");
            let res = alice_codec.decode(&mut buf).unwrap().expect("Alice should decode");
            assert_eq!(packet, res);
        }
    }
    #[test]
    fn decode_encrypted_packet_incomplete() {
        let (alice_channel, _) = create_channels();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(b"\x00");
        let stats = Stats::new();
        let mut alice_codec = Codec::new(alice_channel, stats);

        // not enought bytes to decode EncryptedPacket
        assert_eq!(alice_codec.decode(&mut buf).unwrap(), None);
    }
    #[test]
    fn decode_encrypted_packet_zero_length() {
        let (alice_channel, _) = create_channels();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(b"\x00\x00");
        let stats = Stats::new();
        let mut alice_codec = Codec::new(alice_channel, stats);

        // 0-length payload is invalid
        assert!(alice_codec.decode(&mut buf).is_err());
    }
    #[test]
    fn decode_encrypted_packet_wrong_key() {
        let (alice_channel, _) = create_channels();
        let (mallory_channel, _) = create_channels();

        let stats = Stats::new();
        let mut alice_codec = Codec::new(alice_channel, stats.clone());
        let mut mallory_codec = Codec::new(mallory_channel, stats);

        let mut buf = BytesMut::new();
        let packet = Packet::PingRequest(PingRequest { ping_id: 4242 });

        alice_codec.encode(packet, &mut buf).expect("Alice should encode");
        // Mallory cannot decode the payload of EncryptedPacket
        assert!(mallory_codec.decode(&mut buf).err().is_some());
    }
    #[test]
    fn decode_packet_imcomplete() {
        let (alice_channel, _) = create_channels();

        let mut buf = BytesMut::new();
        let stats = Stats::new();
        let mut bob_codec = Codec::new(alice_channel, stats);

        // not enough bytes to decode Packet
        assert!(bob_codec.decode(&mut buf).unwrap().is_none());
    }
    #[test]
    fn decode_packet_error() {
        let mut rng = thread_rng();
        let alice_session = Session::random();

        // assume we got Alice's PK via handshake
        let alice_pk = alice_session.pk().clone();

        // assume we got Bob's PK & Nonce via handshake
        let bob_sk = SecretKey::generate(&mut rng);
        let bob_pk = bob_sk.public_key();
        let bob_nonce = SalsaBox::generate_nonce(&mut rng);

        // Now both Alice and Bob may create secure Channels
        let alice_channel = Channel::new(&alice_session, &bob_pk, &bob_nonce.into());

        let stats = Stats::new();
        let mut alice_codec = Codec::new(alice_channel, stats);

        // packet with invalid id
        let precomputed_key = SalsaBox::new(&alice_pk, &bob_sk);
        let payload = precomputed_key.encrypt(&bob_nonce, &[0x0F][..]).unwrap();
        let packet = EncryptedPacket { payload };
        let mut packet_bytes = [0; 32];
        let (_, size) = packet.to_bytes((&mut packet_bytes, 0)).unwrap();

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&packet_bytes[..size]);

        assert!(alice_codec.decode(&mut buf).is_err());
    }

    #[test]
    fn encode_packet_too_big() {
        let (alice_channel, _) = create_channels();
        let mut buf = BytesMut::new();
        let stats = Stats::new();
        let mut alice_codec = Codec::new(alice_channel, stats);
        let packet = Packet::Data(Data {
            connection_id: ConnectionId::from_index(42),
            data: DataPayload::CryptoData(CryptoData {
                nonce_last_bytes: 42,
                payload: vec![42; 2030],
            }),
        });

        // Alice cannot serialize Packet because it is too long
        assert!(alice_codec.encode(packet, &mut buf).is_err());
    }
}
