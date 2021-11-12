/*! Codec for encoding/decoding DHT Packets & DHT Request packets using tokio-io
*/

use std::io::Error as IoError;

use tox_packet::dht::*;
use tox_binary_io::*;
use crate::stats::*;

use bytes::BytesMut;
use cookie_factory::GenError;
use thiserror::Error;
use nom::error::Error as NomError;
use tokio_util::codec::{Decoder, Encoder};

/// A serialized `Packet` should be not longer than 2048 bytes.
pub const MAX_DHT_PACKET_SIZE: usize = 2048;

/// Error that can happen when decoding `Packet` from bytes.
#[derive(Debug, Error)]
pub enum DecodeError {
    /// Error indicates that we received too big packet.
    #[error("Packet should not be longer than 2048 bytes: {} bytes", len)]
    TooBigPacket {
        /// Length of received packet.
        len: usize
    },
    /// Error indicates that received packet can't be parsed.
    #[error("Deserialize Packet error: {:?}, packet: {:?}", error, packet)]
    Deserialize {
        /// Parsing error.
        error: nom::Err<NomError<Vec<u8>>>,
        /// Received packet.
        packet: Vec<u8>,
    },
    /// General IO error that can happen with UDP socket.
    #[error("IO Error")]
    Io(IoError),
}

impl DecodeError {
    pub(crate) fn too_big_packet(len: usize) -> DecodeError {
        DecodeError::TooBigPacket { len }
    }

    pub(crate) fn deserialize(e: nom::Err<NomError<&[u8]>>, packet: Vec<u8>) -> DecodeError {
        DecodeError::Deserialize { error: e.map(|e| NomError::new(e.input.to_vec(), e.code)), packet }
    }
}

/// Error that can happen when encoding `Packet` to bytes.
#[derive(Debug, Error)]
pub enum EncodeError {
    /// Error indicates that `Packet` is invalid and can't be serialized.
    #[error("Serialize Packet error: {:?}", error)]
    Serialize {
        /// Serialization error.
        error: GenError
    },
    /// General IO error that can happen with UDP socket.
    #[error("IO Error")]
    Io(IoError),
}

impl EncodeError {
    pub(crate) fn serialize(error: GenError) -> EncodeError {
        EncodeError::Serialize { error }
    }
}

impl From<IoError> for DecodeError {
    fn from(error: IoError) -> DecodeError {
        DecodeError::Io(error)
    }
}

impl From<IoError> for EncodeError {
    fn from(error: IoError) -> EncodeError {
        EncodeError::Io(error)
    }
}

/// Struct to use for {de-,}serializing DHT UDP packets.
#[derive(Clone)]
pub struct DhtCodec {
    stats: Stats,
}

impl DhtCodec {
    /// Make object
    pub fn new(stats: Stats) -> Self {
        DhtCodec {
            stats
        }
    }
}

impl Decoder for DhtCodec {
    type Item = Packet;
    type Error = DecodeError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        let len = buf.len();
        if len > MAX_DHT_PACKET_SIZE {
            return Err(DecodeError::too_big_packet(len))
        }

        let result = match Packet::from_bytes(buf) {
            Err(error) => {
                Err(DecodeError::deserialize(error, buf.to_vec()))
            },
            Ok((_, packet)) => {
                // Add 1 to incoming counter
                self.stats.counters.increase_incoming();

                Ok(Some(packet))
            }
        };

        buf.clear();

        result
    }
}

impl Encoder<Packet> for DhtCodec {
    type Error = EncodeError;

    fn encode(&mut self, packet: Packet, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let mut packet_buf = [0; MAX_DHT_PACKET_SIZE];
        packet.to_bytes((&mut packet_buf, 0))
            .map(|(packet_buf, size)| {
                // Add 1 to outgoing counter
                self.stats.counters.increase_outgoing();

                buf.extend(&packet_buf[..size]);
            })
            .map_err(|error|
                EncodeError::serialize(error)
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use tox_packet::onion::*;
    use crypto_box::{SalsaBox, SecretKey, aead::{AeadCore, generic_array::typenum::marker_traits::Unsigned}};
    use nom::{Err, error::ErrorKind as NomErrorKind};

    const ONION_RETURN_1_PAYLOAD_SIZE: usize = ONION_RETURN_1_SIZE - xsalsa20poly1305::NONCE_SIZE;
    const ONION_RETURN_2_PAYLOAD_SIZE: usize = ONION_RETURN_2_SIZE - xsalsa20poly1305::NONCE_SIZE;
    const ONION_RETURN_3_PAYLOAD_SIZE: usize = ONION_RETURN_3_SIZE - xsalsa20poly1305::NONCE_SIZE;

    #[test]
    fn encode_decode() {
        let test_packets = vec![
            Packet::PingRequest(PingRequest {
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                payload: vec![42; 88],
            }),
            Packet::PingResponse(PingResponse {
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                payload: vec![42; 88],
            }),
            Packet::NodesRequest(NodesRequest {
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                payload: vec![42; 88],
            }),
            Packet::NodesResponse(NodesResponse {
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                payload: vec![42; 188],
            }),
            Packet::DhtRequest(DhtRequest {
                rpk: SecretKey::generate(&mut thread_rng()).public_key(),
                spk: SecretKey::generate(&mut thread_rng()).public_key(),
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                payload: vec![42; 123],
            }),
            Packet::CookieRequest(CookieRequest {
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                payload: vec![42; 88],
            }),
            Packet::LanDiscovery(LanDiscovery {
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
            }),
            Packet::OnionRequest0(OnionRequest0 {
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                temporary_pk: SecretKey::generate(&mut thread_rng()).public_key(),
                payload: vec![42; 123]
            }),
            Packet::OnionRequest1(OnionRequest1 {
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                temporary_pk: SecretKey::generate(&mut thread_rng()).public_key(),
                payload: vec![42; 123],
                onion_return: OnionReturn {
                    nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                    payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
                }
            }),
            Packet::OnionRequest2(OnionRequest2 {
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                temporary_pk: SecretKey::generate(&mut thread_rng()).public_key(),
                payload: vec![42; 123],
                onion_return: OnionReturn {
                    nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                    payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
                }
            }),
            Packet::OnionAnnounceRequest(OnionAnnounceRequest {
                inner: InnerOnionAnnounceRequest {
                    nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                    pk: SecretKey::generate(&mut thread_rng()).public_key(),
                    payload: vec![42; 123]
                },
                onion_return: OnionReturn {
                    nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                    payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
                }
            }),
            Packet::OnionDataRequest(OnionDataRequest {
                inner: InnerOnionDataRequest {
                    destination_pk: SecretKey::generate(&mut thread_rng()).public_key(),
                    nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                    temporary_pk: SecretKey::generate(&mut thread_rng()).public_key(),
                    payload: vec![42; 123]
                },
                onion_return: OnionReturn {
                    nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                    payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
                }
            }),
            Packet::OnionDataResponse(OnionDataResponse {
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                temporary_pk: SecretKey::generate(&mut thread_rng()).public_key(),
                payload: vec![42; 123]
            }),
            Packet::OnionAnnounceResponse(OnionAnnounceResponse {
                sendback_data: 12345,
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                payload: vec![42; 123]
            }),
            Packet::OnionResponse3(OnionResponse3 {
                onion_return: OnionReturn {
                    nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                    payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
                },
                payload: InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
                    sendback_data: 12345,
                    nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                    payload: vec![42; 123]
                })
            }),
            Packet::OnionResponse2(OnionResponse2 {
                onion_return: OnionReturn {
                    nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                    payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
                },
                payload: InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
                    sendback_data: 12345,
                    nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                    payload: vec![42; 123]
                })
            }),
            Packet::OnionResponse1(OnionResponse1 {
                onion_return: OnionReturn {
                    nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                    payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
                },
                payload: InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
                    sendback_data: 12345,
                    nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                    payload: vec![42; 123]
                })
            }),
            Packet::BootstrapInfo(BootstrapInfo {
                version: 42,
                motd: vec![1, 2, 3, 4]
            }),
        ];

        let stats = Stats::new();
        let mut codec = DhtCodec::new(stats);
        let mut buf = BytesMut::new();
        for packet in test_packets {
            buf.clear();
            codec.encode(packet.clone(), &mut buf).expect("Codec should encode");
            let res = codec.decode(&mut buf).unwrap().expect("Codec should decode");
            assert_eq!(packet, res);
        }
    }

    #[test]
    fn decode_encrypted_packet_incomplete() {
        let stats = Stats::new();
        let mut codec = DhtCodec::new(stats);
        let mut buf = BytesMut::new();
        let packet = Packet::PingRequest(PingRequest {
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                payload: vec![42; 88],
            });
        let mut packet_buf = [0;256];
        let (_, size) = packet.to_bytes((&mut packet_buf, 0)).unwrap();
        buf.extend_from_slice(&packet_buf[..(size-90)]);

        // not enought bytes to decode EncryptedPacket
        assert!(codec.decode(&mut buf).is_err());
    }

    #[test]
    fn decode_encrypted_packet_error() {
        let stats = Stats::new();
        let mut codec = DhtCodec::new(stats);
        let mut buf = BytesMut::new();

        buf.extend_from_slice(b"\xFF");

        let res = codec.decode(&mut buf);
        // not enough bytes to decode EncryptedPacket
        assert!(matches!(res, Err(DecodeError::Deserialize { error: Err::Error(NomError { input: _, code: NomErrorKind::Tag }), packet: _ })));
    }

    #[test]
    fn decode_encrypted_packet_zero_length() {
        let stats = Stats::new();
        let mut codec = DhtCodec::new(stats);
        let mut buf = BytesMut::new();

        // we can't distinguish 0-length UDP packets from completely consumed packets
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn encode_packet_too_big() {
        let stats = Stats::new();
        let mut codec = DhtCodec::new(stats);
        let mut buf = BytesMut::new();
        let pk = SecretKey::generate(&mut thread_rng()).public_key();
        let payload = [0x01; MAX_DHT_PACKET_SIZE + 1].to_vec();
        let packet = Packet::PingRequest(PingRequest {
            pk,
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload,
        });

        // Codec cannot serialize Packet because it is too long
        let res = codec.encode(packet, &mut buf);
        assert!(res.is_err());
        let error = res.err().unwrap();
        let error_serialize = unpack!(error, EncodeError::Serialize, error);
        let too_small = unpack!(error_serialize, GenError::BufferTooSmall);
        assert_eq!(too_small, 2106 - MAX_DHT_PACKET_SIZE);
    }
}
