/*! Codec for encoding/decoding DHT Packets & DHT Request packets using tokio-io
*/

use std::sync::Arc;
use parking_lot::RwLock;

use toxcore::dht::packet::*;
use toxcore::binary_io::*;
use toxcore::utils::*;

use bytes::BytesMut;
use cookie_factory::GenError;
use failure::Error;
use nom::{ErrorKind, Needed};
use tokio_codec::{Decoder, Encoder};

/// A serialized `Packet` should be not longer than 2048 bytes.
pub const MAX_DHT_PACKET_SIZE: usize = 2048;

/// Error that can happen when decoding `Packet` from bytes
#[derive(Debug, Fail)]
pub enum DecodeError {
    /// Error indicates that we received too big packet
    #[fail(display = "Packet should not be longer then 2048 bytes: {} bytes", len)]
    TooBigPacket {
        /// Length of received packet
        len: usize
    },
    /// Error indicates that more data is needed to parse received packet
    #[fail(display = "Packet should not be incomplete: {:?}, packet: {:?}", needed, packet)]
    IncompletePacket {
        /// Required data size to be parsed
        needed: Needed,
        /// Received packet
        packet: Vec<u8>,
    },
    /// Error indicates that received packet can't be parsed
    #[fail(display = "Deserialize Packet error: {:?}, packet: {:?}", error, packet)]
    DeserializeError {
        /// Parsing error
        error: ErrorKind,
        /// Received packet
        packet: Vec<u8>,
    }
}

/// Error that can happen when encoding `Packet` to bytes
#[derive(Debug, Fail)]
pub enum EncodeError {
    /// Error indicates that `Packet` is invalid and can't be serialized
    #[fail(display = "Serialize Packet error: {:?}", error)]
    SerializeError {
        /// Serialization error
        error: GenError
    }
}

/// Struct to use for {de-,}serializing DHT UDP packets.
#[derive(Clone, Debug)]
pub struct DhtCodec {
    stats: Arc<RwLock<Stats>>,
}

impl DhtCodec {
    /// Make object
    pub fn new(stats: Stats) -> Self {
        DhtCodec {
            stats: Arc::new(RwLock::new(stats))
        }
    }

    /// Get Stats object
    pub fn get_current_stats(&self) -> Stats {
        self.stats.read().clone()
    }
}

impl Decoder for DhtCodec {
    type Item = Packet;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Add 1 to incoming counter
        self.stats.write().incoming +=  1;

        let len = buf.len();
        if len > MAX_DHT_PACKET_SIZE {
            return Err(DecodeError::TooBigPacket { len }.into())
        }

        match Packet::from_bytes(buf) {
            IResult::Incomplete(needed) => Err(DecodeError::IncompletePacket { needed, packet: buf.to_vec() }.into()),
            IResult::Error(error) => Err(DecodeError::DeserializeError { error, packet: buf.to_vec() }.into()),
            IResult::Done(_, packet) => Ok(Some(packet))
        }
    }
}

impl Encoder for DhtCodec {
    type Item = Packet;
    type Error = Error;

    fn encode(&mut self, packet: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        // Add 1 to outgoing counter
        self.stats.write().outgoing +=  1;

        let mut packet_buf = [0; MAX_DHT_PACKET_SIZE];
        packet.to_bytes((&mut packet_buf, 0))
            .map(|(packet_buf, size)| {
                buf.extend(&packet_buf[..size]);
            })
            .map_err(|error|
                EncodeError::SerializeError { error }.into()
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use toxcore::onion::packet::*;
    use toxcore::crypto_core::*;

    const ONION_RETURN_1_PAYLOAD_SIZE: usize = ONION_RETURN_1_SIZE - secretbox::NONCEBYTES;
    const ONION_RETURN_2_PAYLOAD_SIZE: usize = ONION_RETURN_2_SIZE - secretbox::NONCEBYTES;
    const ONION_RETURN_3_PAYLOAD_SIZE: usize = ONION_RETURN_3_SIZE - secretbox::NONCEBYTES;

    #[test]
    fn encode_decode() {
        let test_packets = vec![
            Packet::PingRequest(PingRequest {
                pk: gen_keypair().0,
                nonce: gen_nonce(),
                payload: vec![42; 88],
            }),
            Packet::PingResponse(PingResponse {
                pk: gen_keypair().0,
                nonce: gen_nonce(),
                payload: vec![42; 88],
            }),
            Packet::NodesRequest(NodesRequest {
                pk: gen_keypair().0,
                nonce: gen_nonce(),
                payload: vec![42; 88],
            }),
            Packet::NodesResponse(NodesResponse {
                pk: gen_keypair().0,
                nonce: gen_nonce(),
                payload: vec![42; 188],
            }),
            Packet::DhtRequest(DhtRequest {
                rpk: gen_keypair().0,
                spk: gen_keypair().0,
                nonce: gen_nonce(),
                payload: vec![42; 123],
            }),
            Packet::CookieRequest(CookieRequest {
                pk: gen_keypair().0,
                nonce: gen_nonce(),
                payload: vec![42; 88],
            }),
            Packet::LanDiscovery(LanDiscovery {
                pk: gen_keypair().0
            }),
            Packet::OnionRequest0(OnionRequest0 {
                nonce: gen_nonce(),
                temporary_pk: gen_keypair().0,
                payload: vec![42; 123]
            }),
            Packet::OnionRequest1(OnionRequest1 {
                nonce: gen_nonce(),
                temporary_pk: gen_keypair().0,
                payload: vec![42; 123],
                onion_return: OnionReturn {
                    nonce: secretbox::gen_nonce(),
                    payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
                }
            }),
            Packet::OnionRequest2(OnionRequest2 {
                nonce: gen_nonce(),
                temporary_pk: gen_keypair().0,
                payload: vec![42; 123],
                onion_return: OnionReturn {
                    nonce: secretbox::gen_nonce(),
                    payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
                }
            }),
            Packet::OnionAnnounceRequest(OnionAnnounceRequest {
                inner: InnerOnionAnnounceRequest {
                    nonce: gen_nonce(),
                    pk: gen_keypair().0,
                    payload: vec![42; 123]
                },
                onion_return: OnionReturn {
                    nonce: secretbox::gen_nonce(),
                    payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
                }
            }),
            Packet::OnionDataRequest(OnionDataRequest {
                inner: InnerOnionDataRequest {
                    destination_pk: gen_keypair().0,
                    nonce: gen_nonce(),
                    temporary_pk: gen_keypair().0,
                    payload: vec![42; 123]
                },
                onion_return: OnionReturn {
                    nonce: secretbox::gen_nonce(),
                    payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
                }
            }),
            Packet::OnionDataResponse(OnionDataResponse {
                nonce: gen_nonce(),
                temporary_pk: gen_keypair().0,
                payload: vec![42; 123]
            }),
            Packet::OnionAnnounceResponse(OnionAnnounceResponse {
                sendback_data: 12345,
                nonce: gen_nonce(),
                payload: vec![42; 123]
            }),
            Packet::OnionResponse3(OnionResponse3 {
                onion_return: OnionReturn {
                    nonce: secretbox::gen_nonce(),
                    payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
                },
                payload: InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
                    sendback_data: 12345,
                    nonce: gen_nonce(),
                    payload: vec![42; 123]
                })
            }),
            Packet::OnionResponse2(OnionResponse2 {
                onion_return: OnionReturn {
                    nonce: secretbox::gen_nonce(),
                    payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
                },
                payload: InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
                    sendback_data: 12345,
                    nonce: gen_nonce(),
                    payload: vec![42; 123]
                })
            }),
            Packet::OnionResponse1(OnionResponse1 {
                onion_return: OnionReturn {
                    nonce: secretbox::gen_nonce(),
                    payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
                },
                payload: InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
                    sendback_data: 12345,
                    nonce: gen_nonce(),
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
                pk: gen_keypair().0,
                nonce: gen_nonce(),
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
        // not enought bytes to decode EncryptedPacket
        assert!(codec.decode(&mut buf).is_err());
    }
    #[test]
    fn decode_encrypted_packet_zero_length() {
        let stats = Stats::new();
        let mut codec = DhtCodec::new(stats);
        let mut buf = BytesMut::new();

        // not enought bytes to decode EncryptedPacket
        assert!(codec.decode(&mut buf).is_err());
    }
    #[test]
    fn encode_packet_too_big() {
        let stats = Stats::new();
        let mut codec = DhtCodec::new(stats);
        let mut buf = BytesMut::new();
        let (pk, _) = gen_keypair();
        let nonce = gen_nonce();
        let payload = [0x01; MAX_DHT_PACKET_SIZE + 1].to_vec();
        let packet = Packet::PingRequest( PingRequest { pk, nonce, payload } );

        // Codec cannot serialize Packet because it is too long
        assert!(codec.encode(packet, &mut buf).is_err());
    }
    #[test]
    fn codec_is_clonable() {
        let stats = Stats::new();
        let codec = DhtCodec::new(stats);
        let _codec_c = codec.clone();
    }
    #[test]
    fn get_current_stats() {
        let stats = Stats::new();
        let codec = DhtCodec::new(stats.clone());
        assert_eq!(stats, codec.get_current_stats());
    }
}
