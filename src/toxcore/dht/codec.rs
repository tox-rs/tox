/*! Codec for encoding/decoding DHT Packets & DHT Request packets using tokio-io
*/

use std::io::Error as IoError;

use crate::toxcore::dht::packet::*;
use crate::toxcore::binary_io::*;
use crate::toxcore::stats::*;

use bytes::BytesMut;
use cookie_factory::GenError;
use failure::Fail;
use nom::{error::ErrorKind, Err};
use tokio_util::codec::{Decoder, Encoder};

/// A serialized `Packet` should be not longer than 2048 bytes.
pub const MAX_DHT_PACKET_SIZE: usize = 2048;

error_kind! {
    #[doc = "Error that can happen when decoding `Packet` from bytes."]
    #[derive(Debug)]
    DecodeError,
    #[doc = "Error that can happen when decoding `Packet` from bytes."]
    #[derive(Clone, Debug, Eq, PartialEq, Fail)]
    DecodeErrorKind {
        #[doc = "Error indicates that we received too big packet."]
        #[fail(display = "Packet should not be longer than 2048 bytes: {} bytes", len)]
        TooBigPacket {
            #[doc = "Length of received packet."]
            len: usize
        },
        #[doc = "Error indicates that received packet can't be parsed."]
        #[fail(display = "Deserialize Packet error: {:?}, packet: {:?}", error, packet)]
        Deserialize {
            #[doc = "Parsing error."]
            error: nom::Err<(Vec<u8>, ErrorKind)>,
            #[doc = "Received packet."]
            packet: Vec<u8>,
        },
        #[doc = "General IO error that can happen with UDP socket."]
        #[fail(display = "IO Error")]
        Io,
    }
}

impl DecodeError {
    pub(crate) fn too_big_packet(len: usize) -> DecodeError {
        DecodeError::from(DecodeErrorKind::TooBigPacket { len })
    }

    pub(crate) fn deserialize(e: Err<(&[u8], ErrorKind)>, packet: Vec<u8>) -> DecodeError {
        DecodeError::from(DecodeErrorKind::Deserialize { error: e.to_owned(), packet })
    }
}

error_kind! {
    #[doc = "Error that can happen when encoding `Packet` to bytes."]
    #[derive(Debug)]
    EncodeError,
    #[doc = "Error that can happen when encoding `Packet` to bytes."]
    #[derive(Debug, Fail)]
    EncodeErrorKind {
        #[doc = "Error indicates that `Packet` is invalid and can't be serialized."]
        #[fail(display = "Serialize Packet error: {:?}", error)]
        Serialize {
            #[doc = "Serialization error."]
            error: GenError
        },
        #[doc = "General IO error that can happen with UDP socket."]
        #[fail(display = "IO Error")]
        Io,
    }
}

impl EncodeError {
    pub(crate) fn serialize(error: GenError) -> EncodeError {
        EncodeError::from(EncodeErrorKind::Serialize { error })
    }
}

impl From<IoError> for DecodeError {
    fn from(error: IoError) -> DecodeError {
        DecodeError {
            ctx: error.context(DecodeErrorKind::Io)
        }
    }
}

impl From<IoError> for EncodeError {
    fn from(error: IoError) -> EncodeError {
        EncodeError {
            ctx: error.context(EncodeErrorKind::Io)
        }
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
        let len = buf.len();
        if len > MAX_DHT_PACKET_SIZE {
            return Err(DecodeError::too_big_packet(len))
        }

        match Packet::from_bytes(buf) {
            Err(error) => {
                Err(DecodeError::deserialize(error, buf.to_vec()))
            },
            Ok((_, packet)) => {
                // Add 1 to incoming counter
                self.stats.counters.increase_incoming();

                Ok(Some(packet))
            }
        }
    }
}

impl Encoder for DhtCodec {
    type Item = Packet;
    type Error = EncodeError;

    fn encode(&mut self, packet: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
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
    use nom::Needed;
    use crate::toxcore::onion::packet::*;
    use crate::toxcore::crypto_core::*;

    const ONION_RETURN_1_PAYLOAD_SIZE: usize = ONION_RETURN_1_SIZE - secretbox::NONCEBYTES;
    const ONION_RETURN_2_PAYLOAD_SIZE: usize = ONION_RETURN_2_SIZE - secretbox::NONCEBYTES;
    const ONION_RETURN_3_PAYLOAD_SIZE: usize = ONION_RETURN_3_SIZE - secretbox::NONCEBYTES;

    #[test]
    fn encode_decode() {
        crypto_init().unwrap();
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
        crypto_init().unwrap();
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
        crypto_init().unwrap();
        let stats = Stats::new();
        let mut codec = DhtCodec::new(stats);
        let mut buf = BytesMut::new();

        buf.extend_from_slice(b"\xFF");

        let res = codec.decode(&mut buf);
        // not enought bytes to decode EncryptedPacket
        let error = res.err().unwrap();
        assert_eq!(*error.kind(), DecodeErrorKind::Deserialize { error: Err::Error((vec![255], ErrorKind::Alt)) , packet: vec![0xff] });
    }

    #[test]
    fn decode_encrypted_packet_zero_length() {
        crypto_init().unwrap();
        let stats = Stats::new();
        let mut codec = DhtCodec::new(stats);
        let mut buf = BytesMut::new();

        // not enought bytes to decode EncryptedPacket
        let res = codec.decode(&mut buf);
        let error = res.err().unwrap();
        assert_eq!(*error.kind(), DecodeErrorKind::Deserialize { error: Err::Incomplete(Needed::Size(1)), packet: Vec::new() });
    }

    #[test]
    fn encode_packet_too_big() {
        crypto_init().unwrap();
        let stats = Stats::new();
        let mut codec = DhtCodec::new(stats);
        let mut buf = BytesMut::new();
        let (pk, _) = gen_keypair();
        let nonce = gen_nonce();
        let payload = [0x01; MAX_DHT_PACKET_SIZE + 1].to_vec();
        let packet = Packet::PingRequest( PingRequest { pk, nonce, payload } );

        // Codec cannot serialize Packet because it is too long
        let res = codec.encode(packet, &mut buf);
        assert!(res.is_err());
        let error = res.err().unwrap();
        let error_kind = error.kind();
        let error_serialize = unpack!(error_kind, EncodeErrorKind::Serialize, error);
        let too_small = unpack!(error_serialize, GenError::BufferTooSmall);
        assert_eq!(*too_small, 2106 - MAX_DHT_PACKET_SIZE);
    }
}
