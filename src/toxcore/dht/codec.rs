/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2016-2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2018 Namsoo CHO <nscho66@gmail.com>
    Copyright © 2018 Evgeny Kurnevsky <kurnevsky@gmail.com>
    Copyright © 2018 Roman Proskuryakov <humbug@deeptown.org>

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

/*! Codec for encoding/decoding DHT Packets & DHT Request packets using tokio-io
*/

use toxcore::dht::packet::*;
use toxcore::binary_io::*;

use std::io::{Error, ErrorKind};
use bytes::BytesMut;
use tokio_io::codec::{Decoder, Encoder};

/**
SendNodes
size    | description
1       | packet type
32      | public key
24      | nonce
1       | number of response nodes
[39,204]| packed nodes
8       | Request Id (Ping Id)
---------------------------------
270 bytes maximun.
Because size of SendNodes is largest in DHT related packets
512 is enough for DhtPacket
*/
pub const MAX_DHT_PACKET_SIZE: usize = 512;

/// Struct to use for {de-,}serializing DHT UDP packets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtCodec;

impl Decoder for DhtCodec {
    type Item = DhtPacket;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match DhtPacket::from_bytes(buf) {
            IResult::Incomplete(_) => {
                Err(Error::new(ErrorKind::Other,
                    "DhtPacket should not be incomplete"))
            },
            IResult::Error(e) => {
                Err(Error::new(ErrorKind::Other,
                    format!("Deserialize DhtPacket error: {:?}", e)))
            },
            IResult::Done(_, encrypted_packet) => {
                Ok(Some(encrypted_packet))
            }
        }
    }
}

impl Encoder for DhtCodec {
    type Item = DhtPacket;
    type Error = Error;

    fn encode(&mut self, packet: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let mut packet_buf = [0; MAX_DHT_PACKET_SIZE];
        packet.to_bytes((&mut packet_buf, 0))
            .map(|(packet_buf, size)| {
                buf.extend(&packet_buf[..size]);
            })
            .map_err(|e|
                Error::new(ErrorKind::Other,
                    format!("DhtPacket serialize error: {:?}", e))
            )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use toxcore::dht::codec::*;
    use toxcore::onion::packet::*;
    use toxcore::crypto_core::*;

    const ONION_RETURN_1_PAYLOAD_SIZE: usize = ONION_RETURN_1_SIZE - NONCEBYTES;
    const ONION_RETURN_2_PAYLOAD_SIZE: usize = ONION_RETURN_2_SIZE - NONCEBYTES;
    const ONION_RETURN_3_PAYLOAD_SIZE: usize = ONION_RETURN_3_SIZE - NONCEBYTES;

    #[test]
    fn encode_decode() {
        let test_packets = vec![
            DhtPacket::PingRequest(PingRequest {
                pk: gen_keypair().0,
                nonce: gen_nonce(),
                payload: vec![42; 88],
            }),
            DhtPacket::PingResponse(PingResponse {
                pk: gen_keypair().0,
                nonce: gen_nonce(),
                payload: vec![42; 88],
            }),
            DhtPacket::NodesRequest(NodesRequest {
                pk: gen_keypair().0,
                nonce: gen_nonce(),
                payload: vec![42; 88],
            }),
            DhtPacket::NodesResponse(NodesResponse {
                pk: gen_keypair().0,
                nonce: gen_nonce(),
                payload: vec![42; 188],
            }),
            DhtPacket::DhtRequest(DhtRequest {
                rpk: gen_keypair().0,
                spk: gen_keypair().0,
                nonce: gen_nonce(),
                payload: vec![42; 123],
            }),
            DhtPacket::CookieRequest(CookieRequest {
                pk: gen_keypair().0,
                nonce: gen_nonce(),
                payload: vec![42; 88],
            }),
            DhtPacket::LanDiscovery(LanDiscovery {
                pk: gen_keypair().0
            }),
            DhtPacket::OnionRequest0(OnionRequest0 {
                nonce: gen_nonce(),
                temporary_pk: gen_keypair().0,
                payload: vec![42, 123]
            }),
            DhtPacket::OnionRequest1(OnionRequest1 {
                nonce: gen_nonce(),
                temporary_pk: gen_keypair().0,
                payload: vec![42, 123],
                onion_return: OnionReturn {
                    nonce: gen_nonce(),
                    payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
                }
            }),
            DhtPacket::OnionRequest2(OnionRequest2 {
                nonce: gen_nonce(),
                temporary_pk: gen_keypair().0,
                payload: vec![42, 123],
                onion_return: OnionReturn {
                    nonce: gen_nonce(),
                    payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
                }
            }),
            DhtPacket::AnnounceRequest(AnnounceRequest {
                inner: InnerAnnounceRequest {
                    nonce: gen_nonce(),
                    pk: gen_keypair().0,
                    payload: vec![42, 123]
                },
                onion_return: OnionReturn {
                    nonce: gen_nonce(),
                    payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
                }
            }),
            DhtPacket::OnionDataRequest(OnionDataRequest {
                inner: InnerOnionDataRequest {
                    destination_pk: gen_keypair().0,
                    nonce: gen_nonce(),
                    temporary_pk: gen_keypair().0,
                    payload: vec![42, 123]
                },
                onion_return: OnionReturn {
                    nonce: gen_nonce(),
                    payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
                }
            }),
            DhtPacket::OnionDataResponse(OnionDataResponse {
                nonce: gen_nonce(),
                temporary_pk: gen_keypair().0,
                payload: vec![42, 123]
            }),
            DhtPacket::AnnounceResponse(AnnounceResponse {
                sendback_data: 12345,
                nonce: gen_nonce(),
                payload: vec![42, 123]
            }),
            DhtPacket::OnionResponse3(OnionResponse3 {
                onion_return: OnionReturn {
                    nonce: gen_nonce(),
                    payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
                },
                payload: InnerOnionResponse::AnnounceResponse(AnnounceResponse {
                    sendback_data: 12345,
                    nonce: gen_nonce(),
                    payload: vec![42, 123]
                })
            }),
            DhtPacket::OnionResponse2(OnionResponse2 {
                onion_return: OnionReturn {
                    nonce: gen_nonce(),
                    payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
                },
                payload: InnerOnionResponse::AnnounceResponse(AnnounceResponse {
                    sendback_data: 12345,
                    nonce: gen_nonce(),
                    payload: vec![42, 123]
                })
            }),
            DhtPacket::OnionResponse1(OnionResponse1 {
                onion_return: OnionReturn {
                    nonce: gen_nonce(),
                    payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
                },
                payload: InnerOnionResponse::AnnounceResponse(AnnounceResponse {
                    sendback_data: 12345,
                    nonce: gen_nonce(),
                    payload: vec![42, 123]
                })
            }),
            DhtPacket::BootstrapInfo(BootstrapInfo {
                version: 42,
                motd: vec![1, 2, 3, 4]
            }),
        ];

        let mut codec = DhtCodec;
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
        let mut codec = DhtCodec;
        let mut buf = BytesMut::new();
        let packet = DhtPacket::PingRequest(PingRequest {
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
        let mut codec = DhtCodec;
        let mut buf = BytesMut::new();

        buf.extend_from_slice(b"\xFF");
        // not enought bytes to decode EncryptedPacket
        assert!(codec.decode(&mut buf).is_err());
    }
    #[test]
    fn decode_encrypted_packet_zero_length() {
        let mut codec = DhtCodec;
        let mut buf = BytesMut::new();

        // not enought bytes to decode EncryptedPacket
        assert!(codec.decode(&mut buf).is_err());
    }
    #[test]
    fn encode_packet_too_big() {
        let mut codec = DhtCodec;
        let mut buf = BytesMut::new();
        let (pk, _) = gen_keypair();
        let nonce = gen_nonce();
        let payload = [0x01; 1024].to_vec();
        let packet = DhtPacket::PingRequest( PingRequest { pk, nonce, payload } );

        // Codec cannot serialize Packet because it is too long
        assert!(codec.encode(packet, &mut buf).is_err());
    }
    #[test]
    fn codec_is_clonable() {
        let codec = DhtCodec;
        let _codec_c = codec.clone();
    }
}
