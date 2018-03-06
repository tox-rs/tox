/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2016-2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2018 Namsoo CHO <nscho66@gmail.com>
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

/*! Codec for encoding/decoding DHT Packets & DHT Request packets using tokio-io
*/

use toxcore::dht_new::packet::*;
use toxcore::binary_io::*;

use std::io;
use std::io::{Error, ErrorKind};
use tokio_core::net::UdpCodec;
use std::net::SocketAddr;

/// Type representing Dht UDP packets.
pub type DhtUdpPacket = (SocketAddr, DhtPacket);

/// Type representing received Dht UDP packets.
pub type DhtRecvUdpPacket = (SocketAddr, Option<DhtPacket>);

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

impl UdpCodec for DhtCodec {
    type In = DhtRecvUdpPacket;
    type Out = DhtUdpPacket;

    fn decode(&mut self, src: &SocketAddr, buf: &[u8]) -> io::Result<Self::In> {
        match DhtPacket::from_bytes(buf) {
            IResult::Incomplete(_) => {
                Err(Error::new(ErrorKind::Other,
                    "DhtPacket packet should not be incomplete"))
            },
            IResult::Error(e) => {
                Err(Error::new(ErrorKind::Other,
                    format!("deserialize DhtPacket packet error: {:?}", e)))
            },
            IResult::Done(_, encrypted_packet) => {
                Ok((*src, Some(encrypted_packet)))
            }
        }
    }

    fn encode(&mut self, (addr, dp): Self::Out, into: &mut Vec<u8>) -> SocketAddr {
        let mut buf = [0; MAX_DHT_PACKET_SIZE];
        if let Ok((_, size)) = dp.to_bytes((&mut buf, 0)) {
            into.extend(&buf[..size]);
        } else {
            // TODO: move from tokio-core to tokio and return error instead of panic
            panic!("DhtPacket to_bytes error {:?}", dp);
        }
        addr
    }
}

#[cfg(test)]
mod tests {
    use tokio_core::net::UdpCodec;
    use std::net::SocketAddr;

    use super::*;

    use quickcheck::quickcheck;

    #[test]
    fn dht_codec_decode_test() {
        fn with_packet(packet: DhtPacket) {
            // TODO: random SocketAddr
            let addr = SocketAddr::V4("0.1.2.3:4".parse().unwrap());
            let mut tc = DhtCodec;

            let mut buf = [0; MAX_DHT_PACKET_SIZE];
            let (bytes, len) = packet.to_bytes((&mut buf, 0)).unwrap();

            let (decoded_a, decoded_packet) = tc.decode(&addr, &bytes[..len])
                .unwrap();
            // it did have correct packet
            let decoded_packet = decoded_packet.unwrap();

            assert_eq!(addr, decoded_a);
            assert_eq!(packet, decoded_packet);

            // make it error
            bytes[0] = 0x03;
            assert!(tc.decode(&addr, &bytes[..len]).is_err());
        }
        quickcheck(with_packet as fn(DhtPacket));
    }

    #[test]
    fn dht_codec_encode_test() {
        fn with_packet(packet: DhtPacket) {
            // TODO: random SocketAddr
            let addr = SocketAddr::V4("5.6.7.8:9".parse().unwrap());
            let mut buf = Vec::new();
            let mut tc = DhtCodec;

            let socket = tc.encode((addr, packet.clone()), &mut buf);
            assert_eq!(addr, socket);
            let mut enc_buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, size) = packet.to_bytes((&mut enc_buf, 0)).unwrap();
            assert_eq!(buf, enc_buf[..size].to_vec());
        }
        quickcheck(with_packet as fn(DhtPacket));
    }
}
