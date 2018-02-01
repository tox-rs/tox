/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2016-2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2018 Namsoo CHO <nscho66@gmail.com>

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
use toxcore::dht_new::binary_io::*;

use std::io;
use std::io::{Error, ErrorKind};
use tokio_core::net::UdpCodec;
use std::net::SocketAddr;
//use std::io::{Error, ErrorKind};

/// Type representing Dht UDP packets.
pub type DhtUdpPacket = (SocketAddr, DhtBase);

/// Type representing received Dht UDP packets.
pub type DhtRecvUdpPacket = (SocketAddr, Option<DhtBase>);

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
pub struct DhtCodec;

impl UdpCodec for DhtCodec {
    type In = DhtRecvUdpPacket;
    type Out = DhtUdpPacket;

    fn decode(&mut self, src: &SocketAddr, buf: &[u8]) -> io::Result<Self::In>
    {
        match DhtBase::from_bytes(buf) {
            IResult::Incomplete(_) => {
                Err(Error::new(ErrorKind::Other,
                    "DhtBase packet should not be incomplete"))
            },
            IResult::Error(e) => {
                Err(Error::new(ErrorKind::Other,
                    format!("deserialize DhtBase packet error: {:?}", e)))
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
            panic!("DhtBase to_bytes error {:?}", dp);
        }
        addr
    }
}

#[cfg(test)]
mod test {
    use tokio_core::net::UdpCodec;
    use std::net::SocketAddr;

    use super::*;
    use toxcore::dht_new::packet_kind::*;

    use quickcheck::{quickcheck, TestResult};

    #[test]
    fn dht_codec_decode_test() {
        fn with_dp(dp: DhtPacket) -> TestResult {
            // need an invalid PacketKind for DhtPacket
            if dp.packet_kind as u8 <= PacketKind::SendNodes as u8 {
                return TestResult::discard()
            }

            let kind = dp.packet_kind.clone() as u8;
            // TODO: random SocketAddr
            let addr = SocketAddr::V4("0.1.2.3:4".parse().unwrap());
            let mut tc = DhtCodec;

            let mut buf = [0; 1024];
            let bytes = dp.to_bytes((&mut buf, 0)).unwrap().0;

            let (decoded_a, decoded_dp) = tc.decode(&addr, &bytes)
                .unwrap();
            // it did have correct packet
            let decoded_dp = decoded_dp.unwrap();

            assert_eq!(addr, decoded_a);
            assert_eq!(DhtBase::DhtPacket(dp), decoded_dp);

            // make it error
            bytes[0] = kind;
            let (r_addr, none) = tc.decode(&addr, &bytes).unwrap();
            assert_eq!(addr, r_addr);
            assert!(none.is_none());

            TestResult::passed()
        }
        quickcheck(with_dp as fn(DhtPacket) -> TestResult);
    }

    #[test]
    fn dht_codec_encode_test() {
        fn with_dp(dp: DhtPacket) {
            // TODO: random SocketAddr
            let addr = SocketAddr::V4("5.6.7.8:9".parse().unwrap());
            let mut buf = Vec::new();
            let mut tc = DhtCodec;

            let socket = tc.encode((addr, DhtBase::DhtPacket(dp.clone())), &mut buf);
            assert_eq!(addr, socket);
            let mut enc_buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, size) = dp.to_bytes((&mut enc_buf, 0)).unwrap();
            assert_eq!(buf, enc_buf[..size].to_vec());
        }
        quickcheck(with_dp as fn(DhtPacket));
    }
}
