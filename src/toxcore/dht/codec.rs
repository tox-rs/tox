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
    use quickcheck::quickcheck;

    #[test]
    fn encode_decode() {
        fn with_packet(packet: DhtPacket) {
            let mut codec = DhtCodec;
            let mut buf = BytesMut::new();

            codec.encode(packet.clone(), &mut buf).expect("Codec should encode");
            let res = codec.decode(&mut buf).unwrap().expect("Codec should decode");
            assert_eq!(packet, res);
        }
        quickcheck(with_packet as fn(DhtPacket));
    }
}
