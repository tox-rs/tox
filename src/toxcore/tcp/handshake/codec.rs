/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2017 Roman Proskuryakov <humbug@deeptown.org>

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

/*! Codecs to deal with ClientHandshake and ServerHandshake in terms of tokio-io

*/

use toxcore::binary_io_new::*;
use toxcore::tcp::handshake::packet::*;

use nom::Offset;
use bytes::BytesMut;
use std::io::{Error, ErrorKind};
use tokio_io::codec::{Decoder, Encoder};

/// implements tokio-io's Decoder and Encoder to deal with Client handshake
pub struct ClientHandshakeCodec;

impl Decoder for ClientHandshakeCodec {
    type Item = ClientHandshake;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let (consumed, handshake) = match ClientHandshake::from_bytes(buf) {
            IResult::Incomplete(_) => {
                return Ok(None)
            },
            IResult::Error(_) => unreachable!("ClientHandshake cannot be deserialized with error"),
            IResult::Done(i, handshake) => {
                (buf.offset(i), handshake)
            }
        };
        buf.split_to(consumed);
        Ok(Some(handshake))
    }
}

impl Encoder for ClientHandshakeCodec {
    type Item = ClientHandshake;
    type Error = Error;

    fn encode(&mut self, handshake: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let mut handshake_buf = [0; CLIENT_HANDSHAKE_SIZE];
        handshake.to_bytes((&mut handshake_buf, 0))
            .map(|(handshake_buf, handshake_size)| {
                buf.extend_from_slice(&handshake_buf[..handshake_size]);
                ()
            })
            .map_err(|e|
                Error::new(ErrorKind::Other,
                           format!("Client handshake serialize error: {:?}", e))
            )
    }
}

/// implements tokio-io's Decoder and Encoder to deal with Client handshake
pub struct ServerHandshakeCodec;

impl Decoder for ServerHandshakeCodec {
    type Item = ServerHandshake;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let (consumed, handshake) = match ServerHandshake::from_bytes(buf) {
            IResult::Incomplete(_) => {
                return Ok(None)
            },
            IResult::Error(_) => unreachable!("ServerHandshake cannot be deserialized with error"),
            IResult::Done(i, handshake) => {
                (buf.offset(i), handshake)
            }
        };
        buf.split_to(consumed);
        Ok(Some(handshake))
    }
}

impl Encoder for ServerHandshakeCodec {
    type Item = ServerHandshake;
    type Error = Error;

    fn encode(&mut self, handshake: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let mut handshake_buf = [0; SERVER_HANDSHAKE_SIZE];
        handshake.to_bytes((&mut handshake_buf, 0))
            .map(|(handshake_buf, handshake_size)| {
                buf.extend_from_slice(&handshake_buf[..handshake_size]);
                ()
            })
            .map_err(|e|
                Error::new(ErrorKind::Other,
                           format!("Server handshake serialize error: {:?}", e))
            )
    }
}
