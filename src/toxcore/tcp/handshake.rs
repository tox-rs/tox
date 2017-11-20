/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2017 Zetok Zalbavar <zexavexxe@gmail.com>
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

/*! Handshake packets to establish a confirmed connection via
handshake using [`Diagram`](https://zetok.github.io/tox-spec/#handshake-diagram)

*/

use toxcore::crypto_core::*;
use toxcore::tcp::binary_io::*;
use bytes::BytesMut;
use nom::*;
use cookie_factory::*;
use std::io::{Error, ErrorKind};
use tokio_io::codec::{Decoder, Encoder};

/** The request of the client to create a TCP handshake.

According to https://zetok.github.io/tox-spec/#handshake-request.

Serialized form:

Length  | Contents
------- | --------
`32`    | PK of the client
`24`    | Nonce of the encrypted payload
`72`    | Encrypted payload (plus MAC)

*/

#[derive(PartialEq, Debug, Clone)]
pub struct Client {
    /// Client's Public Key
    pub pk: PublicKey,
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Encrypted payload according to
    /// https://zetok.github.io/tox-spec/#handshake-request-packet-payload
    pub payload: Vec<u8>
}

/// A serialized client handshake must be equal to 32 (PK) + 24 (nonce)
/// + 72 (encrypted payload) bytes
pub const CLIENT_HANDSHAKE_SIZE: usize = 128;

impl FromBytes for Client {
    named!(from_bytes<Client>, do_parse!(
        pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        payload: take!(ENC_PAYLOAD_SIZE) >>
        (Client { pk: pk, nonce: nonce, payload: payload.to_vec() })
    ));
}

impl ToBytes for Client {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

/** The response of the server to a TCP handshake.

According to https://zetok.github.io/tox-spec/#handshake-response.

Serialized form:

Length  | Contents
------- | --------
`24`    | Nonce for the encrypted payload
`72`    | Encrypted payload (plus MAC)

*/

#[derive(PartialEq, Debug, Clone)]
pub struct Server {
    /// Nonce of the encrypted payload
    pub nonce: Nonce,
    /// Encrypted payload according to
    /// https://zetok.github.io/tox-spec/#handshake-response-payload.
    pub payload: Vec<u8>
}

/// A serialized server handshake must be equal to 24 (nonce)
/// + 72 (encrypted payload) bytes
pub const SERVER_HANDSHAKE_SIZE: usize = 96;

impl FromBytes for Server {
    named!(from_bytes<Server>, do_parse!(
        nonce: call!(Nonce::from_bytes) >>
        payload: take!(ENC_PAYLOAD_SIZE) >>
        (Server { nonce: nonce, payload: payload.to_vec() })
    ));
}

impl ToBytes for Server {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

/** The payload of a TCP handshake. The payload is encrypted with algo:

precomputed_key = precomputed(self_pk, other_sk)
encrypted_payload = encrypt_data_symmetric(precomputed_key, nonce, payload)

According to https://zetok.github.io/tox-spec/#handshake-request-packet-payload
or https://zetok.github.io/tox-spec/#handshake-response-payload

Serialized and decrypted form:

Length  | Contents
------- | --------
`32`    | PublicKey for the current session
`24`    | Nonce of the current session

*/

pub struct Payload {
    /// Temporary Session PK
    pub session_pk: PublicKey,
    /// Temporary Session Nonce
    pub session_nonce: Nonce
}

/// A serialized payload must be equal to 32 (PK) + 24 (nonce) bytes
pub const PAYLOAD_SIZE: usize = 56;

/// A serialized encrypted payload must be equal to 32 (PK) + 24 (nonce) + 16 (MAC) bytes
pub const ENC_PAYLOAD_SIZE: usize = 72;

impl FromBytes for Payload {
    named!(from_bytes<Payload>, do_parse!(
        pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        (Payload { session_pk: pk, session_nonce: nonce })
    ));
}

impl ToBytes for Payload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.session_pk.as_ref()) >>
            gen_slice!(self.session_nonce.as_ref())
        )
    }
}



/// implements tokio-io's Decoder and Encoder to deal with Client handshake
pub struct ClientCodec;

impl Decoder for ClientCodec {
    type Item = Client;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let (consumed, handshake) = match Client::from_bytes(buf) {
            IResult::Incomplete(_) => {
                return Ok(None)
            },
            IResult::Error(e) => {
                return Err(Error::new(ErrorKind::Other,
                                      format!("Client handshake deserialize error: {:?}", e)))
            },
            IResult::Done(i, handshake) => {
                (buf.offset(i), handshake)
            }
        };
        buf.split_to(consumed);
        Ok(Some(handshake))
    }
}

impl Encoder for ClientCodec {
    type Item = Client;
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
pub struct ServerCodec;

impl Decoder for ServerCodec {
    type Item = Server;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let (consumed, handshake) = match Server::from_bytes(buf) {
            IResult::Incomplete(_) => {
                return Ok(None)
            },
            IResult::Error(e) => {
                return Err(Error::new(ErrorKind::Other,
                                      format!("Server handshake deserialize error: {:?}", e)))
            },
            IResult::Done(i, handshake) => {
                (buf.offset(i), handshake)
            }
        };
        buf.split_to(consumed);
        Ok(Some(handshake))
    }
}

impl Encoder for ServerCodec {
    type Item = Server;
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

#[cfg(test)]
mod tests {
    use ::toxcore::tcp::handshake::*;

    #[test]
    fn client_encode_decode() {
        let (pk, _) = gen_keypair();
        let nonce = gen_nonce();
        let mut buf = BytesMut::new();
        let mut codec = ClientCodec { };
        let handshake = Client { pk: pk, nonce: nonce, payload: vec![42; ENC_PAYLOAD_SIZE] };
        codec.encode(handshake.clone(), &mut buf).expect("should encode");
        let res = codec.decode(&mut buf).unwrap().expect("should decode");
        assert_eq!(handshake, res);
    }
    #[test]
    fn client_decode_incomplete() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[]);
        let mut codec = ClientCodec { };
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }
    #[test]
    fn client_encode_too_big() {
        let nonce = gen_nonce();
        let (pk, _) = gen_keypair();
        let handshake = Client { pk: pk, nonce: nonce, payload: vec![42; ENC_PAYLOAD_SIZE + 1] };
        let mut buf = BytesMut::new();
        let mut codec = ClientCodec { };
        assert!(codec.encode(handshake, &mut buf).is_err());
    }
    #[test]
    fn server_encode_decode() {
        let nonce = gen_nonce();
        let mut buf = BytesMut::new();
        let mut codec = ServerCodec { };
        let handshake = Server { nonce: nonce, payload: vec![42; ENC_PAYLOAD_SIZE] };
        codec.encode(handshake.clone(), &mut buf).expect("should encode");
        let res = codec.decode(&mut buf).unwrap().expect("should decode");
        assert_eq!(handshake, res);
    }
    #[test]
    fn server_decode_incomplete() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[]);
        let mut codec = ServerCodec { };
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }
    #[test]
    fn server_encode_too_big() {
        let nonce = gen_nonce();
        let mut buf = BytesMut::new();
        let mut codec = ServerCodec { };
        let handshake = Server { nonce: nonce, payload: vec![42; ENC_PAYLOAD_SIZE + 1] };
        assert!(codec.encode(handshake, &mut buf).is_err());
    }
}
