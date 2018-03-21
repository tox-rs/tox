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

/*! Handshake packets to establish a confirmed connection via
handshake using [`Diagram`](https://zetok.github.io/tox-spec/#handshake-diagram)

*/

pub mod packet;
pub mod codec;

pub use self::packet::*;
pub use self::codec::*;

#[cfg(test)]
mod tests {
    use ::toxcore::tcp::handshake::*;
    use ::toxcore::crypto_core::*;
    use bytes::BytesMut;
    use tokio_io::codec::*;

    #[test]
    fn client_encode_decode() {
        let (pk, _) = gen_keypair();
        let nonce = gen_nonce();
        let mut buf = BytesMut::new();
        let mut codec = ClientHandshakeCodec { };
        let handshake = ClientHandshake { pk, nonce, payload: vec![42; ENC_PAYLOAD_SIZE] };
        codec.encode(handshake.clone(), &mut buf).expect("should encode");
        let res = codec.decode(&mut buf).unwrap().expect("should decode");
        assert_eq!(handshake, res);
    }
    #[test]
    fn client_decode_incomplete() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[]);
        let mut codec = ClientHandshakeCodec { };
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }
    #[test]
    fn client_encode_too_big() {
        let nonce = gen_nonce();
        let (pk, _) = gen_keypair();
        let handshake = ClientHandshake { pk, nonce, payload: vec![42; ENC_PAYLOAD_SIZE + 1] };
        let mut buf = BytesMut::new();
        let mut codec = ClientHandshakeCodec { };
        assert!(codec.encode(handshake, &mut buf).is_err());
    }
    #[test]
    fn server_encode_decode() {
        let nonce = gen_nonce();
        let mut buf = BytesMut::new();
        let mut codec = ServerHandshakeCodec { };
        let handshake = ServerHandshake { nonce, payload: vec![42; ENC_PAYLOAD_SIZE] };
        codec.encode(handshake.clone(), &mut buf).expect("should encode");
        let res = codec.decode(&mut buf).unwrap().expect("should decode");
        assert_eq!(handshake, res);
    }
    #[test]
    fn server_decode_incomplete() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[]);
        let mut codec = ServerHandshakeCodec { };
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }
    #[test]
    fn server_encode_too_big() {
        let nonce = gen_nonce();
        let mut buf = BytesMut::new();
        let mut codec = ServerHandshakeCodec { };
        let handshake = ServerHandshake { nonce, payload: vec![42; ENC_PAYLOAD_SIZE + 1] };
        assert!(codec.encode(handshake, &mut buf).is_err());
    }
}
