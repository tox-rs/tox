/*! Codecs to deal with ClientHandshake and ServerHandshake in terms of tokio-io
*/

use crate::toxcore::binary_io::*;
use crate::toxcore::tcp::handshake::packet::*;

use nom::{Err, Offset};
use bytes::{BytesMut, Buf};
use std::io::{Error, ErrorKind};
use tokio_util::codec::{Decoder, Encoder};

/// implements tokio-io's Decoder and Encoder to deal with Client handshake
pub struct ClientHandshakeCodec;

impl Decoder for ClientHandshakeCodec {
    type Item = ClientHandshake;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let (consumed, handshake) = match ClientHandshake::from_bytes(buf) {
            Err(Err::Incomplete(_)) => {
                return Ok(None)
            },
            Err(_) => unreachable!("ClientHandshake cannot be deserialized with error"),
            Ok((i, handshake)) => {
                (buf.offset(i), handshake)
            }
        };
        buf.advance(consumed);
        Ok(Some(handshake))
    }
}

impl Encoder for ClientHandshakeCodec {
    type Item = ClientHandshake;
    type Error = Error;

    fn encode(&mut self, handshake: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let mut handshake_buf = [0; CLIENT_HANDSHAKE_SIZE];
        handshake.to_bytes((&mut handshake_buf, 0))
            .map(|(handshake_buf, handshake_size)|
                buf.extend_from_slice(&handshake_buf[..handshake_size])
            )
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
            Err(Err::Incomplete(_)) => {
                return Ok(None)
            },
            Err(_) => unreachable!("ServerHandshake cannot be deserialized with error"),
            Ok((i, handshake)) => {
                (buf.offset(i), handshake)
            }
        };
        buf.advance(consumed);
        Ok(Some(handshake))
    }
}

impl Encoder for ServerHandshakeCodec {
    type Item = ServerHandshake;
    type Error = Error;

    fn encode(&mut self, handshake: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let mut handshake_buf = [0; SERVER_HANDSHAKE_SIZE];
        handshake.to_bytes((&mut handshake_buf, 0))
            .map(|(handshake_buf, handshake_size)|
                buf.extend_from_slice(&handshake_buf[..handshake_size])
            )
            .map_err(|e|
                Error::new(ErrorKind::Other,
                           format!("Server handshake serialize error: {:?}", e))
            )
    }
}

#[cfg(test)]
mod tests {
    use crate::toxcore::tcp::handshake::codec::*;
    use crate::toxcore::crypto_core::*;
    use bytes::BytesMut;

    #[test]
    fn client_encode_decode() {
        crypto_init().unwrap();
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
        crypto_init().unwrap();
        let mut buf = BytesMut::new();
        let mut codec = ClientHandshakeCodec { };
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }
    #[test]
    fn client_encode_too_big() {
        crypto_init().unwrap();
        let nonce = gen_nonce();
        let (pk, _) = gen_keypair();
        let handshake = ClientHandshake { pk, nonce, payload: vec![42; ENC_PAYLOAD_SIZE + 1] };
        let mut buf = BytesMut::new();
        let mut codec = ClientHandshakeCodec { };
        assert!(codec.encode(handshake, &mut buf).is_err());
    }
    #[test]
    fn server_encode_decode() {
        crypto_init().unwrap();
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
        crypto_init().unwrap();
        let mut buf = BytesMut::new();
        let mut codec = ServerHandshakeCodec { };
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }
    #[test]
    fn server_encode_too_big() {
        crypto_init().unwrap();
        let nonce = gen_nonce();
        let mut buf = BytesMut::new();
        let mut codec = ServerHandshakeCodec { };
        let handshake = ServerHandshake { nonce, payload: vec![42; ENC_PAYLOAD_SIZE + 1] };
        assert!(codec.encode(handshake, &mut buf).is_err());
    }
}
