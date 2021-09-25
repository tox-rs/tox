/*! Codecs to deal with ClientHandshake and ServerHandshake in terms of tokio-io
*/

use tox_binary_io::*;
use crate::relay::handshake::packet::*;

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

impl Encoder<ClientHandshake> for ClientHandshakeCodec {
    type Error = Error;

    fn encode(&mut self, handshake: ClientHandshake, buf: &mut BytesMut) -> Result<(), Self::Error> {
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

impl Encoder<ServerHandshake> for ServerHandshakeCodec {
    type Error = Error;

    fn encode(&mut self, handshake: ServerHandshake, buf: &mut BytesMut) -> Result<(), Self::Error> {
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
    use crate::relay::handshake::codec::*;
    use bytes::BytesMut;
    use crypto_box::{SalsaBox, SecretKey, aead::{AeadCore, generic_array::typenum::marker_traits::Unsigned}};
    use rand::thread_rng;

    #[test]
    fn client_encode_decode() {
        let pk = SecretKey::generate(&mut thread_rng()).public_key();
        let mut buf = BytesMut::new();
        let mut codec = ClientHandshakeCodec { };
        let handshake = ClientHandshake {
            pk,
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; ENC_PAYLOAD_SIZE],
        };
        codec.encode(handshake.clone(), &mut buf).expect("should encode");
        let res = codec.decode(&mut buf).unwrap().expect("should decode");
        assert_eq!(handshake, res);
    }
    #[test]
    fn client_decode_incomplete() {
        let mut buf = BytesMut::new();
        let mut codec = ClientHandshakeCodec { };
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }
    #[test]
    fn client_encode_too_big() {
        let pk = SecretKey::generate(&mut thread_rng()).public_key();
        let handshake = ClientHandshake {
            pk,
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; ENC_PAYLOAD_SIZE + 1],
        };
        let mut buf = BytesMut::new();
        let mut codec = ClientHandshakeCodec { };
        assert!(codec.encode(handshake, &mut buf).is_err());
    }
    #[test]
    fn server_encode_decode() {
        let mut buf = BytesMut::new();
        let mut codec = ServerHandshakeCodec { };
        let handshake = ServerHandshake {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; ENC_PAYLOAD_SIZE],
        };
        codec.encode(handshake.clone(), &mut buf).expect("should encode");
        let res = codec.decode(&mut buf).unwrap().expect("should decode");
        assert_eq!(handshake, res);
    }
    #[test]
    fn server_decode_incomplete() {
        let mut buf = BytesMut::new();
        let mut codec = ServerHandshakeCodec { };
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }
    #[test]
    fn server_encode_too_big() {
        let mut buf = BytesMut::new();
        let mut codec = ServerHandshakeCodec { };
        let handshake = ServerHandshake {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; ENC_PAYLOAD_SIZE + 1],
        };
        assert!(codec.encode(handshake, &mut buf).is_err());
    }
}
