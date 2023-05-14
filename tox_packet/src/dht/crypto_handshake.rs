/*! CryptoHandshake packet
*/

use super::*;

use crate::dht::cookie::EncryptedCookie;
use crate::dht::errors::*;
use crypto_box::{
    aead::{Aead, AeadCore, Error as AeadError},
    SalsaBox,
};
use nom::bytes::complete::{tag, take};
use nom::combinator::eof;
use sha2::digest::typenum::Unsigned;
use sha2::digest::OutputSizeUser;
use sha2::Sha512;
use tox_binary_io::*;
use tox_crypto::*;

/** Packet used to establish `net_crypto` connection between two peers.

When Alice establishes `net_crypto` connection with Bob she should get valid
`Cookie` from him and send `CryptoHandshake` packet. Connection considered
established when both Alice and Bob received `CryptoHandshake` packet from each
other with valid cookies.

Serialized form:

Length | Content
------ | ------
`1`    | `0x1a`
`24`   | `Nonce` for the cookie
`88`   | Cookie
`24`   | `Nonce` for the payload
`248`  | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptoHandshake {
    /// Encrypted cookie used to check that the sender of this packet received a
    /// cookie response
    pub cookie: EncryptedCookie,
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Encrypted payload
    pub payload: Vec<u8>,
}

impl FromBytes for CryptoHandshake {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x1a")(input)?;
        let (input, cookie) = EncryptedCookie::from_bytes(input)?;
        let (input, nonce) = Nonce::from_bytes(input)?;
        let (input, payload) = take(248usize)(input)?;
        let (input, _) = eof(input)?;
        Ok((
            input,
            CryptoHandshake {
                cookie,
                nonce,
                payload: payload.to_vec(),
            },
        ))
    }
}

impl ToBytes for CryptoHandshake {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x1a) >>
            gen_call!(|buf, cookie| EncryptedCookie::to_bytes(cookie, buf), &self.cookie) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl CryptoHandshake {
    /// Create `CryptoHandshake` from `CryptoHandshakePayload` encrypting it
    /// with `shared_key` and from `EncryptedCookie`.
    pub fn new(shared_secret: &SalsaBox, payload: &CryptoHandshakePayload, cookie: EncryptedCookie) -> CryptoHandshake {
        let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
        let mut buf = [0; 232];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = shared_secret.encrypt(&nonce, &buf[..size]).unwrap();

        CryptoHandshake {
            cookie,
            nonce: nonce.into(),
            payload,
        }
    }
    /** Decrypt payload with precomputed key and try to parse it as `CryptoHandshakePayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse `CryptoHandshakePayload`
    */
    pub fn get_payload(&self, shared_secret: &SalsaBox) -> Result<CryptoHandshakePayload, GetPayloadError> {
        let decrypted = shared_secret
            .decrypt((&self.nonce).into(), self.payload.as_slice())
            .map_err(|AeadError| GetPayloadError::decrypt())?;
        match CryptoHandshakePayload::from_bytes(&decrypted) {
            Err(error) => Err(GetPayloadError::deserialize(error, decrypted.clone())),
            Ok((_, payload)) => Ok(payload),
        }
    }
}

/** Unencrypted payload of `CryptoHandshake` packet.

Serialized form:

Length | Content
------ | ------
`24`   | `Nonce`
`32`   | Session `PublicKey`
`64`   | SHA512 hash of the cookie
`24`   | `Nonce` for the cookie
`88`   | Cookie

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptoHandshakePayload {
    /// Nonce that should be used to encrypt each data packet, adding 1 to it
    /// for each data packet sent.
    pub base_nonce: Nonce,
    /// Temporary session key used to encrypt data packets to achieve perfect
    /// forward secrecy.
    pub session_pk: PublicKey,
    /// SHA512 hash of the encrypted cookie from `CryptoHandshake` packet. It's
    /// used to make sure that possible attacker can't combine payload from old
    /// `CryptoHandshake` with new `Cookie` and try to do mess sending such
    /// packets.
    pub cookie_hash: [u8; <Sha512 as OutputSizeUser>::OutputSize::USIZE],
    /// Encrypted cookie of sender of `CryptoHandshake` packet. When node
    /// receives `CryptoHandshake` it can take this cookie instead of sending
    /// `CookieRequest` to obtain one.
    pub cookie: EncryptedCookie,
}

impl FromBytes for CryptoHandshakePayload {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, base_nonce) = Nonce::from_bytes(input)?;
        let (input, session_pk) = PublicKey::from_bytes(input)?;
        let (input, cookie_hash) = <[u8; <Sha512 as OutputSizeUser>::OutputSize::USIZE]>::from_bytes(input)?;
        let (input, cookie) = EncryptedCookie::from_bytes(input)?;
        let (input, _) = eof(input)?;
        Ok((
            input,
            CryptoHandshakePayload {
                base_nonce,
                session_pk,
                cookie_hash,
                cookie,
            },
        ))
    }
}

impl ToBytes for CryptoHandshakePayload {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.base_nonce.as_ref()) >>
            gen_slice!(self.session_pk.as_bytes()) >>
            gen_slice!(self.cookie_hash.as_ref()) >>
            gen_call!(|buf, cookie| EncryptedCookie::to_bytes(cookie, buf), &self.cookie)
        )
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::*;
    use crypto_box::aead::{generic_array::typenum::marker_traits::Unsigned, AeadCore};
    use nom::{Err, Needed};
    use rand::thread_rng;

    encode_decode_test!(
        crypto_handshake_encode_decode,
        CryptoHandshake {
            cookie: EncryptedCookie {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; 88],
            },
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 248],
        }
    );

    encode_decode_test!(
        crypto_handshake_payload_encode_decode,
        CryptoHandshakePayload {
            base_nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            session_pk: SecretKey::generate(&mut thread_rng()).public_key(),
            cookie_hash: [42; 64],
            cookie: EncryptedCookie {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; 88],
            },
        }
    );

    #[test]
    fn crypto_handshake_encrypt_decrypt() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let cookie = EncryptedCookie {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; 88],
        };
        let payload = CryptoHandshakePayload {
            base_nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            session_pk: SecretKey::generate(&mut rng).public_key(),
            cookie_hash: [42; 64],
            cookie: EncryptedCookie {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; 88],
            },
        };
        // encode payload with shared secret
        let crypto_handshake = CryptoHandshake::new(&shared_secret, &payload, cookie);
        // decode payload with shared secret
        let decoded_payload = crypto_handshake.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn crypto_handshake_encrypt_decrypt_invalid_key() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let eve_sk = SecretKey::generate(&mut rng);
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let eve_shared_secret = SalsaBox::new(&bob_pk, &eve_sk);
        let cookie = EncryptedCookie {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; 88],
        };
        let payload = CryptoHandshakePayload {
            base_nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            session_pk: SecretKey::generate(&mut rng).public_key(),
            cookie_hash: [42; 64],
            cookie: EncryptedCookie {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; 88],
            },
        };
        // encode payload with shared secret
        let dht_packet = CryptoHandshake::new(&shared_secret, &payload, cookie);
        // try to decode payload with eve's shared secret
        let decoded_payload = dht_packet.get_payload(&eve_shared_secret);
        let error = decoded_payload.err().unwrap();
        assert_eq!(error, GetPayloadError::Decrypt);
    }

    #[test]
    fn crypto_handshake_encrypt_decrypt_invalid() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
        let cookie = EncryptedCookie {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; 88],
        };
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_packet = CryptoHandshake {
            cookie: cookie.clone(),
            nonce: nonce.into(),
            payload: invalid_payload_encoded,
        };
        let decoded_payload = invalid_packet.get_payload(&shared_secret);
        let error = decoded_payload.err().unwrap();
        assert_eq!(
            error,
            GetPayloadError::Deserialize {
                error: Err::Incomplete(Needed::Size(NonZeroUsize::new(21).unwrap())),
                payload: invalid_payload.to_vec()
            }
        );
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_packet = CryptoHandshake {
            cookie,
            nonce: nonce.into(),
            payload: invalid_payload_encoded,
        };
        let decoded_payload = invalid_packet.get_payload(&shared_secret);
        let error = decoded_payload.err().unwrap();
        assert_eq!(
            error,
            GetPayloadError::Deserialize {
                error: Err::Incomplete(Needed::Size(NonZeroUsize::new(24).unwrap())),
                payload: invalid_payload.to_vec()
            }
        );
    }
}
