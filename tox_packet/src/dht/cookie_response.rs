/*! CookieResponse packet
*/

use crypto_box::{
    aead::{Aead, AeadCore, Error as AeadError},
    SalsaBox,
};
use nom::bytes::complete::{tag, take};
use nom::combinator::eof;
use nom::number::complete::be_u64;

use cookie_factory::{do_gen, gen_be_u64, gen_be_u8, gen_call, gen_slice};

use crate::dht::cookie::EncryptedCookie;
use crate::dht::errors::*;
use tox_binary_io::*;
use tox_crypto::*;

/** Response to a `CookieRequest` packet.

Encrypted payload is encrypted with the same symmetric key as the
`CookieRequest` packet it responds to but with a different nonce.

Serialized form:

Length | Content
------ | ------
`1`    | `0x19`
`24`   | `Nonce`
`136`  | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CookieResponse {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Encrypted payload
    pub payload: Vec<u8>,
}

impl FromBytes for CookieResponse {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x19")(input)?;
        let (input, nonce) = Nonce::from_bytes(input)?;
        let (input, payload) = take(136usize)(input)?;
        let (input, _) = eof(input)?;
        Ok((
            input,
            CookieResponse {
                nonce,
                payload: payload.to_vec(),
            },
        ))
    }
}

impl ToBytes for CookieResponse {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x19) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl CookieResponse {
    /// Create `CookieResponse` from `CookieRequestPayload` encrypting it with `shared_key`
    pub fn new(shared_secret: &SalsaBox, payload: &CookieResponsePayload) -> CookieResponse {
        let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
        let mut buf = [0; 120];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = shared_secret.encrypt(&nonce, &buf[..size]).unwrap();

        CookieResponse {
            nonce: nonce.into(),
            payload,
        }
    }
    /** Decrypt payload with precomputed key and try to parse it as `CookieResponsePayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse `CookieResponsePayload`
    */
    pub fn get_payload(&self, shared_secret: &SalsaBox) -> Result<CookieResponsePayload, GetPayloadError> {
        let decrypted = shared_secret
            .decrypt((&self.nonce).into(), self.payload.as_slice())
            .map_err(|AeadError| GetPayloadError::decrypt())?;
        match CookieResponsePayload::from_bytes(&decrypted) {
            Err(error) => Err(GetPayloadError::deserialize(error, decrypted.clone())),
            Ok((_, payload)) => Ok(payload),
        }
    }
}

/** Unencrypted payload of `CookieResponse` packet.

Contains requested cookie and id to match response packet with sent request.

Serialized form:

Length | Content
------ | ------
`24`   | `Nonce` for the encrypted cookie
`88`   | Encrypted cookie
`8`    | Request ID in BigEndian

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CookieResponsePayload {
    /// Encrypted cookie
    pub cookie: EncryptedCookie,
    /// Request id
    pub id: u64,
}

impl FromBytes for CookieResponsePayload {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, cookie) = EncryptedCookie::from_bytes(input)?;
        let (input, id) = be_u64(input)?;
        let (input, _) = eof(input)?;
        Ok((input, CookieResponsePayload { cookie, id }))
    }
}

impl ToBytes for CookieResponsePayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(
            buf,
            gen_call!(|buf, cookie| EncryptedCookie::to_bytes(cookie, buf), &self.cookie) >> gen_be_u64!(self.id)
        )
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::*;
    use crypto_box::aead::{generic_array::typenum::marker_traits::Unsigned, AeadCore};
    use nom::{
        error::{Error, ErrorKind},
        Err, Needed,
    };
    use rand::thread_rng;

    encode_decode_test!(
        cookie_response_encode_decode,
        CookieResponse {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 136],
        }
    );

    encode_decode_test!(
        cookie_response_payload_encode_decode,
        CookieResponsePayload {
            cookie: EncryptedCookie {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; 88],
            },
            id: 12345,
        }
    );

    #[test]
    fn cookie_response_encrypt_decrypt() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let payload = CookieResponsePayload {
            cookie: EncryptedCookie {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; 88],
            },
            id: 12345,
        };
        // encode payload with shared secret
        let cookie_response = CookieResponse::new(&shared_secret, &payload);
        // decode payload with shared secret
        let decoded_payload = cookie_response.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn cookie_response_encrypt_decrypt_invalid_key() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let eve_sk = SecretKey::generate(&mut rng);
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let eve_shared_secret = SalsaBox::new(&bob_pk, &eve_sk);
        let payload = CookieResponsePayload {
            cookie: EncryptedCookie {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; 88],
            },
            id: 12345,
        };
        // encode payload with shared secret
        let dht_packet = CookieResponse::new(&shared_secret, &payload);
        // try to decode payload with eve's shared secret
        let decoded_payload = dht_packet.get_payload(&eve_shared_secret);
        assert!(decoded_payload.is_err());
        assert_eq!(decoded_payload.err().unwrap(), GetPayloadError::Decrypt);
    }

    #[test]
    fn cookie_response_encrypt_decrypt_invalid() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_packet = CookieResponse {
            nonce: nonce.into(),
            payload: invalid_payload_encoded,
        };
        let decoded_payload = invalid_packet.get_payload(&shared_secret);
        let error = decoded_payload.err().unwrap();
        assert_eq!(
            error,
            GetPayloadError::Deserialize {
                error: Err::Error(Error::new(vec![42; 3], ErrorKind::Eof)),
                payload: invalid_payload.to_vec()
            }
        );
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_packet = CookieResponse {
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
