/*! CookieResponse packet
*/

use nom::number::complete::be_u64;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packet::cookie::EncryptedCookie;
use crate::toxcore::dht::packet::errors::*;

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
    named!(from_bytes<CookieResponse>, do_parse!(
        tag!("\x19") >>
        nonce: call!(Nonce::from_bytes) >>
        payload: take!(136) >>
        eof!() >>
        (CookieResponse { nonce, payload: payload.to_vec() })
    ));
}

impl ToBytes for CookieResponse {
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
    pub fn new(shared_secret: &PrecomputedKey, payload: &CookieResponsePayload) -> CookieResponse {
        let nonce = gen_nonce();
        let mut buf = [0; 120];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        CookieResponse {
            nonce,
            payload,
        }
    }
    /** Decrypt payload with precomputed key and try to parse it as `CookieResponsePayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse `CookieResponsePayload`
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<CookieResponsePayload, GetPayloadError> {
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|()| {
                debug!("Decrypting CookieResponse failed!");
                GetPayloadError::decrypt()
            })?;
        match CookieResponsePayload::from_bytes(&decrypted) {
            Err(error) => {
                debug!(target: "Dht", "CookieResponsePayload return deserialize error: {:?}", error);
                Err(GetPayloadError::deserialize(error, decrypted.clone()))
            },
            Ok((_, payload)) => {
                Ok(payload)
            }
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
    named!(from_bytes<CookieResponsePayload>, do_parse!(
        cookie: call!(EncryptedCookie::from_bytes) >>
        id: be_u64 >>
        eof!() >>
        (CookieResponsePayload { cookie, id })
    ));
}

impl ToBytes for CookieResponsePayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, cookie| EncryptedCookie::to_bytes(cookie, buf), &self.cookie) >>
            gen_be_u64!(self.id)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::{Needed, Err, error::ErrorKind};

    encode_decode_test!(
        cookie_response_encode_decode,
        CookieResponse {
            nonce: gen_nonce(),
            payload: vec![42; 136],
        }
    );

    encode_decode_test!(
        cookie_response_payload_encode_decode,
        CookieResponsePayload {
            cookie: EncryptedCookie {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; 88],
            },
            id: 12345,
        }
    );

    #[test]
    fn cookie_response_encrypt_decrypt() {
        crypto_init().unwrap();
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = CookieResponsePayload {
            cookie: EncryptedCookie {
                nonce: secretbox::gen_nonce(),
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
        crypto_init().unwrap();
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let eve_shared_secret = encrypt_precompute(&bob_pk, &eve_sk);
        let payload = CookieResponsePayload {
            cookie: EncryptedCookie {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; 88],
            },
            id: 12345,
        };
        // encode payload with shared secret
        let dht_packet = CookieResponse::new(&shared_secret, &payload);
        // try to decode payload with eve's shared secret
        let decoded_payload = dht_packet.get_payload(&eve_shared_secret);
        assert!(decoded_payload.is_err());
        assert_eq!(*decoded_payload.err().unwrap().kind(), GetPayloadErrorKind::Decrypt);
    }

    #[test]
    fn cookie_response_encrypt_decrypt_invalid() {
        crypto_init().unwrap();
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_packet = CookieResponse {
            nonce,
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&shared_secret);
        let error = decoded_payload.err().unwrap();
        assert_eq!(*error.kind(), GetPayloadErrorKind::Deserialize {
            error: Err::Error((vec![42; 3], ErrorKind::Eof)),
            payload: invalid_payload.to_vec()
        });
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_packet = CookieResponse {
            nonce,
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&shared_secret);
        let error = decoded_payload.err().unwrap();
        assert_eq!(*error.kind(), GetPayloadErrorKind::Deserialize {
            error: Err::Incomplete(Needed::Size(24)),
            payload: invalid_payload.to_vec()
        });
    }
}
