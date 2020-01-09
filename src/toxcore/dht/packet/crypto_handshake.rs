/*! CryptoHandshake packet
*/

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packet::cookie::EncryptedCookie;
use crate::toxcore::dht::packet::errors::*;

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
    pub payload: Vec<u8>
}

impl FromBytes for CryptoHandshake {
    named!(from_bytes<CryptoHandshake>, do_parse!(
        tag!("\x1a") >>
        cookie: call!(EncryptedCookie::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        payload: take!(248) >>
        eof!() >>
        (CryptoHandshake {
            cookie,
            nonce,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for CryptoHandshake {
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
    pub fn new(shared_secret: &PrecomputedKey, payload: &CryptoHandshakePayload, cookie: EncryptedCookie) -> CryptoHandshake {
        let nonce = gen_nonce();
        let mut buf = [0; 232];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        CryptoHandshake {
            cookie,
            nonce,
            payload,
        }
    }
    /** Decrypt payload with precomputed key and try to parse it as `CryptoHandshakePayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse `CryptoHandshakePayload`
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<CryptoHandshakePayload, GetPayloadError> {
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|()| {
                debug!("Decrypting CryptoHandshake failed!");
                GetPayloadError::decrypt()
            })?;
        match CryptoHandshakePayload::from_bytes(&decrypted) {
            Err(error) => {
                debug!(target: "Dht", "CryptoHandshakePayload return deserialize error: {:?}", error);
                Err(GetPayloadError::deserialize(error, decrypted.clone()))
            },
            Ok((_, payload)) => {
                Ok(payload)
            }
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
    pub cookie_hash: sha512::Digest,
    /// Encrypted cookie of sender of `CryptoHandshake` packet. When node
    /// receives `CryptoHandshake` it can take this cookie instead of sending
    /// `CookieRequest` to obtain one.
    pub cookie: EncryptedCookie
}

impl FromBytes for CryptoHandshakePayload {
    named!(from_bytes<CryptoHandshakePayload>, do_parse!(
        base_nonce: call!(Nonce::from_bytes) >>
        session_pk: call!(PublicKey::from_bytes) >>
        cookie_hash: call!(sha512::Digest::from_bytes) >>
        cookie: call!(EncryptedCookie::from_bytes) >>
        eof!() >>
        (CryptoHandshakePayload {
            base_nonce,
            session_pk,
            cookie_hash,
            cookie
        })
    ));
}

impl ToBytes for CryptoHandshakePayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.base_nonce.as_ref()) >>
            gen_slice!(self.session_pk.as_ref()) >>
            gen_slice!(self.cookie_hash.as_ref()) >>
            gen_call!(|buf, cookie| EncryptedCookie::to_bytes(cookie, buf), &self.cookie)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::{Needed, Err};

    encode_decode_test!(
        crypto_handshake_encode_decode,
        CryptoHandshake {
            cookie: EncryptedCookie {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; 88],
            },
            nonce: gen_nonce(),
            payload: vec![42; 248],
        }
    );

    encode_decode_test!(
        crypto_handshake_payload_encode_decode,
        CryptoHandshakePayload {
            base_nonce: gen_nonce(),
            session_pk: gen_keypair().0,
            cookie_hash: sha512::hash(&[1, 2, 3]),
            cookie: EncryptedCookie {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; 88],
            },
        }
    );

    #[test]
    fn crypto_handshake_encrypt_decrypt() {
        crypto_init().unwrap();
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; 88],
        };
        let payload = CryptoHandshakePayload {
            base_nonce: gen_nonce(),
            session_pk: gen_keypair().0,
            cookie_hash: sha512::hash(&[1, 2, 3]),
            cookie: EncryptedCookie {
                nonce: secretbox::gen_nonce(),
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
        crypto_init().unwrap();
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let eve_shared_secret = encrypt_precompute(&bob_pk, &eve_sk);
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; 88],
        };
        let payload = CryptoHandshakePayload {
            base_nonce: gen_nonce(),
            session_pk: gen_keypair().0,
            cookie_hash: sha512::hash(&[1, 2, 3]),
            cookie: EncryptedCookie {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; 88],
            },
        };
        // encode payload with shared secret
        let dht_packet = CryptoHandshake::new(&shared_secret, &payload, cookie);
        // try to decode payload with eve's shared secret
        let decoded_payload = dht_packet.get_payload(&eve_shared_secret);
        let error = decoded_payload.err().unwrap();
        assert_eq!(*error.kind(), GetPayloadErrorKind::Decrypt);
    }

    #[test]
    fn crypto_handshake_encrypt_decrypt_invalid() {
        crypto_init().unwrap();
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();
        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; 88],
        };
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_packet = CryptoHandshake {
            cookie: cookie.clone(),
            nonce,
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&shared_secret);
        let error = decoded_payload.err().unwrap();
        assert_eq!(*error.kind(), GetPayloadErrorKind::Deserialize {
            error: Err::Incomplete(Needed::Size(24)),
            payload: invalid_payload.to_vec()
        });
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_packet = CryptoHandshake {
            cookie,
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
