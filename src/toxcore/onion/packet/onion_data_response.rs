/*! OnionDataResponse packet
*/

use super::*;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packet::*;
use crate::toxcore::friend_connection::packet::MAX_ONION_CLIENT_DATA_SIZE;

use nom::combinator::{rest, rest_len};

/// Maximum size in bytes of Onion Data Response payload
pub const MAX_ONION_RESPONSE_PAYLOAD_SIZE: usize = MAX_ONION_CLIENT_DATA_SIZE + PUBLICKEYBYTES + MACBYTES;

/** When onion node receives `OnionDataRequest` packet it converts it to
`OnionDataResponse` and sends to destination node if it announced itself
and is contained in onion nodes list.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x86`
`24`     | `Nonce`
`32`     | Temporary `PublicKey`
variable | Payload

where payload is encrypted [`OnionDataResponsePayload`](./struct.OnionDataResponsePayload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionDataResponse {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for OnionDataResponse {
    named!(from_bytes<OnionDataResponse>, do_parse!(
        verify!(rest_len, |len| *len <= ONION_MAX_PACKET_SIZE) >>
        tag!(&[0x86][..]) >>
        nonce: call!(Nonce::from_bytes) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        payload: rest >>
        (OnionDataResponse {
            nonce,
            temporary_pk,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for OnionDataResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x86) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.payload.as_slice()) >>
            gen_len_limit(ONION_MAX_PACKET_SIZE)
        )
    }
}

impl OnionDataResponse {
    /// Create `OnionDataResponse` from `OnionDataResponsePayload` encrypting it
    /// with `shared_key` and `nonce`
    pub fn new(shared_secret: &PrecomputedKey, temporary_pk: PublicKey, nonce: Nonce, payload: &OnionDataResponsePayload) -> OnionDataResponse {
        let mut buf = [0; MAX_ONION_RESPONSE_PAYLOAD_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        OnionDataResponse {
            nonce,
            temporary_pk,
            payload,
        }
    }

    /** Decrypt payload and try to parse it as `OnionDataResponsePayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `OnionDataResponsePayload`
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<OnionDataResponsePayload, GetPayloadError> {
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|()| {
                debug!("Decrypting OnionDataResponsePayload failed!");
                GetPayloadError::decrypt()
            })?;
        match OnionDataResponsePayload::from_bytes(&decrypted) {
            Err(error) => {
                debug!(target: "Onion", "OnionDataResponsePayload deserialize error: {:?}", error);
                Err(GetPayloadError::deserialize(error, decrypted.clone()))
            },
            Ok((_, inner)) => {
                Ok(inner)
            }
        }
    }
}

/** Unencrypted payload of `OnionDataResponse` packet.

Inner payload is encrypted with long term `PublicKey` to prove to the receiver
that the sender owns it.

Serialized form:

Length   | Content
-------- | ------
`32`     | Long term `PublicKey`
variable | Payload

where payload is encrypted [`OnionDataResponseInnerPayload`](./struct.OnionDataResponseInnerPayload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionDataResponsePayload {
    /// Long term `PublicKey` that was used for the inner encrypted payload.
    pub real_pk: PublicKey,
    /// Inner encrypted payload.
    pub payload: Vec<u8>,
}

impl FromBytes for OnionDataResponsePayload {
    named!(from_bytes<OnionDataResponsePayload>, do_parse!(
        real_pk: call!(PublicKey::from_bytes) >>
        payload: rest >>
        (OnionDataResponsePayload {
            real_pk,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for OnionDataResponsePayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.real_pk.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl OnionDataResponsePayload {
    /// Create `OnionDataResponsePayload` from `OnionDataResponseInnerPayload`
    /// encrypting it with `shared_key` and `nonce`
    pub fn new(shared_secret: &PrecomputedKey, real_pk: PublicKey, nonce: &Nonce, payload: &OnionDataResponseInnerPayload) -> OnionDataResponsePayload {
        let mut buf = [0; MAX_ONION_CLIENT_DATA_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], nonce, shared_secret);

        OnionDataResponsePayload {
            real_pk,
            payload,
        }
    }

    /** Decrypt payload and try to parse it as `OnionDataResponseInnerPayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `OnionDataResponseInnerPayload`
    */
    pub fn get_payload(&self, nonce: &Nonce, shared_secret: &PrecomputedKey) -> Result<OnionDataResponseInnerPayload, GetPayloadError> {
        let decrypted = open_precomputed(&self.payload, nonce, shared_secret)
            .map_err(|()| {
                debug!("Decrypting OnionDataResponseInnerPayload failed!");
                GetPayloadError::decrypt()
            })?;
        match OnionDataResponseInnerPayload::from_bytes(&decrypted) {
            Err(error) => {
                debug!(target: "Onion", "OnionDataResponseInnerPayload deserialize error: {:?}", error);
                Err(GetPayloadError::deserialize(error, decrypted.clone()))
            },
            Ok((_, inner)) => {
                Ok(inner)
            }
        }
    }
}

/** Packet that is embedded in the payload of
[`OnionDataResponsePayload`](./struct.OnionDataResponsePayload.html).
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OnionDataResponseInnerPayload {
    /// [`DhtPkAnnouncePayload`](../../dht/packet/struct.DhtPkAnnouncePayload.html) structure.
    DhtPkAnnounce(DhtPkAnnouncePayload),
    /// [`FriendRequest`](../../dht/packet/struct.FriendRequest.html) structure.
    FriendRequest(FriendRequest),
}

impl FromBytes for OnionDataResponseInnerPayload {
    named!(from_bytes<OnionDataResponseInnerPayload>, alt!(
        map!(DhtPkAnnouncePayload::from_bytes, OnionDataResponseInnerPayload::DhtPkAnnounce) |
        map!(FriendRequest::from_bytes, OnionDataResponseInnerPayload::FriendRequest)
    ));
}

impl ToBytes for OnionDataResponseInnerPayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            OnionDataResponseInnerPayload::DhtPkAnnounce(ref p) => p.to_bytes(buf),
            OnionDataResponseInnerPayload::FriendRequest(ref p) => p.to_bytes(buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::toxcore::packed_node::*;
    use crate::toxcore::toxid::NoSpam;

    encode_decode_test!(
        onion_data_response_encode_decode,
        OnionDataResponse {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123]
        }
    );

    #[test]
    fn onion_data_response_encrypt_decrypt() {
        crypto_init().unwrap();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let nonce = gen_nonce();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = OnionDataResponsePayload {
            real_pk: gen_keypair().0,
            payload: vec![42; 123],
        };
        // encode payload with shared secret
        let packet = OnionDataResponse::new(&shared_secret, alice_pk, nonce, &payload);
        // decode payload with shared secret
        let decoded_payload = packet.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn onion_data_response_encrypt_decrypt_invalid_key() {
        crypto_init().unwrap();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let nonce = gen_nonce();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let shared_secret_invalid = encrypt_precompute(&bob_pk, &eve_sk);
        let payload = OnionDataResponsePayload {
            real_pk: gen_keypair().0,
            payload: vec![42; 123],
        };
        // encode payload with shared secret
        let packet = OnionDataResponse::new(&shared_secret, alice_pk, nonce, &payload);
        // try to decode payload with invalid shared secret
        let decoded_payload = packet.get_payload(&shared_secret_invalid);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn onion_data_response_encrypt_decrypt_invalid() {
        crypto_init().unwrap();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_packet = OnionDataResponse {
            nonce,
            temporary_pk: alice_pk,
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&shared_secret);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn onion_data_response_payload_encrypt_decrypt() {
        crypto_init().unwrap();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let nonce = gen_nonce();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = OnionDataResponseInnerPayload::DhtPkAnnounce(DhtPkAnnouncePayload {
            no_reply: 42,
            dht_pk: gen_keypair().0,
            nodes: vec![
                TcpUdpPackedNode {
                    ip_port: IpPort {
                        protocol: ProtocolType::UDP,
                        ip_addr: "127.0.0.1".parse().unwrap(),
                        port: 12345
                    },
                    pk: gen_keypair().0,
                },
            ],
        });
        // encode payload with shared secret
        let packet = OnionDataResponsePayload::new(&shared_secret, alice_pk, &nonce, &payload);
        // decode payload with shared secret
        let decoded_payload = packet.get_payload(&nonce, &shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn onion_data_response_payload_encrypt_decrypt_invalid_key() {
        crypto_init().unwrap();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let nonce = gen_nonce();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let shared_secret_invalid = encrypt_precompute(&bob_pk, &eve_sk);
        let payload = OnionDataResponseInnerPayload::DhtPkAnnounce(DhtPkAnnouncePayload {
            no_reply: 42,
            dht_pk: gen_keypair().0,
            nodes: vec![
                TcpUdpPackedNode {
                    ip_port: IpPort {
                        protocol: ProtocolType::UDP,
                        ip_addr: "127.0.0.1".parse().unwrap(),
                        port: 12345
                    },
                    pk: gen_keypair().0,
                },
            ],
        });
        // encode payload with shared secret
        let packet = OnionDataResponsePayload::new(&shared_secret, alice_pk, &nonce, &payload);
        // try to decode payload with invalid shared secret
        let decoded_payload = packet.get_payload(&nonce, &shared_secret_invalid);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn onion_data_response_payload_encrypt_decrypt_invalid() {
        crypto_init().unwrap();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_packet = OnionDataResponsePayload {
            real_pk: alice_pk,
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&nonce, &shared_secret);
        assert!(decoded_payload.is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_packet = OnionDataResponsePayload {
            real_pk: alice_pk,
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&nonce, &shared_secret);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn onion_data_response_payload_encrypt_decrypt_friend_request() {
        crypto_init().unwrap();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let nonce = gen_nonce();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let friend_request = FriendRequest::new(NoSpam::random(), "1234".to_owned());
        let payload = OnionDataResponseInnerPayload::FriendRequest(friend_request);
        // encode payload
        let packet = OnionDataResponsePayload::new(&shared_secret, alice_pk, &nonce, &payload);
        // decode payload
        let decoded_payload = packet.get_payload(&nonce, &shared_secret).unwrap();
        assert_eq!(payload, decoded_payload);
    }
}
