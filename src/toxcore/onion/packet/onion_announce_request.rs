/*! OnionAnnounceRequest packet with OnionAnnounceRequestPayload
*/

use super::*;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packet::*;

use nom::{
    number::complete::le_u64,
    combinator::{rest, rest_len},
    bytes::complete::take
};

/** It's used for announcing ourselves to onion node and for looking for other
announced nodes.

If we want to announce ourselves we should send one `OnionAnnounceRequest`
packet with PingId set to 0 to acquire correct PingId of onion node. Then using
this PingId we can send another `OnionAnnounceRequest` to be added to onion
nodes list. If `OnionAnnounceRequest` succeed we will get
`OnionAnnounceResponse` with announce_status set to 2. Otherwise announce_status
will be set to 0.

If we are looking for another node we should send `OnionAnnounceRequest` packet
with PingId set to 0 and with `PublicKey` of this node. If node is found we will
get `OnionAnnounceResponse` with announce_status set to 1. Otherwise
announce_status will be set to 0.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x83`
`24`     | `Nonce`
`32`     | Temporary or real `PublicKey`
variable | Payload

where payload is encrypted [`OnionAnnounceRequestPayload`](./struct.OnionAnnounceRequestPayload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InnerOnionAnnounceRequest {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary or real `PublicKey` for the current encrypted payload
    pub pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for InnerOnionAnnounceRequest {
    named!(from_bytes<InnerOnionAnnounceRequest>, do_parse!(
        tag!(&[0x83][..]) >>
        nonce: call!(Nonce::from_bytes) >>
        pk: call!(PublicKey::from_bytes) >>
        payload: rest >>
        (InnerOnionAnnounceRequest {
            nonce,
            pk,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for InnerOnionAnnounceRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x83) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl InnerOnionAnnounceRequest {
    /// Create new `InnerOnionAnnounceRequest` object.
    pub fn new(shared_secret: &PrecomputedKey, pk: &PublicKey, payload: &OnionAnnounceRequestPayload) -> InnerOnionAnnounceRequest {
        let nonce = gen_nonce();
        let mut buf = [0; ONION_MAX_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        InnerOnionAnnounceRequest { nonce, pk: *pk, payload }
    }

    /** Decrypt payload and try to parse it as `OnionAnnounceRequestPayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `OnionAnnounceRequestPayload`
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<OnionAnnounceRequestPayload, GetPayloadError> {
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|()| {
                debug!("Decrypting OnionAnnounceRequest failed!");
                GetPayloadError::decrypt()
            })?;
        match OnionAnnounceRequestPayload::from_bytes(&decrypted) {
            Err(error) => {
                debug!(target: "Onion", "OnionAnnounceRequestPayload deserialize error: {:?}", error);
                Err(GetPayloadError::deserialize(error, decrypted.clone()))
            },
            Ok((_, inner)) => {
                Ok(inner)
            }
        }
    }
}

/** Same as `InnerOnionAnnounceRequest` but with `OnionReturn` addresses. It's sent
from the third node from onion chain to the destination node.

See [`InnerOnionAnnounceRequest`](./struct.InnerOnionAnnounceRequest.html) for additional docs.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x83`
`24`     | `Nonce`
`32`     | Temporary or real `PublicKey`
variable | Payload
`177`    | `OnionReturn`

where payload is encrypted [`OnionAnnounceRequestPayload`](./struct.OnionAnnounceRequestPayload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionAnnounceRequest {
    /// Inner announce request that was enclosed in onion packets
    pub inner: InnerOnionAnnounceRequest,
    /// Return address encrypted by the third node from onion chain
    pub onion_return: OnionReturn
}

impl FromBytes for OnionAnnounceRequest {
    named!(from_bytes<OnionAnnounceRequest>, do_parse!(
        rest_len: verify!(rest_len, |len| *len <= ONION_MAX_PACKET_SIZE && *len >= ONION_RETURN_3_SIZE) >>
        inner: flat_map!(take(rest_len - ONION_RETURN_3_SIZE), InnerOnionAnnounceRequest::from_bytes) >>
        onion_return: call!(OnionReturn::from_bytes) >>
        (OnionAnnounceRequest { inner, onion_return })
    ));
}

impl ToBytes for OnionAnnounceRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, inner| InnerOnionAnnounceRequest::to_bytes(inner, buf), &self.inner) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return) >>
            gen_len_limit(ONION_MAX_PACKET_SIZE)
        )
    }
}

/** Unencrypted payload of `OnionAnnounceRequest` packet.

Serialized form:

Length   | Content
-------- | ------
`32`     | Onion ping id
`32`     | `PublicKey` we are searching for
`32`     | `PublicKey` that should be used for sending data packets
`8`      | Data to send back in the response

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionAnnounceRequestPayload {
    /// Onion ping id
    pub ping_id: sha256::Digest,
    /// `PublicKey` we are searching for
    pub search_pk: PublicKey,
    /// `PublicKey` that should be used for sending data packets
    pub data_pk: PublicKey,
    /// Data to send back in the response
    pub sendback_data: u64
}

impl FromBytes for OnionAnnounceRequestPayload {
    named!(from_bytes<OnionAnnounceRequestPayload>, do_parse!(
        ping_id: call!(sha256::Digest::from_bytes) >>
        search_pk: call!(PublicKey::from_bytes) >>
        data_pk: call!(PublicKey::from_bytes) >>
        sendback_data: le_u64 >>
        eof!() >>
        (OnionAnnounceRequestPayload { ping_id, search_pk, data_pk, sendback_data })
    ));
}

impl ToBytes for OnionAnnounceRequestPayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.ping_id.as_ref()) >>
            gen_slice!(self.search_pk.as_ref()) >>
            gen_slice!(self.data_pk.as_ref()) >>
            gen_le_u64!(self.sendback_data)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION_RETURN_3_PAYLOAD_SIZE: usize = ONION_RETURN_3_SIZE - secretbox::NONCEBYTES;

    encode_decode_test!(
        inner_onion_announce_request_encode_decode,
        InnerOnionAnnounceRequest {
            nonce: gen_nonce(),
            pk: gen_keypair().0,
            payload: vec![42; 123]
        }
    );

    encode_decode_test!(
        onion_announce_request_encode_decode,
        OnionAnnounceRequest {
            inner: InnerOnionAnnounceRequest {
                nonce: gen_nonce(),
                pk: gen_keypair().0,
                payload: vec![42; 123]
            },
            onion_return: OnionReturn {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
            }
        }
    );

    encode_decode_test!(
        onion_announce_request_payload_encode_decode,
        OnionAnnounceRequestPayload {
            ping_id: sha256::hash(&[1, 2, 3]),
            search_pk: gen_keypair().0,
            data_pk: gen_keypair().0,
            sendback_data: 12345
        }
    );

    #[test]
    fn onion_announce_request_payload_encrypt_decrypt() {
        crypto_init().unwrap();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = OnionAnnounceRequestPayload {
            ping_id: sha256::hash(&[1, 2, 3]),
            search_pk: gen_keypair().0,
            data_pk: gen_keypair().0,
            sendback_data: 12345
        };
        // encode payload with shared secret
        let onion_packet = InnerOnionAnnounceRequest::new(&shared_secret, &alice_pk, &payload);
        // decode payload with bob's secret key
        let decoded_payload = onion_packet.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn onion_announce_request_payload_encrypt_decrypt_invalid_key() {
        crypto_init().unwrap();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = OnionAnnounceRequestPayload {
            ping_id: sha256::hash(&[1, 2, 3]),
            search_pk: gen_keypair().0,
            data_pk: gen_keypair().0,
            sendback_data: 12345
        };
        // encode payload with shared secret
        let onion_packet = InnerOnionAnnounceRequest::new(&shared_secret, &alice_pk, &payload);
        // try to decode payload with eve's secret key
        let eve_shared_secret = encrypt_precompute(&bob_pk, &eve_sk);
        let decoded_payload = onion_packet.get_payload(&eve_shared_secret);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn onion_announce_request_decrypt_invalid() {
        crypto_init().unwrap();
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();
        let pk = gen_keypair().0;
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_onion_announce_request = InnerOnionAnnounceRequest {
            nonce,
            pk,
            payload: invalid_payload_encoded
        };
        assert!(invalid_onion_announce_request.get_payload(&shared_secret).is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_onion_announce_request = InnerOnionAnnounceRequest {
            nonce,
            pk,
            payload: invalid_payload_encoded
        };
        assert!(invalid_onion_announce_request.get_payload(&shared_secret).is_err());
    }
}
