/*! OnionDataRequest packet
*/

use super::*;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packet::*;
use crate::toxcore::onion::packet::MAX_ONION_RESPONSE_PAYLOAD_SIZE;

use nom::{
    combinator::{rest, rest_len},
    bytes::complete::take,
};

/** It's used to send data requests to dht node using onion paths.

When DHT node receives `OnionDataRequest` it sends `OnionDataResponse` to
destination node for which data request is intended. Thus, data request will
go through 7 intermediate nodes until destination node gets it - 3 nodes with
OnionRequests, onion node that handles `OnionDataRequest` and 3 nodes with
OnionResponses.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x85`
`32`     | `PublicKey` of destination node
`24`     | `Nonce`
`32`     | Temporary `PublicKey`
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InnerOnionDataRequest {
    /// `PublicKey` of destination node
    pub destination_pk: PublicKey,
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for InnerOnionDataRequest {
    named!(from_bytes<InnerOnionDataRequest>, do_parse!(
        tag!(&[0x85][..]) >>
        destination_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        payload: rest >>
        (InnerOnionDataRequest {
            destination_pk,
            nonce,
            temporary_pk,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for InnerOnionDataRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x85) >>
            gen_slice!(self.destination_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl InnerOnionDataRequest {
    /// Create `InnerOnionDataRequest` from `OnionDataResponsePayload`
    /// encrypting it with `shared_key` and `nonce`
    pub fn new(
        shared_secret: &PrecomputedKey,
        destination_pk: PublicKey,
        temporary_pk: PublicKey,
        nonce: Nonce,
        payload: &OnionDataResponsePayload
    ) -> InnerOnionDataRequest {
        let mut buf = [0; MAX_ONION_RESPONSE_PAYLOAD_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        InnerOnionDataRequest {
            destination_pk,
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

/** Same as `InnerOnionDataRequest` but with `OnionReturn` addresses. It's sent
from the third node from onion chain to the destination node.

See [`InnerOnionDataRequest`](./struct.InnerOnionDataRequest.html) for additional docs.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x85`
`32`     | `PublicKey` of destination node
`24`     | `Nonce`
`32`     | Temporary `PublicKey`
variable | Payload
`177`    | `OnionReturn`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionDataRequest {
    /// Inner onion data request that was enclosed in onion packets
    pub inner: InnerOnionDataRequest,
    /// Return address encrypted by the third node from onion chain
    pub onion_return: OnionReturn
}

impl FromBytes for OnionDataRequest {
    named!(from_bytes<OnionDataRequest>, do_parse!(
        rest_len: verify!(rest_len, |len| *len <= ONION_MAX_PACKET_SIZE && *len >= ONION_RETURN_3_SIZE) >>
        inner: flat_map!(take(rest_len - ONION_RETURN_3_SIZE), InnerOnionDataRequest::from_bytes) >>
        onion_return: call!(OnionReturn::from_bytes) >>
        (OnionDataRequest { inner, onion_return })
    ));
}

impl ToBytes for OnionDataRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, inner| InnerOnionDataRequest::to_bytes(inner, buf), &self.inner) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return) >>
            gen_len_limit(ONION_MAX_PACKET_SIZE)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION_RETURN_3_PAYLOAD_SIZE: usize = ONION_RETURN_3_SIZE - secretbox::NONCEBYTES;

    encode_decode_test!(
        inner_onion_data_request_encode_decode,
        InnerOnionDataRequest {
            destination_pk: gen_keypair().0,
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123]
        }
    );

    encode_decode_test!(
        onion_data_request_encode_decode,
        OnionDataRequest {
            inner: InnerOnionDataRequest {
                destination_pk: gen_keypair().0,
                nonce: gen_nonce(),
                temporary_pk: gen_keypair().0,
                payload: vec![42; 123]
            },
            onion_return: OnionReturn {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
            }
        }
    );

    #[test]
    fn inner_onion_data_request_encrypt_decrypt() {
        crypto_init().unwrap();
        let (real_pk, _real_sk) = gen_keypair();
        let (data_pk, _data_sk) = gen_keypair();
        let (temporary_pk, temporary_sk) = gen_keypair();
        let nonce = gen_nonce();
        let shared_secret = encrypt_precompute(&data_pk, &temporary_sk);
        let payload = OnionDataResponsePayload {
            real_pk: gen_keypair().0,
            payload: vec![42; 123],
        };
        // encode payload with shared secret
        let packet = InnerOnionDataRequest::new(&shared_secret, real_pk, temporary_pk, nonce, &payload);
        // decode payload with shared secret
        let decoded_payload = packet.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn inner_onion_data_request_encrypt_decrypt_invalid_key() {
        crypto_init().unwrap();
        let (real_pk, _real_sk) = gen_keypair();
        let (data_pk, _data_sk) = gen_keypair();
        let (temporary_pk, temporary_sk) = gen_keypair();
        let (_invalid_pk, invalid_sk) = gen_keypair();
        let nonce = gen_nonce();
        let shared_secret = encrypt_precompute(&data_pk, &temporary_sk);
        let shared_secret_invalid = encrypt_precompute(&temporary_pk, &invalid_sk);
        let payload = OnionDataResponsePayload {
            real_pk: gen_keypair().0,
            payload: vec![42; 123],
        };
        // encode payload with shared secret
        let packet = InnerOnionDataRequest::new(&shared_secret, real_pk, temporary_pk, nonce, &payload);
        // try to decode payload with invalid shared secret
        let decoded_payload = packet.get_payload(&shared_secret_invalid);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn inner_onion_data_request_encrypt_decrypt_invalid() {
        crypto_init().unwrap();
        let (real_pk, _real_sk) = gen_keypair();
        let (data_pk, _data_sk) = gen_keypair();
        let (temporary_pk, temporary_sk) = gen_keypair();
        let nonce = gen_nonce();
        let shared_secret = encrypt_precompute(&data_pk, &temporary_sk);
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_packet = InnerOnionDataRequest {
            destination_pk: real_pk,
            nonce,
            temporary_pk,
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&shared_secret);
        assert!(decoded_payload.is_err());
    }
}
