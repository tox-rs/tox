/*! OnionDataRequest packet
*/

use super::*;

use tox_binary_io::*;
use tox_crypto::*;
use crate::dht::*;
use crate::onion::MAX_ONION_RESPONSE_PAYLOAD_SIZE;

use nom::{
    combinator::{rest, rest_len, map_parser, verify},
    bytes::complete::{take, tag},
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
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag(&[0x85][..])(input)?;
        let (input, destination_pk) = PublicKey::from_bytes(input)?;
        let (input, nonce) = Nonce::from_bytes(input)?;
        let (input, temporary_pk) = PublicKey::from_bytes(input)?;
        let (input, payload) = rest(input)?;
        Ok((input, InnerOnionDataRequest {
            destination_pk,
            nonce,
            temporary_pk,
            payload: payload.to_vec()
        }))
    }
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
        shared_secret: &SalsaBox,
        destination_pk: PublicKey,
        temporary_pk: PublicKey,
        nonce: Nonce,
        payload: &OnionDataResponsePayload
    ) -> InnerOnionDataRequest {
        let mut buf = [0; MAX_ONION_RESPONSE_PAYLOAD_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = shared_secret.encrypt((&nonce).into(), &buf[..size]).unwrap();

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
    pub fn get_payload(&self, shared_secret: &SalsaBox) -> Result<OnionDataResponsePayload, GetPayloadError> {
        let decrypted = shared_secret.decrypt((&self.nonce).into(), self.payload.as_slice())
            .map_err(|AeadError| {
                GetPayloadError::decrypt()
            })?;
        match OnionDataResponsePayload::from_bytes(&decrypted) {
            Err(error) => {
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
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, rest_len) = verify(rest_len, |len| *len <= ONION_MAX_PACKET_SIZE && *len >= ONION_RETURN_3_SIZE)(input)?;
        let (input, inner) = map_parser(take(rest_len - ONION_RETURN_3_SIZE), InnerOnionDataRequest::from_bytes)(input)?;
        let (input, onion_return) = OnionReturn::from_bytes(input)?;
        Ok((input, OnionDataRequest { inner, onion_return }))
    }
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
    use crypto_box::aead::generic_array::typenum::marker_traits::Unsigned;
    use rand::thread_rng;

    const ONION_RETURN_3_PAYLOAD_SIZE: usize = ONION_RETURN_3_SIZE - xsalsa20poly1305::NONCE_SIZE;

    encode_decode_test!(
        inner_onion_data_request_encode_decode,
        InnerOnionDataRequest {
            destination_pk: SecretKey::generate(&mut thread_rng()).public_key(),
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            temporary_pk: SecretKey::generate(&mut thread_rng()).public_key(),
            payload: vec![42; 123]
        }
    );

    encode_decode_test!(
        onion_data_request_encode_decode,
        OnionDataRequest {
            inner: InnerOnionDataRequest {
                destination_pk: SecretKey::generate(&mut thread_rng()).public_key(),
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                temporary_pk: SecretKey::generate(&mut thread_rng()).public_key(),
                payload: vec![42; 123]
            },
            onion_return: OnionReturn {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
            }
        }
    );

    #[test]
    fn inner_onion_data_request_encrypt_decrypt() {
        let mut rng = thread_rng();
        let real_pk = SecretKey::generate(&mut rng).public_key();
        let data_pk = SecretKey::generate(&mut rng).public_key();
        let temporary_sk = SecretKey::generate(&mut rng);
        let temporary_pk = temporary_sk.public_key();
        let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
        let shared_secret = SalsaBox::new(&data_pk, &temporary_sk);
        let payload = OnionDataResponsePayload {
            real_pk: SecretKey::generate(&mut rng).public_key(),
            payload: vec![42; 123],
        };
        // encode payload with shared secret
        let packet = InnerOnionDataRequest::new(&shared_secret, real_pk, temporary_pk, nonce.into(), &payload);
        // decode payload with shared secret
        let decoded_payload = packet.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn inner_onion_data_request_encrypt_decrypt_invalid_key() {
        let mut rng = thread_rng();
        let real_pk = SecretKey::generate(&mut rng).public_key();
        let data_pk = SecretKey::generate(&mut rng).public_key();
        let temporary_sk = SecretKey::generate(&mut rng);
        let temporary_pk = temporary_sk.public_key();
        let invalid_sk = SecretKey::generate(&mut rng);
        let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
        let shared_secret = SalsaBox::new(&data_pk, &temporary_sk);
        let shared_secret_invalid = SalsaBox::new(&temporary_pk, &invalid_sk);
        let payload = OnionDataResponsePayload {
            real_pk: SecretKey::generate(&mut rng).public_key(),
            payload: vec![42; 123],
        };
        // encode payload with shared secret
        let packet = InnerOnionDataRequest::new(&shared_secret, real_pk, temporary_pk, nonce.into(), &payload);
        // try to decode payload with invalid shared secret
        let decoded_payload = packet.get_payload(&shared_secret_invalid);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn inner_onion_data_request_encrypt_decrypt_invalid() {
        let mut rng = thread_rng();
        let real_pk = SecretKey::generate(&mut rng).public_key();
        let data_pk = SecretKey::generate(&mut rng).public_key();
        let temporary_sk = SecretKey::generate(&mut rng);
        let temporary_pk = temporary_sk.public_key();
        let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
        let shared_secret = SalsaBox::new(&data_pk, &temporary_sk);
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_packet = InnerOnionDataRequest {
            destination_pk: real_pk,
            nonce: nonce.into(),
            temporary_pk,
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&shared_secret);
        assert!(decoded_payload.is_err());
    }
}
