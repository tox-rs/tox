/*! OnionAnnounceResponse packet with OnionAnnounceResponsePayload
*/

use super::*;

use crate::dht::*;
use crypto_box::SalsaBox;
use tox_binary_io::*;
use tox_crypto::*;

use nom::{
    bytes::complete::tag,
    combinator::{eof, rest, rest_len, success, verify},
    multi::many0,
    number::complete::le_u64,
};

/** It's used to respond to `OnionAnnounceRequest` packet.

sendback_data is the data from `OnionAnnounceRequest` that should be sent in the
response as is. It's used in onion client to match onion response with sent
request.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x84`
`8`      | Data to send back in response
`24`     | `Nonce`
variable | Payload

where payload is encrypted [`OnionAnnounceResponsePayload`](./struct.OnionAnnounceResponsePayload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionAnnounceResponse {
    /// Data to send back in response
    pub sendback_data: u64,
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Encrypted payload
    pub payload: Vec<u8>,
}

impl FromBytes for OnionAnnounceResponse {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = verify(rest_len, |len| *len <= ONION_MAX_PACKET_SIZE)(input)?;
        let (input, _) = tag(&[0x84][..])(input)?;
        let (input, sendback_data) = le_u64(input)?;
        let (input, nonce) = Nonce::from_bytes(input)?;
        let (input, payload) = rest(input)?;
        Ok((
            input,
            OnionAnnounceResponse {
                sendback_data,
                nonce,
                payload: payload.to_vec(),
            },
        ))
    }
}

impl ToBytes for OnionAnnounceResponse {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x84) >>
            gen_le_u64!(self.sendback_data) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice()) >>
            gen_len_limit(ONION_MAX_PACKET_SIZE)
        )
    }
}

impl OnionAnnounceResponse {
    /// Create new `OnionAnnounceResponse` object.
    pub fn new(
        shared_secret: &SalsaBox,
        sendback_data: u64,
        payload: &OnionAnnounceResponsePayload,
    ) -> OnionAnnounceResponse {
        let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
        let mut buf = [0; ONION_MAX_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = shared_secret.encrypt(&nonce, &buf[..size]).unwrap();

        OnionAnnounceResponse {
            sendback_data,
            nonce: nonce.into(),
            payload,
        }
    }

    /** Decrypt payload and try to parse it as `OnionAnnounceResponsePayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `OnionAnnounceResponsePayload`
    */
    pub fn get_payload(&self, shared_secret: &SalsaBox) -> Result<OnionAnnounceResponsePayload, GetPayloadError> {
        let decrypted = shared_secret
            .decrypt((&self.nonce).into(), self.payload.as_slice())
            .map_err(|AeadError| GetPayloadError::decrypt())?;
        match OnionAnnounceResponsePayload::from_bytes(&decrypted) {
            Err(error) => Err(GetPayloadError::deserialize(error, decrypted.clone())),
            Ok((_, inner)) => Ok(inner),
        }
    }
}

/** Unencrypted payload of `OnionAnnounceResponse` packet.

`announce_status` variable contains the result of sent request. It might have
values:

* 0: failed to announce ourselves or find requested node
* 1: requested node is found by its long term `PublicKey`
* 2: we successfully announced ourselves

In case of announce_status is equal to 1 ping_id will contain `PublicKey` that
should be used to send data packets to the requested node. In other cases it
will contain ping id that should be used for announcing ourselves.

Serialized form:

Length   | Content
-------- | ------
`1`      | `announce_status` (aka `is_stored`)
`32`     | Onion ping id or `PublicKey`
`[0, 204]` | Nodes in packed format

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionAnnounceResponsePayload {
    /// Variable that represents result of sent `OnionAnnounceRequest`. Also known
    /// as `is_stored` variable
    pub announce_status: AnnounceStatus,
    /// Onion ping id or PublicKey that should be used to send data packets
    pub ping_id_or_pk: [u8; 32],
    /// Up to 4 closest to the requested PublicKey DHT nodes
    pub nodes: Vec<PackedNode>,
}

impl FromBytes for OnionAnnounceResponsePayload {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, announce_status) = AnnounceStatus::from_bytes(input)?;
        let (input, ping_id_or_pk) = <[u8; 32]>::from_bytes(input)?;
        let (input, nodes) = many0(PackedNode::from_bytes)(input)?;
        let (input, _) = verify(success(nodes.len()), |len| *len <= 4_usize)(input)?;
        let (input, _) = eof(input)?;
        Ok((
            input,
            OnionAnnounceResponsePayload {
                announce_status,
                ping_id_or_pk,
                nodes,
            },
        ))
    }
}

impl ToBytes for OnionAnnounceResponsePayload {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, announce_status| AnnounceStatus::to_bytes(announce_status, buf), &self.announce_status) >>
            gen_slice!(self.ping_id_or_pk.as_ref()) >>
            gen_cond!(
                self.nodes.len() <= 4,
                gen_many_ref!(&self.nodes, |buf, node| PackedNode::to_bytes(node, buf))
            )
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_box::SecretKey;
    use rand::thread_rng;

    use std::net::SocketAddr;

    encode_decode_test!(
        onion_announce_response_encode_decode,
        OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 123]
        }
    );

    encode_decode_test!(
        onion_announce_response_payload_encode_decode,
        OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Found,
            ping_id_or_pk: [42; 32],
            nodes: vec![PackedNode::new(
                SocketAddr::V4("5.6.7.8:12345".parse().unwrap()),
                SecretKey::generate(&mut thread_rng()).public_key()
            )]
        }
    );

    #[test]
    fn onion_announce_response_payload_encrypt_decrypt() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let payload = OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Found,
            ping_id_or_pk: [42; 32],
            nodes: vec![PackedNode::new(
                SocketAddr::V4("5.6.7.8:12345".parse().unwrap()),
                SecretKey::generate(&mut rng).public_key(),
            )],
        };
        // encode payload with shared secret
        let onion_packet = OnionAnnounceResponse::new(&shared_secret, 12345, &payload);
        // decode payload with bob's secret key
        let decoded_payload = onion_packet.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn onion_announce_response_payload_encrypt_decrypt_invalid_key() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let eve_sk = SecretKey::generate(&mut rng);
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let payload = OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Found,
            ping_id_or_pk: [42; 32],
            nodes: vec![PackedNode::new(
                SocketAddr::V4("5.6.7.8:12345".parse().unwrap()),
                SecretKey::generate(&mut rng).public_key(),
            )],
        };
        // encode payload with shared secret
        let onion_packet = OnionAnnounceResponse::new(&shared_secret, 12345, &payload);
        // try to decode payload with eve's secret key
        let eve_shared_secret = SalsaBox::new(&bob_pk, &eve_sk);
        let decoded_payload = onion_packet.get_payload(&eve_shared_secret);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn onion_announce_response_decrypt_invalid() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let nonce = SalsaBox::generate_nonce(&mut rng);
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_onion_announce_response = OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: nonce.into(),
            payload: invalid_payload_encoded,
        };
        assert!(invalid_onion_announce_response.get_payload(&shared_secret).is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_onion_announce_response = OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: nonce.into(),
            payload: invalid_payload_encoded,
        };
        assert!(invalid_onion_announce_response.get_payload(&shared_secret).is_err());
    }
}
