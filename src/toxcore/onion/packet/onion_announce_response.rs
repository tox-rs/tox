/*! OnionAnnounceResponse packet with OnionAnnounceResponsePayload
*/

use super::*;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packet::*;

use nom::{
    number::complete::le_u64,
    combinator::{rest, rest_len},
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
    pub payload: Vec<u8>
}

impl FromBytes for OnionAnnounceResponse {
    named!(from_bytes<OnionAnnounceResponse>, do_parse!(
        verify!(rest_len, |len| *len <= ONION_MAX_PACKET_SIZE) >>
        tag!(&[0x84][..]) >>
        sendback_data: le_u64 >>
        nonce: call!(Nonce::from_bytes) >>
        payload: rest >>
        (OnionAnnounceResponse {
            sendback_data,
            nonce,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for OnionAnnounceResponse {
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
    pub fn new(shared_secret: &PrecomputedKey, sendback_data: u64, payload: &OnionAnnounceResponsePayload) -> OnionAnnounceResponse {
        let nonce = gen_nonce();
        let mut buf = [0; ONION_MAX_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        OnionAnnounceResponse { sendback_data, nonce, payload }
    }

    /** Decrypt payload and try to parse it as `OnionAnnounceResponsePayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `OnionAnnounceResponsePayload`
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<OnionAnnounceResponsePayload, GetPayloadError> {
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|()| {
                debug!("Decrypting OnionAnnounceResponse failed!");
                GetPayloadError::decrypt()
            })?;
        match OnionAnnounceResponsePayload::from_bytes(&decrypted) {
            Err(error) => {
                debug!(target: "Onion", "OnionAnnounceResponsePayload deserialize error: {:?}", error);
                Err(GetPayloadError::deserialize(error, decrypted.clone()))
            },
            Ok((_, inner)) => {
                Ok(inner)
            }
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
    pub ping_id_or_pk: sha256::Digest,
    /// Up to 4 closest to the requested PublicKey DHT nodes
    pub nodes: Vec<PackedNode>
}

impl FromBytes for OnionAnnounceResponsePayload {
    named!(from_bytes<OnionAnnounceResponsePayload>, do_parse!(
        announce_status: call!(AnnounceStatus::from_bytes) >>
        ping_id_or_pk: call!(sha256::Digest::from_bytes) >>
        nodes: many0!(PackedNode::from_bytes) >>
        _len: verify!(value!(nodes.len()), |len| *len <= 4 as usize) >>
        eof!() >>
        (OnionAnnounceResponsePayload {
            announce_status,
            ping_id_or_pk,
            nodes
        })
    ));
}

impl ToBytes for OnionAnnounceResponsePayload {
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

    use std::net::SocketAddr;

    encode_decode_test!(
        onion_announce_response_encode_decode,
        OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42; 123]
        }
    );

    encode_decode_test!(
        onion_announce_response_payload_encode_decode,
        OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Found,
            ping_id_or_pk: sha256::hash(&[1, 2, 3]),
            nodes: vec![
                PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &gen_keypair().0)
            ]
        }
    );

    #[test]
    fn onion_announce_response_payload_encrypt_decrypt() {
        crypto_init().unwrap();
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Found,
            ping_id_or_pk: sha256::hash(&[1, 2, 3]),
            nodes: vec![
                PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &gen_keypair().0)
            ]
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
        crypto_init().unwrap();
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Found,
            ping_id_or_pk: sha256::hash(&[1, 2, 3]),
            nodes: vec![
                PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &gen_keypair().0)
            ]
        };
        // encode payload with shared secret
        let onion_packet = OnionAnnounceResponse::new(&shared_secret, 12345, &payload);
        // try to decode payload with eve's secret key
        let eve_shared_secret = encrypt_precompute(&bob_pk, &eve_sk);
        let decoded_payload = onion_packet.get_payload(&eve_shared_secret);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn onion_announce_response_decrypt_invalid() {
        crypto_init().unwrap();
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_onion_announce_response = OnionAnnounceResponse {
            sendback_data: 12345,
            nonce,
            payload: invalid_payload_encoded
        };
        assert!(invalid_onion_announce_response.get_payload(&shared_secret).is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_onion_announce_response = OnionAnnounceResponse {
            sendback_data: 12345,
            nonce,
            payload: invalid_payload_encoded
        };
        assert!(invalid_onion_announce_response.get_payload(&shared_secret).is_err());
    }
}
