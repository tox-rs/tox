/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2018 Evgeny Kurnevsky <kurnevsky@gmail.com>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

/*! AnnounceResponse packet with AnnounceResponsePayload
*/

use super::*;

use toxcore::binary_io::*;
use toxcore::crypto_core::*;

use nom::{le_u64, rest};
use std::io::{Error, ErrorKind};

/** It's used to respond to AnnounceRequest packet.

sendback_data is the data from `AnnounceRequest` that should be sent in the
response as is. It's used in onion client to match onion response with sent
request.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x84`
`8`      | Data to send back in response
`24`     | `Nonce`
variable | Payload

where payload is encrypted [`AnnounceResponsePayload`](./struct.AnnounceResponsePayload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnounceResponse {
    /// Data to send back in response
    pub sendback_data: u64,
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for AnnounceResponse {
    named!(from_bytes<AnnounceResponse>, do_parse!(
        tag!(&[0x84][..]) >>
        sendback_data: le_u64 >>
        nonce: call!(Nonce::from_bytes) >>
        payload: rest >>
        (AnnounceResponse {
            sendback_data,
            nonce,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for AnnounceResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x84) >>
            gen_le_u64!(self.sendback_data) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload)
        )
    }
}

impl AnnounceResponse {
    /// Create new `AnnounceResponse` object.
    pub fn new(shared_secret: &PrecomputedKey, sendback_data: u64, payload: AnnounceResponsePayload) -> AnnounceResponse {
        let nonce = gen_nonce();
        let mut buf = [0; ONION_MAX_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        AnnounceResponse { sendback_data, nonce, payload }
    }

    /** Decrypt payload and try to parse it as `AnnounceResponsePayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `AnnounceResponsePayload`
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<AnnounceResponsePayload, Error> {
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|e| {
                debug!("Decrypting AnnounceResponse failed!");
                Error::new(ErrorKind::Other,
                    format!("AnnounceResponse decrypt error: {:?}", e))
            })?;
        match AnnounceResponsePayload::from_bytes(&decrypted) {
            IResult::Incomplete(e) => {
                debug!(target: "Onion", "AnnounceResponsePayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("AnnounceResponsePayload deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                debug!(target: "Onion", "AnnounceResponsePayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("AnnounceResponsePayload deserialize error: {:?}", e)))
            },
            IResult::Done(_, inner) => {
                Ok(inner)
            }
        }
    }
}

/** Unencrypted payload of `AnnounceResponse` packet.

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
pub struct AnnounceResponsePayload {
    /// Variable that represents result of sent `AnnounceRequest`. Also known
    /// as `is_stored` variable
    pub announce_status: AnnounceStatus,
    /// Onion ping id or PublicKey that should be used to send data packets
    pub ping_id_or_pk: Digest,
    /// Up to 4 closest to the requested PublicKey DHT nodes
    pub nodes: Vec<PackedNode>
}

impl FromBytes for AnnounceResponsePayload {
    named!(from_bytes<AnnounceResponsePayload>, do_parse!(
        announce_status: call!(AnnounceStatus::from_bytes) >>
        ping_id_or_pk: call!(Digest::from_bytes) >>
        nodes: many0!(PackedNode::from_bytes) >>
        cond_reduce!(nodes.len() <= 4, eof!()) >>
        (AnnounceResponsePayload {
            announce_status,
            ping_id_or_pk,
            nodes
        })
    ));
}

impl ToBytes for AnnounceResponsePayload {
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
        announce_response_encode_decode,
        AnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42, 123]
        }
    );

    encode_decode_test!(
        announce_response_payload_encode_decode,
        AnnounceResponsePayload {
            announce_status: AnnounceStatus::Found,
            ping_id_or_pk: hash(&[1, 2, 3]),
            nodes: vec![
                PackedNode::new(false, SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &gen_keypair().0)
            ]
        }
    );

    #[test]
    fn announce_response_payload_encrypt_decrypt() {
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = AnnounceResponsePayload {
            announce_status: AnnounceStatus::Found,
            ping_id_or_pk: hash(&[1, 2, 3]),
            nodes: vec![
                PackedNode::new(false, SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &gen_keypair().0)
            ]
        };
        // encode payload with shared secret
        let onion_packet = AnnounceResponse::new(&shared_secret, 12345, payload.clone());
        // decode payload with bob's secret key
        let decoded_payload = onion_packet.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn announce_response_payload_encrypt_decrypt_invalid_key() {
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = AnnounceResponsePayload {
            announce_status: AnnounceStatus::Found,
            ping_id_or_pk: hash(&[1, 2, 3]),
            nodes: vec![
                PackedNode::new(false, SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &gen_keypair().0)
            ]
        };
        // encode payload with shared secret
        let onion_packet = AnnounceResponse::new(&shared_secret, 12345, payload.clone());
        // try to decode payload with eve's secret key
        let eve_shared_secret = encrypt_precompute(&bob_pk, &eve_sk);
        let decoded_payload = onion_packet.get_payload(&eve_shared_secret);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn announce_response_decrypt_invalid() {
        let symmetric_key = new_symmetric_key();
        let nonce = gen_nonce();
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_announce_response = AnnounceResponse {
            sendback_data: 12345,
            nonce,
            payload: invalid_payload_encoded
        };
        assert!(invalid_announce_response.get_payload(&symmetric_key).is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_announce_response = AnnounceResponse {
            sendback_data: 12345,
            nonce,
            payload: invalid_payload_encoded
        };
        assert!(invalid_announce_response.get_payload(&symmetric_key).is_err());
    }
}
