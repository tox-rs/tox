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

/*! AnnounceRequest packet with AnnounceRequestPayload
*/

use super::*;

use toxcore::binary_io::*;
use toxcore::crypto_core::*;

use nom::{le_u64, rest};
use std::io::{Error, ErrorKind};

/** It's used for announcing ourselves to onion node and for looking for other
announced nodes.

If we want to announce ourselves we should send one `AnnounceRequest` packet with
PingId set to 0 to acquire correct PingId of onion node. Then using this PingId
we can send another `AnnounceRequest` to be added to onion nodes list. If
`AnnounceRequest` succeed we will get `AnnounceResponse` with announce_status
set to 2. Otherwise announce_status will be set to 0.

If we are looking for another node we should send `AnnounceRequest` packet with
PingId set to 0 and with `PublicKey` of this node. If node is found we will get
`AnnounceResponse` with announce_status set to 1. Otherwise announce_status will
be set to 0.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x83`
`24`     | `Nonce`
`32`     | Temporary or real `PublicKey`
variable | Payload

where payload is encrypted [`AnnounceRequestPayload`](./struct.AnnounceRequestPayload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InnerAnnounceRequest {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary or real `PublicKey` for the current encrypted payload
    pub pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for InnerAnnounceRequest {
    named!(from_bytes<InnerAnnounceRequest>, do_parse!(
        tag!(&[0x83][..]) >>
        nonce: call!(Nonce::from_bytes) >>
        pk: call!(PublicKey::from_bytes) >>
        payload: rest >>
        (InnerAnnounceRequest {
            nonce,
            pk,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for InnerAnnounceRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x83) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.payload)
        )
    }
}

impl InnerAnnounceRequest {
    /// Create new `InnerAnnounceRequest` object.
    pub fn new(shared_secret: &PrecomputedKey, pk: &PublicKey, payload: AnnounceRequestPayload) -> InnerAnnounceRequest {
        let nonce = gen_nonce();
        let mut buf = [0; ONION_MAX_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        InnerAnnounceRequest { nonce, pk: *pk, payload }
    }

    /** Decrypt payload and try to parse it as `AnnounceRequestPayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `AnnounceRequestPayload`
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<AnnounceRequestPayload, Error> {
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|()| {
                debug!("Decrypting AnnounceRequest failed!");
                Error::new(ErrorKind::Other, "AnnounceRequest decrypt error.")
            })?;
        match AnnounceRequestPayload::from_bytes(&decrypted) {
            IResult::Incomplete(e) => {
                debug!(target: "Onion", "AnnounceRequestPayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("AnnounceRequestPayload deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                debug!(target: "Onion", "AnnounceRequestPayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("AnnounceRequestPayload deserialize error: {:?}", e)))
            },
            IResult::Done(_, inner) => {
                Ok(inner)
            }
        }
    }
}

/** Same as `InnerAnnounceRequest` but with `OnionReturn` addresses. It's sent
from the third node from onion chain to the destination node.

See [`InnerAnnounceRequest`](./struct.InnerAnnounceRequest.html) for additional docs.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x83`
`24`     | `Nonce`
`32`     | Temporary or real `PublicKey`
variable | Payload
`177`    | `OnionReturn`

where payload is encrypted [`AnnounceRequestPayload`](./struct.AnnounceRequestPayload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnounceRequest {
    /// Inner announce request that was enclosed in onion packets
    pub inner: InnerAnnounceRequest,
    /// Return address encrypted by the third node from onion chain
    pub onion_return: OnionReturn
}

impl FromBytes for AnnounceRequest {
    named!(from_bytes<AnnounceRequest>, do_parse!(
        rest_len: verify!(rest_len, |len| len <= ONION_MAX_PACKET_SIZE) >>
        inner: cond_reduce!(
            rest_len >= ONION_RETURN_3_SIZE,
            flat_map!(take!(rest_len - ONION_RETURN_3_SIZE), InnerAnnounceRequest::from_bytes)
        ) >>
        onion_return: call!(OnionReturn::from_bytes) >>
        (AnnounceRequest { inner, onion_return })
    ));
}

impl ToBytes for AnnounceRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, inner| InnerAnnounceRequest::to_bytes(inner, buf), &self.inner) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return) >>
            gen_len_limit(ONION_MAX_PACKET_SIZE)
        )
    }
}

/** Unencrypted payload of `AnnounceRequest` packet.

Serialized form:

Length   | Content
-------- | ------
`32`     | Onion ping id
`32`     | `PublicKey` we are searching for
`32`     | `PublicKey` that should be used for sending data packets
`8`      | Data to send back in the response

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnounceRequestPayload {
    /// Onion ping id
    pub ping_id: Digest,
    /// `PublicKey` we are searching for
    pub search_pk: PublicKey,
    /// `PublicKey` that should be used for sending data packets
    pub data_pk: PublicKey,
    /// Data to send back in the response
    pub sendback_data: u64
}

impl FromBytes for AnnounceRequestPayload {
    named!(from_bytes<AnnounceRequestPayload>, do_parse!(
        ping_id: call!(Digest::from_bytes) >>
        search_pk: call!(PublicKey::from_bytes) >>
        data_pk: call!(PublicKey::from_bytes) >>
        sendback_data: le_u64 >>
        eof!() >>
        (AnnounceRequestPayload { ping_id, search_pk, data_pk, sendback_data })
    ));
}

impl ToBytes for AnnounceRequestPayload {
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

    const ONION_RETURN_3_PAYLOAD_SIZE: usize = ONION_RETURN_3_SIZE - NONCEBYTES;

    encode_decode_test!(
        inner_announce_request_encode_decode,
        InnerAnnounceRequest {
            nonce: gen_nonce(),
            pk: gen_keypair().0,
            payload: vec![42, 123]
        }
    );

    encode_decode_test!(
        announce_request_encode_decode,
        AnnounceRequest {
            inner: InnerAnnounceRequest {
                nonce: gen_nonce(),
                pk: gen_keypair().0,
                payload: vec![42, 123]
            },
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
            }
        }
    );

    encode_decode_test!(
        announce_request_payload_encode_decode,
        AnnounceRequestPayload {
            ping_id: hash(&[1, 2, 3]),
            search_pk: gen_keypair().0,
            data_pk: gen_keypair().0,
            sendback_data: 12345
        }
    );

    #[test]
    fn announce_request_payload_encrypt_decrypt() {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = AnnounceRequestPayload {
            ping_id: hash(&[1, 2, 3]),
            search_pk: gen_keypair().0,
            data_pk: gen_keypair().0,
            sendback_data: 12345
        };
        // encode payload with shared secret
        let onion_packet = InnerAnnounceRequest::new(&shared_secret, &alice_pk, payload.clone());
        // decode payload with bob's secret key
        let decoded_payload = onion_packet.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn announce_request_payload_encrypt_decrypt_invalid_key() {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = AnnounceRequestPayload {
            ping_id: hash(&[1, 2, 3]),
            search_pk: gen_keypair().0,
            data_pk: gen_keypair().0,
            sendback_data: 12345
        };
        // encode payload with shared secret
        let onion_packet = InnerAnnounceRequest::new(&shared_secret, &alice_pk, payload.clone());
        // try to decode payload with eve's secret key
        let eve_shared_secret = encrypt_precompute(&bob_pk, &eve_sk);
        let decoded_payload = onion_packet.get_payload(&eve_shared_secret);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn announce_request_decrypt_invalid() {
        let symmetric_key = new_symmetric_key();
        let nonce = gen_nonce();
        let pk = gen_keypair().0;
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_announce_request = InnerAnnounceRequest {
            nonce,
            pk,
            payload: invalid_payload_encoded
        };
        assert!(invalid_announce_request.get_payload(&symmetric_key).is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_announce_request = InnerAnnounceRequest {
            nonce,
            pk,
            payload: invalid_payload_encoded
        };
        assert!(invalid_announce_request.get_payload(&symmetric_key).is_err());
    }
}
