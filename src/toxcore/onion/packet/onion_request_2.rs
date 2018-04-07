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

/*! OnionRequest2 packet with OnionRequest2Payload
*/

use super::*;

use toxcore::binary_io::*;
use toxcore::crypto_core::*;

use std::io::{Error, ErrorKind};

/** Third onion request packet. It's sent from the second to the third node from
onion chain. Payload should be encrypted with temporary generated `SecretKey` and
with DHT `PublicKey` of receiver.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x82`
`24`     | `Nonce`
`32`     | Temporary `PublicKey`
variable | Payload
`118`    | `OnionReturn`

where payload is encrypted [`OnionRequest2Payload`](./struct.OnionRequest2Payload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionRequest2 {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>,
    /// Return address encrypted by the second node from onion chain
    pub onion_return: OnionReturn
}

impl FromBytes for OnionRequest2 {
    named!(from_bytes<OnionRequest2>, do_parse!(
        verify!(rest_len, |len| len <= ONION_MAX_PACKET_SIZE) >>
        tag!(&[0x82][..]) >>
        nonce: call!(Nonce::from_bytes) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        rest_len: rest_len >>
        payload: cond_reduce!(
            rest_len >= ONION_RETURN_2_SIZE,
            take!(rest_len - ONION_RETURN_2_SIZE)
        ) >>
        onion_return: call!(OnionReturn::from_bytes) >>
        (OnionRequest2 {
            nonce,
            temporary_pk,
            payload: payload.to_vec(),
            onion_return
        })
    ));
}

impl ToBytes for OnionRequest2 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x82) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.payload) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return)
        )
    }
}

impl OnionRequest2 {
    /// Create new `OnionRequest2` object.
    pub fn new(shared_secret: &PrecomputedKey, temporary_pk: &PublicKey, payload: OnionRequest2Payload, onion_return: OnionReturn) -> OnionRequest2 {
        let nonce = gen_nonce();
        let mut buf = [0; ONION_MAX_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        OnionRequest2 { nonce, temporary_pk: *temporary_pk, payload, onion_return }
    }

    /** Decrypt payload and try to parse it as `OnionRequest2Payload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `OnionRequest2Payload`
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<OnionRequest2Payload, Error> {
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|e| {
                debug!("Decrypting OnionRequest2 failed!");
                Error::new(ErrorKind::Other,
                    format!("OnionRequest2 decrypt error: {:?}", e))
            })?;
        match OnionRequest2Payload::from_bytes(&decrypted) {
            IResult::Incomplete(e) => {
                error!(target: "Onion", "OnionRequest2Payload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("OnionRequest2Payload deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                error!(target: "Onion", "OnionRequest2Payload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("OnionRequest2Payload deserialize error: {:?}", e)))
            },
            IResult::Done(_, inner) => {
                Ok(inner)
            }
        }
    }
}

/** Unencrypted payload of `OnionRequest1` packet.

Inner payload should be sent as DHT packet to the next node with address from
`ip_port` field.

Serialized form:

Length   | Content
-------- | ------
`19`     | `IpPort` of the next node
`32`     | Temporary `PublicKey`
variable | Payload

where payload is encrypted [`InnerOnionRequest`](./enum.InnerOnionRequest.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionRequest2Payload {
    /// Address of the next node in the onion path
    pub ip_port: IpPort,
    /// Inner onion request
    pub inner: InnerOnionRequest
}

impl FromBytes for OnionRequest2Payload {
    named!(from_bytes<OnionRequest2Payload>, do_parse!(
        ip_port: call!(IpPort::from_bytes) >>
        inner: call!(InnerOnionRequest::from_bytes) >>
        eof!() >>
        (OnionRequest2Payload {
            ip_port,
            inner
        })
    ));
}

impl ToBytes for OnionRequest2Payload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, ip_port| IpPort::to_bytes(ip_port, buf), &self.ip_port) >>
            gen_call!(|buf, inner| InnerOnionRequest::to_bytes(inner, buf), &self.inner)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION_RETURN_2_PAYLOAD_SIZE: usize = ONION_RETURN_2_SIZE - NONCEBYTES;

    encode_decode_test!(
        onion_request_2_encode_decode,
        OnionRequest2 {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42, 123],
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
            }
        }
    );

    encode_decode_test!(
        onion_request_2_payload_encode_decode,
        OnionRequest2Payload {
            ip_port: IpPort {
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            inner: InnerOnionRequest::InnerOnionDataRequest(InnerOnionDataRequest {
                destination_pk: gen_keypair().0,
                nonce: gen_nonce(),
                temporary_pk: gen_keypair().0,
                payload: vec![42, 123]
            })
        }
    );

    #[test]
    fn onion_request_2_payload_encrypt_decrypt() {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = OnionRequest2Payload {
            ip_port: IpPort {
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            inner: InnerOnionRequest::InnerOnionDataRequest(InnerOnionDataRequest {
                destination_pk: gen_keypair().0,
                nonce: gen_nonce(),
                temporary_pk: gen_keypair().0,
                payload: vec![42, 123]
            })
        };
        let onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
        };
        // encode payload with shared secret
        let onion_packet = OnionRequest2::new(&shared_secret, &alice_pk, payload.clone(), onion_return);
        // decode payload with bob's secret key
        let decoded_payload = onion_packet.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn onion_request_2_payload_encrypt_decrypt_invalid_key() {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = OnionRequest2Payload {
            ip_port: IpPort {
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            inner: InnerOnionRequest::InnerOnionDataRequest(InnerOnionDataRequest {
                destination_pk: gen_keypair().0,
                nonce: gen_nonce(),
                temporary_pk: gen_keypair().0,
                payload: vec![42, 123]
            })
        };
        let onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
        };
        // encode payload with shared secret
        let onion_packet = OnionRequest2::new(&shared_secret, &alice_pk, payload.clone(), onion_return);
        // try to decode payload with eve's secret key
        let eve_shared_secret = encrypt_precompute(&bob_pk, &eve_sk);
        let decoded_payload = onion_packet.get_payload(&eve_shared_secret);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn onion_request_2_decrypt_invalid() {
        let symmetric_key = new_symmetric_key();
        let nonce = gen_nonce();
        let temporary_pk = gen_keypair().0;
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_onion_request_2 = OnionRequest2 {
            nonce,
            temporary_pk,
            payload: invalid_payload_encoded,
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
            }
        };
        assert!(invalid_onion_request_2.get_payload(&symmetric_key).is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_onion_request_2 = OnionRequest2 {
            nonce,
            temporary_pk,
            payload: invalid_payload_encoded,
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
            }
        };
        assert!(invalid_onion_request_2.get_payload(&symmetric_key).is_err());
    }
}
