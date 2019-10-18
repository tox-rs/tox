/*! OnionRequest0 packet with OnionRequest0Payload
*/

use super::*;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packet::*;

use nom::combinator::{rest, rest_len};

/// Encrypted payload should contain `IpPort`, `PublicKey` and inner encrypted
/// payload that should contain at least `IpPort` struct.
const ONION_REQUEST_0_MIN_PAYLOAD_SIZE: usize = (SIZE_IPPORT + MACBYTES) * 2 + PUBLICKEYBYTES;

/** First onion request packet. It's sent from DHT node to the first node from
onion chain. Payload can be encrypted with either temporary generated
`SecretKey` or DHT `SecretKey` of sender and with DHT `PublicKey` of receiver.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x80`
`24`     | `Nonce`
`32`     | `PublicKey` of sender
variable | Payload

where payload is encrypted [`OnionRequest0Payload`](./struct.OnionRequest0Payload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionRequest0 {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for OnionRequest0 {
    named!(from_bytes<OnionRequest0>, do_parse!(
        verify!(rest_len, |len| *len <= ONION_MAX_PACKET_SIZE) >>
        tag!(&[0x80][..]) >>
        nonce: call!(Nonce::from_bytes) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        payload: verify!(rest, |payload: &[u8]| payload.len() >= ONION_REQUEST_0_MIN_PAYLOAD_SIZE) >>
        (OnionRequest0 {
            nonce,
            temporary_pk,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for OnionRequest0 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_cond!(
                self.payload.len() < ONION_REQUEST_0_MIN_PAYLOAD_SIZE,
                |buf| gen_error(buf, 0)
            ) >>
            gen_be_u8!(0x80) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.payload.as_slice()) >>
            gen_len_limit(ONION_MAX_PACKET_SIZE)
        )
    }
}

impl OnionRequest0 {
    /// Create new `OnionRequest0` object.
    pub fn new(shared_secret: &PrecomputedKey, temporary_pk: &PublicKey, payload: &OnionRequest0Payload) -> OnionRequest0 {
        let nonce = gen_nonce();
        let mut buf = [0; ONION_MAX_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        OnionRequest0 { nonce, temporary_pk: *temporary_pk, payload }
    }

    /** Decrypt payload and try to parse it as `OnionRequest0Payload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `OnionRequest0Payload`
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<OnionRequest0Payload, GetPayloadError> {
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|()| {
                debug!("Decrypting OnionRequest0 failed!");
                GetPayloadError::decrypt()
            })?;
        match OnionRequest0Payload::from_bytes(&decrypted) {
            Err(error) => {
                debug!(target: "Onion", "OnionRequest0Payload deserialize error: {:?}", error);
                Err(GetPayloadError::deserialize(error, decrypted.clone()))
            },
            Ok((_, inner)) => {
                Ok(inner)
            }
        }
    }
}

/** Unencrypted payload of `OnionRequest0` packet.

Inner payload should be sent to the next node with address from `ip_port` field.

Serialized form:

Length   | Content
-------- | ------
`19`     | `IpPort` of the next node
`32`     | Temporary `PublicKey`
variable | Payload

where payload is encrypted [`OnionRequest1Payload`](./struct.OnionRequest1Payload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionRequest0Payload {
    /// Address of the next node in the onion path
    pub ip_port: IpPort,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Inner onion payload
    pub inner: Vec<u8>
}

impl FromBytes for OnionRequest0Payload{
    named!(from_bytes<OnionRequest0Payload>, do_parse!(
        ip_port: call!(IpPort::from_udp_bytes, IpPortPadding::WithPadding) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        inner: rest >>
        (OnionRequest0Payload {
            ip_port,
            temporary_pk,
            inner: inner.to_vec()
        })
    ));
}

impl ToBytes for OnionRequest0Payload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, ip_port| IpPort::to_udp_bytes(ip_port, buf, IpPortPadding::WithPadding), &self.ip_port) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.inner.as_slice())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        onion_request_0_encode_decode,
        OnionRequest0 {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; ONION_REQUEST_0_MIN_PAYLOAD_SIZE]
        }
    );

    encode_decode_test!(
        onion_request_0_payload_encode_decode,
        OnionRequest0Payload {
            ip_port: IpPort {
                protocol: ProtocolType::UDP,
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            temporary_pk: gen_keypair().0,
            inner: vec![42; ONION_REQUEST_0_MIN_PAYLOAD_SIZE]
        }
    );

    #[test]
    fn onion_request_0_payload_encrypt_decrypt() {
        crypto_init().unwrap();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = OnionRequest0Payload {
            ip_port: IpPort {
                protocol: ProtocolType::UDP,
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            temporary_pk: gen_keypair().0,
            inner: vec![42; ONION_REQUEST_0_MIN_PAYLOAD_SIZE]
        };
        // encode payload with shared secret
        let onion_packet = OnionRequest0::new(&shared_secret, &alice_pk, &payload);
        // decode payload with bob's secret key
        let decoded_payload = onion_packet.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn onion_request_0_payload_encrypt_decrypt_invalid_key() {
        crypto_init().unwrap();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = OnionRequest0Payload {
            ip_port: IpPort {
                protocol: ProtocolType::UDP,
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            temporary_pk: gen_keypair().0,
            inner: vec![42; ONION_REQUEST_0_MIN_PAYLOAD_SIZE]
        };
        // encode payload with shared secret
        let onion_packet = OnionRequest0::new(&shared_secret, &alice_pk, &payload);
        // try to decode payload with eve's secret key
        let eve_shared_secret = encrypt_precompute(&bob_pk, &eve_sk);
        let decoded_payload = onion_packet.get_payload(&eve_shared_secret);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn onion_request_0_decrypt_invalid() {
        crypto_init().unwrap();
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();
        let temporary_pk = gen_keypair().0;
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_onion_request_0 = OnionRequest0 {
            nonce,
            temporary_pk,
            payload: invalid_payload_encoded
        };
        assert!(invalid_onion_request_0.get_payload(&shared_secret).is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_onion_request_0 = OnionRequest0 {
            nonce,
            temporary_pk,
            payload: invalid_payload_encoded
        };
        assert!(invalid_onion_request_0.get_payload(&shared_secret).is_err());
    }
}
