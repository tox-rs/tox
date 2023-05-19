/*! OnionRequest2 packet with OnionRequest2Payload
*/

use super::*;

use crypto_box::{aead::Error as AeadError, SalsaBox};
use nom::bytes::complete::{tag, take};
use nom::combinator::{eof, rest_len, verify};

use crate::dht::*;
use tox_binary_io::*;
use tox_crypto::*;

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
    pub onion_return: OnionReturn,
}

impl FromBytes for OnionRequest2 {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = verify(rest_len, |len| *len <= ONION_MAX_PACKET_SIZE)(input)?;
        let (input, _) = tag(&[0x82][..])(input)?;
        let (input, nonce) = Nonce::from_bytes(input)?;
        let (input, temporary_pk) = PublicKey::from_bytes(input)?;
        let (input, rest_len) = verify(rest_len, |rest_len| *rest_len >= ONION_RETURN_2_SIZE)(input)?;
        let (input, payload) = take(rest_len - ONION_RETURN_2_SIZE)(input)?;
        let (input, onion_return) = OnionReturn::from_bytes(input)?;
        Ok((
            input,
            OnionRequest2 {
                nonce,
                temporary_pk,
                payload: payload.to_vec(),
                onion_return,
            },
        ))
    }
}

impl ToBytes for OnionRequest2 {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x82) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.temporary_pk.as_bytes()) >>
            gen_slice!(self.payload.as_slice()) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return) >>
            gen_len_limit(ONION_MAX_PACKET_SIZE)
        )
    }
}

impl OnionRequest2 {
    /// Create new `OnionRequest2` object.
    pub fn new(
        shared_secret: &SalsaBox,
        temporary_pk: PublicKey,
        payload: &OnionRequest2Payload,
        onion_return: OnionReturn,
    ) -> OnionRequest2 {
        let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
        let mut buf = [0; ONION_MAX_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = shared_secret.encrypt(&nonce, &buf[..size]).unwrap();

        OnionRequest2 {
            nonce: nonce.into(),
            temporary_pk,
            payload,
            onion_return,
        }
    }

    /** Decrypt payload and try to parse it as `OnionRequest2Payload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `OnionRequest2Payload`
    */
    pub fn get_payload(&self, shared_secret: &SalsaBox) -> Result<OnionRequest2Payload, GetPayloadError> {
        let decrypted = shared_secret
            .decrypt((&self.nonce).into(), self.payload.as_slice())
            .map_err(|AeadError| GetPayloadError::decrypt())?;
        match OnionRequest2Payload::from_bytes(&decrypted) {
            Err(error) => Err(GetPayloadError::deserialize(error, decrypted.clone())),
            Ok((_, inner)) => Ok(inner),
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
    pub inner: InnerOnionRequest,
}

impl FromBytes for OnionRequest2Payload {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, ip_port) = IpPort::from_udp_bytes(input, IpPortPadding::WithPadding)?;
        let (input, inner) = InnerOnionRequest::from_bytes(input)?;
        let (input, _) = eof(input)?;
        Ok((input, OnionRequest2Payload { ip_port, inner }))
    }
}

impl ToBytes for OnionRequest2Payload {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, ip_port| IpPort::to_udp_bytes(ip_port, buf, IpPortPadding::WithPadding), &self.ip_port) >>
            gen_call!(|buf, inner| InnerOnionRequest::to_bytes(inner, buf), &self.inner)
        )
    }
}

#[cfg(test)]
mod tests {
    use crypto_box::SalsaBox;
    use rand::thread_rng;

    use super::*;

    const ONION_RETURN_2_PAYLOAD_SIZE: usize = ONION_RETURN_2_SIZE - xsalsa20poly1305::NONCE_SIZE;

    encode_decode_test!(
        onion_request_2_encode_decode,
        OnionRequest2 {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            temporary_pk: SecretKey::generate(&mut thread_rng()).public_key(),
            payload: vec![42; 123],
            onion_return: OnionReturn {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
            }
        }
    );

    encode_decode_test!(
        onion_request_2_payload_encode_decode,
        OnionRequest2Payload {
            ip_port: IpPort {
                protocol: ProtocolType::Udp,
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            inner: InnerOnionRequest::InnerOnionDataRequest(InnerOnionDataRequest {
                destination_pk: SecretKey::generate(&mut thread_rng()).public_key(),
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                temporary_pk: SecretKey::generate(&mut thread_rng()).public_key(),
                payload: vec![42; 123]
            })
        }
    );

    #[test]
    fn onion_request_2_payload_encrypt_decrypt() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let alice_pk = alice_sk.public_key();
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let payload = OnionRequest2Payload {
            ip_port: IpPort {
                protocol: ProtocolType::Udp,
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345,
            },
            inner: InnerOnionRequest::InnerOnionDataRequest(InnerOnionDataRequest {
                destination_pk: SecretKey::generate(&mut rng).public_key(),
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                temporary_pk: SecretKey::generate(&mut rng).public_key(),
                payload: vec![42; 123],
            }),
        };
        let onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE],
        };
        // encode payload with shared secret
        let onion_packet = OnionRequest2::new(&shared_secret, alice_pk, &payload, onion_return);
        // decode payload with bob's secret key
        let decoded_payload = onion_packet.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn onion_request_2_payload_encrypt_decrypt_invalid_key() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let alice_pk = alice_sk.public_key();
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let eve_sk = SecretKey::generate(&mut rng);
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let payload = OnionRequest2Payload {
            ip_port: IpPort {
                protocol: ProtocolType::Udp,
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345,
            },
            inner: InnerOnionRequest::InnerOnionDataRequest(InnerOnionDataRequest {
                destination_pk: SecretKey::generate(&mut rng).public_key(),
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                temporary_pk: SecretKey::generate(&mut rng).public_key(),
                payload: vec![42; 123],
            }),
        };
        let onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE],
        };
        // encode payload with shared secret
        let onion_packet = OnionRequest2::new(&shared_secret, alice_pk, &payload, onion_return);
        // try to decode payload with eve's secret key
        let eve_shared_secret = SalsaBox::new(&bob_pk, &eve_sk);
        let decoded_payload = onion_packet.get_payload(&eve_shared_secret);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn onion_request_2_decrypt_invalid() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let nonce = SalsaBox::generate_nonce(&mut rng);
        let temporary_pk = SecretKey::generate(&mut rng).public_key();
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_onion_request_2 = OnionRequest2 {
            nonce: nonce.into(),
            temporary_pk: temporary_pk.clone(),
            payload: invalid_payload_encoded,
            onion_return: OnionReturn {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE],
            },
        };
        assert!(invalid_onion_request_2.get_payload(&shared_secret).is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_onion_request_2 = OnionRequest2 {
            nonce: nonce.into(),
            temporary_pk,
            payload: invalid_payload_encoded,
            onion_return: OnionReturn {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE],
            },
        };
        assert!(invalid_onion_request_2.get_payload(&shared_secret).is_err());
    }
}
