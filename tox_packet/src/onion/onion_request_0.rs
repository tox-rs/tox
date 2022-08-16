/*! OnionRequest0 packet with OnionRequest0Payload
*/

use super::*;

use aead::AeadCore;
use crypto_box::SalsaBox;
use tox_binary_io::*;
use tox_crypto::*;
use crate::dht::*;

use nom::combinator::{rest, rest_len, verify};
use nom::bytes::complete::tag;

/// Encrypted payload should contain `IpPort`, `PublicKey` and inner encrypted
/// payload that should contain at least `IpPort` struct.
const ONION_REQUEST_0_MIN_PAYLOAD_SIZE: usize = (SIZE_IPPORT + <SalsaBox as AeadCore>::TagSize::USIZE) * 2 + crypto_box::KEY_SIZE;

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
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = verify(rest_len, |len| *len <= ONION_MAX_PACKET_SIZE)(input)?;
        let (input, _) = tag(&[0x80][..])(input)?;
        let (input, nonce) = Nonce::from_bytes(input)?;
        let (input, temporary_pk) = PublicKey::from_bytes(input)?;
        let (input, payload) = verify(rest, |payload: &[u8]| payload.len() >= ONION_REQUEST_0_MIN_PAYLOAD_SIZE)(input)?;
        Ok((input, OnionRequest0 {
            nonce,
            temporary_pk,
            payload: payload.to_vec()
        }))
    }
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
    pub fn new(shared_secret: &SalsaBox, temporary_pk: PublicKey, payload: &OnionRequest0Payload) -> OnionRequest0 {
        let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
        let mut buf = [0; ONION_MAX_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = shared_secret.encrypt(&nonce, &buf[..size]).unwrap();

        OnionRequest0 { nonce: nonce.into(), temporary_pk, payload }
    }

    /** Decrypt payload and try to parse it as `OnionRequest0Payload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `OnionRequest0Payload`
    */
    pub fn get_payload(&self, shared_secret: &SalsaBox) -> Result<OnionRequest0Payload, GetPayloadError> {
        let decrypted = shared_secret.decrypt((&self.nonce).into(), self.payload.as_slice())
            .map_err(|AeadError| {
                GetPayloadError::decrypt()
            })?;
        match OnionRequest0Payload::from_bytes(&decrypted) {
            Err(error) => {
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
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, ip_port) = IpPort::from_udp_bytes(input, IpPortPadding::WithPadding)?;
        let (input, temporary_pk) = PublicKey::from_bytes(input)?;
        let (input, inner) = rest(input)?;
        Ok((input, OnionRequest0Payload {
            ip_port,
            temporary_pk,
            inner: inner.to_vec()
        }))
    }
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
    use rand::thread_rng;

    use super::*;

    encode_decode_test!(
        onion_request_0_encode_decode,
        OnionRequest0 {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            temporary_pk: SecretKey::generate(&mut thread_rng()).public_key(),
            payload: vec![42; ONION_REQUEST_0_MIN_PAYLOAD_SIZE]
        }
    );

    encode_decode_test!(
        onion_request_0_payload_encode_decode,
        OnionRequest0Payload {
            ip_port: IpPort {
                protocol: ProtocolType::Udp,
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            temporary_pk: SecretKey::generate(&mut thread_rng()).public_key(),
            inner: vec![42; ONION_REQUEST_0_MIN_PAYLOAD_SIZE]
        }
    );

    #[test]
    fn onion_request_0_payload_encrypt_decrypt() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let alice_pk = alice_sk.public_key();
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let payload = OnionRequest0Payload {
            ip_port: IpPort {
                protocol: ProtocolType::Udp,
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            temporary_pk: SecretKey::generate(&mut rng).public_key(),
            inner: vec![42; ONION_REQUEST_0_MIN_PAYLOAD_SIZE]
        };
        // encode payload with shared secret
        let onion_packet = OnionRequest0::new(&shared_secret, alice_pk, &payload);
        // decode payload with bob's secret key
        let decoded_payload = onion_packet.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn onion_request_0_payload_encrypt_decrypt_invalid_key() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let alice_pk = alice_sk.public_key();
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let eve_sk = SecretKey::generate(&mut rng);
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let payload = OnionRequest0Payload {
            ip_port: IpPort {
                protocol: ProtocolType::Udp,
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            temporary_pk: SecretKey::generate(&mut rng).public_key(),
            inner: vec![42; ONION_REQUEST_0_MIN_PAYLOAD_SIZE]
        };
        // encode payload with shared secret
        let onion_packet = OnionRequest0::new(&shared_secret, alice_pk, &payload);
        // try to decode payload with eve's secret key
        let eve_shared_secret = SalsaBox::new(&bob_pk, &eve_sk);
        let decoded_payload = onion_packet.get_payload(&eve_shared_secret);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn onion_request_0_decrypt_invalid() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let nonce = SalsaBox::generate_nonce(&mut rng);
        let temporary_pk = SecretKey::generate(&mut rng).public_key();
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_onion_request_0 = OnionRequest0 {
            nonce: nonce.into(),
            temporary_pk: temporary_pk.clone(),
            payload: invalid_payload_encoded
        };
        assert!(invalid_onion_request_0.get_payload(&shared_secret).is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_onion_request_0 = OnionRequest0 {
            nonce: nonce.into(),
            temporary_pk,
            payload: invalid_payload_encoded
        };
        assert!(invalid_onion_request_0.get_payload(&shared_secret).is_err());
    }
}
