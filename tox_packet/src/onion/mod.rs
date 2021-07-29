/*! Onion UDP Packets
*/

mod onion_announce_request;
mod onion_announce_response;
mod inner_onion_request;
mod inner_onion_response;
mod onion_data_request;
mod onion_data_response;
mod onion_request_0;
mod onion_request_1;
mod onion_request_2;
mod onion_response_1;
mod onion_response_2;
mod onion_response_3;
mod friend_request;

pub use self::onion_announce_request::*;
pub use self::onion_announce_response::*;
pub use self::inner_onion_request::*;
pub use self::inner_onion_response::*;
pub use self::onion_data_request::*;
pub use self::onion_data_response::*;
pub use self::onion_request_0::*;
pub use self::onion_request_1::*;
pub use self::onion_request_2::*;
pub use self::onion_response_1::*;
pub use self::onion_response_2::*;
pub use self::onion_response_3::*;
pub use self::friend_request::*;

use tox_binary_io::*;
use tox_crypto::*;
use xsalsa20poly1305::{XSalsa20Poly1305, aead::{Aead, Error as AeadError}};
use crate::dht::packed_node::PackedNode;
use crate::ip_port::*;

use rand::{CryptoRng, Rng};
use nom::{alt, call, cond, do_parse, eof, flat_map, map, map_res, named, switch, tag, take, value, verify};

use cookie_factory::{
    do_gen,
    gen_slice,
    gen_call,
    gen_cond,
    gen_be_u8,
    gen_le_u64,
    gen_many_ref
};

use nom::{
    Err,
    number::complete::le_u8,
    combinator::{rest, rest_len},
};
use std::io::{Error, ErrorKind};

const ONION_SEND_BASE: usize = PUBLICKEYBYTES + SIZE_IPPORT + MACBYTES;
const ONION_SEND_1: usize = xsalsa20poly1305::NONCE_SIZE + ONION_SEND_BASE * 3;
const MAX_ONION_DATA_SIZE: usize = ONION_MAX_PACKET_SIZE - (ONION_SEND_1 + 1); // 1 is for packet_id
const MIN_ONION_DATA_REQUEST_SIZE: usize = 1 + PUBLICKEYBYTES + xsalsa20poly1305::NONCE_SIZE + PUBLICKEYBYTES + MACBYTES; // 1 is for packet_id
/// Maximum size in butes of Onion Data Request packet
pub const MAX_DATA_REQUEST_SIZE: usize = MAX_ONION_DATA_SIZE - MIN_ONION_DATA_REQUEST_SIZE;
/// Minimum size in bytes of Onion Data Response packet
pub const MIN_ONION_DATA_RESPONSE_SIZE: usize = PUBLICKEYBYTES + MACBYTES;
/// Maximum size in bytes of Onion Data Response inner payload
pub const MAX_ONION_CLIENT_DATA_SIZE: usize = MAX_DATA_REQUEST_SIZE - MIN_ONION_DATA_RESPONSE_SIZE;

/// Size of first `OnionReturn` struct with no inner `OnionReturn`s.
pub const ONION_RETURN_1_SIZE: usize = xsalsa20poly1305::NONCE_SIZE + SIZE_IPPORT + MACBYTES; // 59
/// Size of second `OnionReturn` struct with one inner `OnionReturn`.
pub const ONION_RETURN_2_SIZE: usize = xsalsa20poly1305::NONCE_SIZE + SIZE_IPPORT + MACBYTES + ONION_RETURN_1_SIZE; // 118
/// Size of third `OnionReturn` struct with two inner `OnionReturn`s.
pub const ONION_RETURN_3_SIZE: usize = xsalsa20poly1305::NONCE_SIZE + SIZE_IPPORT + MACBYTES + ONION_RETURN_2_SIZE; // 177

/// The maximum size of onion packet including public key, nonce, packet kind
/// byte, onion return.
pub const ONION_MAX_PACKET_SIZE: usize = 1400;

/** Encrypted onion return addresses. Payload contains encrypted with symmetric
key `IpPort` and possibly inner `OnionReturn`.

When DHT node receives OnionRequest packet it appends `OnionReturn` to the end
of the next request packet it will send. So when DHT node receives OnionResponse
packet it will know where to send the next response packet by decrypting
`OnionReturn` from received packet. If node can't decrypt `OnionReturn` that
means that onion path is expired and packet should be dropped.

Serialized form:

Length                | Content
--------              | ------
`24`                  | `Nonce`
`35` or `94` or `153` | Payload

where payload is encrypted inner `OnionReturn`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionReturn {
    /// Nonce for the current encrypted payload
    pub nonce: [u8; xsalsa20poly1305::NONCE_SIZE],
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for OnionReturn {
    named!(from_bytes<OnionReturn>, do_parse!(
        nonce: call!(<[u8; xsalsa20poly1305::NONCE_SIZE]>::from_bytes) >>
        payload: rest >>
        (OnionReturn { nonce, payload: payload.to_vec() })
    ));
}

impl ToBytes for OnionReturn {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl OnionReturn {
    #[allow(clippy::needless_pass_by_value)]
    fn inner_to_bytes<'a>(ip_port: &IpPort, inner: Option<&OnionReturn>, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, ip_port| IpPort::to_bytes(ip_port, buf, IpPortPadding::WithPadding), ip_port) >>
            gen_call!(|buf, inner| match inner {
                Some(inner) => OnionReturn::to_bytes(inner, buf),
                None => Ok(buf)
            }, inner)
        )
    }

    named!(inner_from_bytes<(IpPort, Option<OnionReturn>)>, do_parse!(
        ip_port: call!(IpPort::from_bytes, IpPortPadding::WithPadding) >>
        rest_len: rest_len >>
        inner: cond!(rest_len > 0, OnionReturn::from_bytes) >>
        (ip_port, inner)
    ));

    /// Create new `OnionReturn` object using symmetric key for encryption.
    pub fn new<R: Rng + CryptoRng>(rng: &mut R, symmetric_key: &XSalsa20Poly1305, ip_port: &IpPort, inner: Option<&OnionReturn>) -> OnionReturn {
        let nonce = xsalsa20poly1305::generate_nonce(rng);
        let mut buf = [0; ONION_RETURN_2_SIZE + SIZE_IPPORT];
        let (_, size) = OnionReturn::inner_to_bytes(ip_port, inner, (&mut buf, 0)).unwrap();
        let payload = symmetric_key.encrypt(&nonce, &buf[..size]).unwrap();

        OnionReturn {
            nonce: nonce.into(),
            payload
        }
    }

    /** Decrypt payload with symmetric key and try to parse it as `IpPort` with possibly inner `OnionReturn`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `IpPort` with possibly inner `OnionReturn`
    */
    pub fn get_payload(&self, symmetric_key: &XSalsa20Poly1305) -> Result<(IpPort, Option<OnionReturn>), Error> {
        let decrypted = symmetric_key.decrypt(&self.nonce.into(), self.payload.as_slice())
            .map_err(|AeadError| {
                Error::new(ErrorKind::Other, "OnionReturn decrypt error.")
            })?;
        match OnionReturn::inner_from_bytes(&decrypted) {
            Err(Err::Incomplete(e)) => {
                Err(Error::new(ErrorKind::Other,
                               format!("Inner onion return deserialize error: {:?}", e)))
            },
            Err(Err::Error(e)) => {
                Err(Error::new(ErrorKind::Other,
                               format!("Inner onion return deserialize error: {:?}", e)))
            },
            Err(Err::Failure(e)) => {
                Err(Error::new(ErrorKind::Other,
                               format!("Inner onion return deserialize error: {:?}", e)))
            },
            Ok((_, inner)) => {
                Ok(inner)
            }
        }
    }
}

/** Represents the result of sent `AnnounceRequest`.

Also known as `is_stored` number.

*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnounceStatus {
    /// Failed to announce ourselves or find requested node
    Failed = 0,
    /// Requested node is found by its long term `PublicKey`
    Found = 1,
    /// We successfully announced ourselves
    Announced = 2
}

impl FromBytes for AnnounceStatus {
    named!(from_bytes<AnnounceStatus>, switch!(le_u8,
        0 => value!(AnnounceStatus::Failed) |
        1 => value!(AnnounceStatus::Found) |
        2 => value!(AnnounceStatus::Announced)
    ));
}

impl ToBytes for AnnounceStatus {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        gen_be_u8!(buf, *self as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::thread_rng;
    use xsalsa20poly1305::aead::NewAead;

    const ONION_RETURN_1_PAYLOAD_SIZE: usize = ONION_RETURN_1_SIZE - xsalsa20poly1305::NONCE_SIZE;

    encode_decode_test!(
        tox_crypto::crypto_init().unwrap(),
        onion_return_encode_decode,
        OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
        }
    );

    encode_decode_test!(
        tox_crypto::crypto_init().unwrap(),
        announce_status_failed,
        AnnounceStatus::Failed
    );

    encode_decode_test!(
        tox_crypto::crypto_init().unwrap(),
        announce_status_found,
        AnnounceStatus::Found
    );

    encode_decode_test!(
        tox_crypto::crypto_init().unwrap(),
        announce_status_accounced,
        AnnounceStatus::Announced
    );

    #[test]
    fn onion_return_encrypt_decrypt() {
        let mut rng = thread_rng();
        let alice_symmetric_key = XSalsa20Poly1305::new(&XSalsa20Poly1305::generate_key(&mut rng));
        let bob_symmetric_key = XSalsa20Poly1305::new(&XSalsa20Poly1305::generate_key(&mut rng));
        // alice encrypt
        let ip_port_1 = IpPort {
            protocol: ProtocolType::Udp,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let onion_return_1 = OnionReturn::new(&mut rng, &alice_symmetric_key, &ip_port_1, None);
        // bob encrypt
        let ip_port_2 = IpPort {
            protocol: ProtocolType::Udp,
            ip_addr: "7.8.5.6".parse().unwrap(),
            port: 54321
        };
        let onion_return_2 = OnionReturn::new(&mut rng, &bob_symmetric_key, &ip_port_2, Some(&onion_return_1));
        // bob can decrypt it's return address
        let (decrypted_ip_port_2, decrypted_onion_return_1) = onion_return_2.get_payload(&bob_symmetric_key).unwrap();
        assert_eq!(decrypted_ip_port_2, ip_port_2);
        assert_eq!(decrypted_onion_return_1.unwrap(), onion_return_1);
        // alice can decrypt it's return address
        let (decrypted_ip_port_1, none) = onion_return_1.get_payload(&alice_symmetric_key).unwrap();
        assert_eq!(decrypted_ip_port_1, ip_port_1);
        assert!(none.is_none());
    }

    #[test]
    fn onion_return_encrypt_decrypt_invalid_key() {
        let mut rng = thread_rng();
        let alice_symmetric_key = XSalsa20Poly1305::new(&XSalsa20Poly1305::generate_key(&mut rng));
        let bob_symmetric_key = XSalsa20Poly1305::new(&XSalsa20Poly1305::generate_key(&mut rng));
        let eve_symmetric_key = XSalsa20Poly1305::new(&XSalsa20Poly1305::generate_key(&mut rng));
        // alice encrypt
        let ip_port_1 = IpPort {
            protocol: ProtocolType::Udp,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let onion_return_1 = OnionReturn::new(&mut rng, &alice_symmetric_key, &ip_port_1, None);
        // bob encrypt
        let ip_port_2 = IpPort {
            protocol: ProtocolType::Udp,
            ip_addr: "7.8.5.6".parse().unwrap(),
            port: 54321
        };
        let onion_return_2 = OnionReturn::new(&mut rng, &bob_symmetric_key, &ip_port_2, Some(&onion_return_1));
        // eve can't decrypt return addresses
        assert!(onion_return_1.get_payload(&eve_symmetric_key).is_err());
        assert!(onion_return_2.get_payload(&eve_symmetric_key).is_err());
    }

    #[test]
    fn onion_return_decrypt_invalid() {
        let mut rng = thread_rng();
        let symmetric_key = XSalsa20Poly1305::new(&XSalsa20Poly1305::generate_key(&mut rng));
        let nonce = xsalsa20poly1305::generate_nonce(&mut rng);
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = symmetric_key.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_onion_return = OnionReturn {
            nonce: nonce.into(),
            payload: invalid_payload_encoded,
        };
        assert!(invalid_onion_return.get_payload(&symmetric_key).is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = symmetric_key.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_onion_return = OnionReturn {
            nonce: nonce.into(),
            payload: invalid_payload_encoded
        };
        assert!(invalid_onion_return.get_payload(&symmetric_key).is_err());
    }
}
