/*! CryptoData packet
*/
use super::*;

use crypto_box::{SalsaBox, aead::{
    {Aead, AeadCore, Error as AeadError},
    generic_array::typenum::marker_traits::Unsigned,
}};
use nom::{
    bytes::complete::{take_while, tag},
    number::complete::{be_u16, be_u32},
    combinator::{rest, rest_len, verify},
};
use std::convert::TryInto;

use tox_binary_io::*;
use tox_crypto::*;
use crate::dht::errors::*;

/// The maximum size of `CryptoData` packet including two bytes of nonce and
/// packet kind byte.
const MAX_CRYPTO_PACKET_SIZE: usize = 1400;

/// The maximum size of data in packets.
pub const MAX_CRYPTO_DATA_SIZE: usize = MAX_CRYPTO_PACKET_SIZE - <SalsaBox as AeadCore>::TagSize::USIZE - 11;

/// All packets will be padded a number of bytes based on this number.
const CRYPTO_MAX_PADDING: usize = 8;

/** Packet used to send data over `net_crypto` connection.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x1b`
`2`      | Last 2 bytes of the `Nonce`
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptoData {
    /// Last two bytes of `Nonce` for the current encrypted payload in BigEndian
    /// format
    pub nonce_last_bytes: u16,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for CryptoData {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = verify(rest_len, |len| *len <= MAX_CRYPTO_PACKET_SIZE)(input)?;
        let (input, _) = tag("\x1b")(input)?;
        let (input, nonce_last_bytes) = be_u16(input)?;
        let (input, payload) = rest(input)?;
        Ok((input, CryptoData { nonce_last_bytes, payload: payload.to_vec() }))
    }
}

impl ToBytes for CryptoData {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x1b) >>
            gen_be_u16!(self.nonce_last_bytes) >>
            gen_slice!(self.payload.as_slice()) >>
            gen_len_limit(MAX_CRYPTO_PACKET_SIZE)
        )
    }
}

impl CryptoData {
    /// Get last two bytes of `Nonce` considering it as BigEndian number.
    pub fn nonce_last_bytes(nonce: Nonce) -> u16 {
        u16::from_be_bytes(nonce.as_ref()[NONCEBYTES - 2..].try_into().unwrap())
    }
    /// Create `CryptoData` from `CryptoDataPayload` encrypting it with
    /// `shared_key`.
    pub fn new(shared_secret: &SalsaBox, nonce: Nonce, payload: &CryptoDataPayload) -> CryptoData {
        let mut buf = [0; MAX_CRYPTO_PACKET_SIZE - <SalsaBox as AeadCore>::TagSize::USIZE - 3];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = shared_secret.encrypt((&nonce).into(), &buf[..size]).unwrap();
        let nonce_last_bytes = CryptoData::nonce_last_bytes(nonce);

        CryptoData {
            nonce_last_bytes,
            payload,
        }
    }
    /** Decrypt payload with precomputed key and nonce and try to parse it as `CryptoDataPayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse `CryptoDataPayload`
    */
    pub fn get_payload(&self, shared_secret: &SalsaBox, nonce: &Nonce) -> Result<CryptoDataPayload, GetPayloadError> {
        let decrypted = shared_secret.decrypt(nonce.into(), self.payload.as_slice())
            .map_err(|AeadError| {
                GetPayloadError::Decrypt
            })?;
        match CryptoDataPayload::from_bytes(&decrypted) {
            Err(error) => {
                Err(GetPayloadError::Deserialize {
                    error: error.to_owned(),
                    payload: decrypted.clone(),
                })
            },
            Ok((_, payload)) => {
                Ok(payload)
            }
        }
    }
}

/** Unencrypted payload of `CryptoData` packet.

Serialized form:

Length   | Content
-------- | ------
`4`      | Buffer start
`4`      | Packet number
variable | Data

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptoDataPayload {
    /// Highest packet number handled + 1
    pub buffer_start: u32,
    /// Packet number used by the receiver to know if any packets have been lost
    pub packet_number: u32,
    /// Data of `CryptoData` packet
    pub data: Vec<u8>
}

impl FromBytes for CryptoDataPayload {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, buffer_start) = be_u32(input)?;
        let (input, packet_number) = be_u32(input)?;
        let (input, _) = take_while(|b| b == 0)(input)?;
        let (input, data) = rest(input)?;
        Ok((input, CryptoDataPayload { buffer_start, packet_number, data: data.to_vec() }))
    }
}

impl ToBytes for CryptoDataPayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u32!(self.buffer_start) >>
            gen_be_u32!(self.packet_number) >>
            gen_slice!(vec![0; (MAX_CRYPTO_DATA_SIZE - self.data.len()) % CRYPTO_MAX_PADDING]) >>
            gen_slice!(self.data.as_slice())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::{Err, error::{Error, ErrorKind}};
    use rand::thread_rng;

    encode_decode_test!(
        crypto_data_encode_decode,
        CryptoData {
            nonce_last_bytes: 42,
            payload: vec![42; 123],
        }
    );

    encode_decode_test!(
        crypto_data_payload_encode_decode,
        CryptoDataPayload {
            buffer_start: 12345,
            packet_number: 54321,
            data: vec![42; 123],
        }
    );

    encode_decode_test!(
        crypto_data_payload_encode_decode_empty,
        CryptoDataPayload {
            buffer_start: 0,
            packet_number: 0,
            data: vec![],
        }
    );

    #[test]
    fn crypto_data_encrypt_decrypt() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let nonce = SalsaBox::generate_nonce(&mut rng).into();
        let payload = CryptoDataPayload {
            buffer_start: 12345,
            packet_number: 54321,
            data: vec![42; 123],
        };
        // encode payload with shared secret
        let crypto_data = CryptoData::new(&shared_secret, nonce, &payload);
        // payload length should be gradual
        assert_eq!(
            (crypto_data.payload.len() - <SalsaBox as AeadCore>::TagSize::USIZE - 8) % CRYPTO_MAX_PADDING,
            MAX_CRYPTO_DATA_SIZE % CRYPTO_MAX_PADDING
        );
        // decode payload with shared secret
        let decoded_payload = crypto_data.get_payload(&shared_secret, &nonce).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn crypto_data_encrypt_decrypt_invalid_key() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let eve_sk = SecretKey::generate(&mut rng);
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let eve_shared_secret = SalsaBox::new(&bob_pk, &eve_sk);
        let nonce = SalsaBox::generate_nonce(&mut rng).into();
        let payload = CryptoDataPayload {
            buffer_start: 12345,
            packet_number: 54321,
            data: vec![42; 123],
        };
        // encode payload with shared secret
        let crypto_data = CryptoData::new(&shared_secret, nonce, &payload);
        // payload length should be gradual
        assert_eq!(
            (crypto_data.payload.len() - <SalsaBox as AeadCore>::TagSize::USIZE - 8) % CRYPTO_MAX_PADDING,
            MAX_CRYPTO_DATA_SIZE % CRYPTO_MAX_PADDING
        );
        // try to decode payload with eve's shared secret
        let decoded_payload = crypto_data.get_payload(&eve_shared_secret, &nonce);
        let error = decoded_payload.err().unwrap();
        assert_eq!(error, GetPayloadError::Decrypt);
    }

    #[test]
    fn crypto_data_encrypt_decrypt_invalid() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let nonce = SalsaBox::generate_nonce(&mut rng);
        let nonce_last_bytes = CryptoData::nonce_last_bytes(nonce.into());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_packet = CryptoData {
            nonce_last_bytes,
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&shared_secret, &nonce.into());
        let error = decoded_payload.err().unwrap();
        assert_eq!(error, GetPayloadError::Deserialize { error: Err::Error(Error::new(vec![], ErrorKind::Eof)), payload: invalid_payload.to_vec() });
    }
}
