/*! CryptoData packet
*/

use byteorder::{ByteOrder, BigEndian};
use nom::{be_u16, be_u32, rest};

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::dht::errors::*;

/// The maximum size of `CryptoData` packet including two bytes of nonce and
/// packet kind byte.
const MAX_CRYPTO_PACKET_SIZE: usize = 1400;

/// The maximum size of data in packets.
const MAX_CRYPTO_DATA_SIZE: usize = MAX_CRYPTO_PACKET_SIZE - MACBYTES - 11;

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
    named!(from_bytes<CryptoData>, do_parse!(
        verify!(rest_len, |len| len <= MAX_CRYPTO_PACKET_SIZE) >>
        tag!("\x1b") >>
        nonce_last_bytes: be_u16 >>
        payload: rest >>
        (CryptoData { nonce_last_bytes, payload: payload.to_vec() })
    ));
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
        BigEndian::read_u16(&nonce.as_ref()[NONCEBYTES - 2..])
    }
    /// Create `CryptoData` from `CryptoDataPayload` encrypting it with
    /// `shared_key`.
    pub fn new(shared_secret: &PrecomputedKey, nonce: Nonce, payload: &CryptoDataPayload) -> CryptoData {
        let mut buf = [0; MAX_CRYPTO_PACKET_SIZE - MACBYTES - 3];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);
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
    pub fn get_payload(&self, shared_secret: &PrecomputedKey, nonce: &Nonce) -> Result<CryptoDataPayload, GetPayloadError> {
        let decrypted = open_precomputed(&self.payload, nonce, shared_secret)
            .map_err(|()| {
                debug!("Decrypting CryptoData failed!");
                GetPayloadError::DecryptError { packet: stringify!(Self).to_string() }
            })?;
        match CryptoDataPayload::from_bytes(&decrypted) {
            IResult::Incomplete(needed) => {
                debug!(target: "Dht", "CryptoDataPayload return deserialize error: {:?}", needed);
                Err(GetPayloadError::IncompletePayload { packet: stringify!(Self).to_string(), needed, payload: self.payload.to_vec() })
            },
            IResult::Error(error) => {
                debug!(target: "Dht", "CryptoDataPayload return deserialize error: {:?}", error);
                Err(GetPayloadError::DeserializeError { packet: stringify!(Self).to_string(), error, payload: self.payload.to_vec() })
            },
            IResult::Done(_, payload) => {
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
    named!(from_bytes<CryptoDataPayload>, do_parse!(
        buffer_start: be_u32 >>
        packet_number: be_u32 >>
        take_while!(|b| b == 0) >>
        data: rest >>
        (CryptoDataPayload { buffer_start, packet_number, data: data.to_vec() })
    ));
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

    #[test]
    fn crypto_data_encrypt_decrypt() {
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();
        let payload = CryptoDataPayload {
            buffer_start: 12345,
            packet_number: 54321,
            data: vec![42; 123],
        };
        // encode payload with shared secret
        let crypto_data = CryptoData::new(&shared_secret, nonce, &payload);
        // payload length should be gradual
        assert_eq!(
            (crypto_data.payload.len() - MACBYTES - 8) % CRYPTO_MAX_PADDING,
            MAX_CRYPTO_DATA_SIZE % CRYPTO_MAX_PADDING
        );
        // decode payload with shared secret
        let decoded_payload = crypto_data.get_payload(&shared_secret, &nonce).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn crypto_data_encrypt_decrypt_invalid_key() {
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let eve_shared_secret = encrypt_precompute(&bob_pk, &eve_sk);
        let nonce = gen_nonce();
        let payload = CryptoDataPayload {
            buffer_start: 12345,
            packet_number: 54321,
            data: vec![42; 123],
        };
        // encode payload with shared secret
        let crypto_data = CryptoData::new(&shared_secret, nonce, &payload);
        // payload length should be gradual
        assert_eq!(
            (crypto_data.payload.len() - MACBYTES - 8) % CRYPTO_MAX_PADDING,
            MAX_CRYPTO_DATA_SIZE % CRYPTO_MAX_PADDING
        );
        // try to decode payload with eve's shared secret
        let decoded_payload = crypto_data.get_payload(&eve_shared_secret, &nonce);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn crypto_data_encrypt_decrypt_invalid() {
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();
        let nonce_last_bytes = CryptoData::nonce_last_bytes(nonce);
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_packet = CryptoData {
            nonce_last_bytes,
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&shared_secret, &nonce);
        assert!(decoded_payload.is_err());
    }
}
