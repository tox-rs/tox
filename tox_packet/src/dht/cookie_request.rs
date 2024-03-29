/*! CookieRequest packet
*/

use super::*;

use aead::{Aead, AeadCore, Error as AeadError};
use crypto_box::SalsaBox;
use nom::bytes::complete::{tag, take};
use nom::combinator::eof;
use nom::number::complete::be_u64;

use crate::dht::errors::*;
use tox_binary_io::*;
use tox_crypto::*;

/** CookieRequest packet struct.
According to https://zetok.github.io/tox-spec/#net-crypto

CookieRequest packet (145 bytes):

[uint8_t 24]
[Sender's DHT Public key (32 bytes)]
[Random nonce (24 bytes)]
[Encrypted message containing:
    [Sender's real public key (32 bytes)]
    [padding (32 bytes)]
    [uint64_t echo id (must be sent back untouched in cookie response)]
]

Serialized form:

Length | Content
------ | ------
`1`    | `0x18`
`32`   | DHT Public Key
`24`   | Random nonce
`88`   | Payload

where Payload is encrypted [`CookieRequestPayload`](./struct.CookieRequestPayload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CookieRequest {
    /// DHT public key
    pub pk: PublicKey,
    /// Random nonce
    pub nonce: Nonce,
    /// Encrypted payload of CookieRequest
    pub payload: Vec<u8>,
}

impl ToBytes for CookieRequest {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x18) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl FromBytes for CookieRequest {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x18")(input)?;
        let (input, pk) = PublicKey::from_bytes(input)?;
        let (input, nonce) = Nonce::from_bytes(input)?;
        let (input, payload) = take(88usize)(input)?;
        Ok((
            input,
            CookieRequest {
                pk,
                nonce,
                payload: payload.to_vec(),
            },
        ))
    }
}

impl CookieRequest {
    /// Create `CookieRequest` from `CookieRequestPayload` encrypting it with `shared_key`
    pub fn new(shared_secret: &SalsaBox, pk: PublicKey, payload: &CookieRequestPayload) -> CookieRequest {
        let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
        let mut buf = [0; 72];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = shared_secret.encrypt(&nonce, &buf[..size]).unwrap();

        CookieRequest {
            pk,
            nonce: nonce.into(),
            payload,
        }
    }
    /** Decrypt payload with secret key and try to parse it as `CookieRequestPayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse `CookieRequestPayload`
    */
    pub fn get_payload(&self, shared_secret: &SalsaBox) -> Result<CookieRequestPayload, GetPayloadError> {
        let decrypted = shared_secret
            .decrypt((&self.nonce).into(), self.payload.as_slice())
            .map_err(|AeadError| GetPayloadError::decrypt())?;
        match CookieRequestPayload::from_bytes(&decrypted) {
            Err(error) => Err(GetPayloadError::deserialize(error, decrypted.clone())),
            Ok((_, payload)) => Ok(payload),
        }
    }
}

/** CookieRequestPayload packet struct.

Serialized form:

Length      | Contents
----------- | --------
`32`        | Sender's real public key
`32`        | Padding (zeros)
`8`         | Request ID in BigEndian

Serialized form should be put in the encrypted part of `CookieRequest` packet.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CookieRequestPayload {
    /// Sender's real public key
    pub pk: PublicKey,
    /// Request id
    pub id: u64,
}

impl ToBytes for CookieRequestPayload {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(&[0; 32]) >> // padding
            gen_be_u64!(self.id)
        )
    }
}

impl FromBytes for CookieRequestPayload {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, pk) = PublicKey::from_bytes(input)?;
        let (input, _) = take(32usize)(input)?; // padding
        let (input, id) = be_u64(input)?;
        let (input, _) = eof(input)?;
        Ok((input, CookieRequestPayload { pk, id }))
    }
}

#[cfg(test)]
mod tests {
    use crate::dht::cookie_request::*;
    use crypto_box::aead::{generic_array::typenum::marker_traits::Unsigned, AeadCore};
    use rand::thread_rng;

    encode_decode_test!(
        cookie_request_encode_decode,
        CookieRequest {
            pk: SecretKey::generate(&mut thread_rng()).public_key(),
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 88],
        }
    );

    encode_decode_test!(
        cookie_request_payload_encode_decode,
        CookieRequestPayload {
            pk: SecretKey::generate(&mut thread_rng()).public_key(),
            id: 42
        }
    );

    dht_packet_encrypt_decrypt!(
        cookie_request_payload_encrypt_decrypt,
        CookieRequest,
        CookieRequestPayload {
            pk: SecretKey::generate(&mut thread_rng()).public_key(),
            id: 42
        }
    );

    dht_packet_encrypt_decrypt_invalid_key!(
        cookie_request_payload_encrypt_decrypt_invalid_key,
        CookieRequest,
        CookieRequestPayload {
            pk: SecretKey::generate(&mut thread_rng()).public_key(),
            id: 42
        }
    );

    dht_packet_decode_invalid!(cookie_request_decode_invalid, CookieRequest);
}
