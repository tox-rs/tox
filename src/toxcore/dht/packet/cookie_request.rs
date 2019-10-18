/*! CookieRequest packet
*/

use nom::number::complete::be_u64;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packet::errors::*;

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
    named!(from_bytes<CookieRequest>, do_parse!(
        tag!("\x18") >>
        pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        payload: take!(88) >>
        (CookieRequest { pk, nonce, payload: payload.to_vec() })
    ));
}

impl CookieRequest {
    /// Create `CookieRequest` from `CookieRequestPayload` encrypting it with `shared_key`
    pub fn new(shared_secret: &PrecomputedKey, pk: &PublicKey, payload: &CookieRequestPayload) -> CookieRequest {
        let nonce = gen_nonce();
        let mut buf = [0; 72];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        CookieRequest {
            pk: *pk,
            nonce,
            payload,
        }
    }
    /** Decrypt payload with secret key and try to parse it as `CookieRequestPayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse `CookieRequestPayload`
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<CookieRequestPayload, GetPayloadError> {
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|()| {
                debug!("Decrypting CookieRequest failed!");
                GetPayloadError::decrypt()
            })?;
        match CookieRequestPayload::from_bytes(&decrypted) {
            Err(error) => {
                debug!(target: "Dht", "CookieRequestPayload return deserialize error: {:?}", error);
                Err(GetPayloadError::deserialize(error, decrypted.clone()))
            },
            Ok((_, payload)) => {
                Ok(payload)
            }
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
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(&[0; 32]) >> // padding
            gen_be_u64!(self.id)
        )
    }
}

impl FromBytes for CookieRequestPayload {
    named!(from_bytes<CookieRequestPayload>, do_parse!(
        pk: call!(PublicKey::from_bytes) >>
        take!(32) >> // padding
        id: be_u64 >>
        eof!() >>
        (CookieRequestPayload { pk, id })
    ));
}

#[cfg(test)]
mod tests {
    use crate::toxcore::dht::packet::cookie_request::*;

    encode_decode_test!(
        cookie_request_encode_decode,
        CookieRequest {
            pk: gen_keypair().0,
            nonce: gen_nonce(),
            payload: vec![42; 88],
        }
    );

    encode_decode_test!(
        cookie_request_payload_encode_decode,
        CookieRequestPayload {
            pk: gen_keypair().0,
            id: 42
        }
    );

    dht_packet_encrypt_decrypt!(
        cookie_request_payload_encrypt_decrypt,
        CookieRequest,
        CookieRequestPayload { pk: gen_keypair().0, id: 42 }
    );

    dht_packet_encrypt_decrypt_invalid_key!(
        cookie_request_payload_encrypt_decrypt_invalid_key,
        CookieRequest,
        CookieRequestPayload { pk: gen_keypair().0, id: 42 }
    );

    dht_packet_decode_invalid!(cookie_request_decode_invalid, CookieRequest);
}
