/*! PinResponse packet
*/
use super::*;

use nom::{
    number::complete::be_u64,
    combinator::rest,
};
use crypto_box::{SalsaBox, aead::{Aead, Error as AeadError}};

use tox_binary_io::*;
use tox_crypto::*;
use crate::dht::errors::*;
use nom::combinator::eof;
use nom::bytes::complete::tag;

/** Ping response packet struct. When `PingRequest` is received DHT node should
respond with `PingResponse` that contains the same ping id inside it's encrypted
payload as it got from `PingRequest`.

https://zetok.github.io/tox-spec/#dht-packet

Length  | Content
------- | -------------------------
`1`     | `0x01`
`32`    | Public Key
`24`    | Nonce
`25`    | Payload

where Payload is encrypted [`PingResponsePayload`](./struct.PingResponsePayload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PingResponse {
    /// public key used for payload encryption
    pub pk: PublicKey,
    /// one time serial number
    pub nonce: Nonce,
    /// encrypted payload
    pub payload: Vec<u8>,
}

impl ToBytes for PingResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x01) >>
            gen_slice!(self.pk.as_bytes()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl FromBytes for PingResponse {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x01")(input)?;
        let (input, pk) = PublicKey::from_bytes(input)?;
        let (input, nonce) = Nonce::from_bytes(input)?;
        let (input, payload) = map(rest, |bytes: &[u8]| bytes.to_vec())(input)?;
        Ok((input, PingResponse { pk, nonce, payload }))
    }
}

impl PingResponse {
    /// create new PingResponse object
    pub fn new(shared_secret: &SalsaBox, pk: PublicKey, payload: &PingResponsePayload) -> PingResponse {
        let nonce = crypto_box::generate_nonce(&mut rand::thread_rng());
        let mut buf = [0; MAX_DHT_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = shared_secret.encrypt(&nonce, &buf[..size]).unwrap();

        PingResponse {
            pk,
            nonce: nonce.into(),
            payload,
        }
    }
    /** Decrypt payload and try to parse it as `PingResponsePayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as given packet type
    */
    pub fn get_payload(&self, shared_secret: &SalsaBox) -> Result<PingResponsePayload, GetPayloadError> {
        let decrypted = shared_secret.decrypt((&self.nonce).into(), self.payload.as_slice())
            .map_err(|AeadError| {
                GetPayloadError::decrypt()
            })?;

        match PingResponsePayload::from_bytes(&decrypted) {
            Err(error) => {
                Err(GetPayloadError::deserialize(error, decrypted.clone()))
            },
            Ok((_, payload)) => {
                Ok(payload)
            }
        }
    }
}

/**
Used to request/respond to ping. Used in an encrypted form. Request id is used
for resistance against replay attacks.

Serialized form:

Ping Packet (request and response)

Packet type `0x01` for response.

Response ID must match ID of the request, otherwise ping is invalid.

Length      | Contents
----------- | --------
`1`         | `0x01`
`8`         | Ping ID

Serialized form should be put in the encrypted part of `PingResponse` packet.

[`PingResponsePayload`](./struct.PingResponsePayload.html) can only be created as a response
to [`PingRequestPayload`](./struct.PingRequestPayload.html).
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PingResponsePayload {
    /// Ping id same as requested from PingRequest
    pub id: u64,
}

impl FromBytes for PingResponsePayload {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x01")(input)?;
        let (input, id) = be_u64(input)?;
        let (input, _) = eof(input)?;
        Ok((input, PingResponsePayload { id }))
    }
}

impl ToBytes for PingResponsePayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x01) >>
            gen_be_u64!(self.id)
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::dht::ping_response::*;
    use crate::dht::Packet;

    encode_decode_test!(
        ping_response_payload_encode_decode,
        PingResponsePayload { id: 42 }
    );

    dht_packet_encode_decode!(ping_response_encode_decode, PingResponse);

    dht_packet_encrypt_decrypt!(
        ping_response_payload_encrypt_decrypt,
        PingResponse,
        PingResponsePayload { id: 42 }
    );

    dht_packet_encrypt_decrypt_invalid_key!(
        ping_response_payload_encrypt_decrypt_invalid_key,
        PingResponse,
        PingResponsePayload { id: 42 }
    );

    dht_packet_decode_invalid!(ping_response_decode_invalid, PingResponse);
}
