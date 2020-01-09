/*! PingRequest packet
*/

use nom::{
    number::complete::be_u64,
    combinator::rest,
};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::codec::*;
use crate::toxcore::dht::packet::errors::*;

/** Ping request packet struct. Every 60 seconds DHT node sends `PingRequest`
packet to peers to check whether it is alive. When `PingRequest` is received
DHT node should respond with `PingResponse` that contains the same ping id
inside it's encrypted payload as it got from `PingRequest`. If `PingResponse`
doesn't arrive for 122 seconds the DHT node removes peer from ktree and marks
it as offline if the peer is known friend.

https://zetok.github.io/tox-spec/#dht-packet

Length  | Content
------- | -------------------------
`1`     | `0x00`
`32`    | Public Key
`24`    | Nonce
`25`    | Payload

where Payload is encrypted [`PingRequestPayload`](./struct.PingRequestPayload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PingRequest {
    /// public key used for payload encryption
    pub pk: PublicKey,
    /// one time serial number
    pub nonce: Nonce,
    /// encrypted payload
    pub payload: Vec<u8>,
}

impl ToBytes for PingRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x00) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl FromBytes for PingRequest {
    named!(from_bytes<PingRequest>, do_parse!(
        tag!("\x00") >>
        pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        payload: map!(rest, |bytes| bytes.to_vec() ) >>
        (PingRequest { pk, nonce, payload })
    ));
}

impl PingRequest {
    /// create new PingRequest object
    pub fn new(shared_secret: &PrecomputedKey, pk: &PublicKey, payload: &PingRequestPayload) -> PingRequest {
        let nonce = gen_nonce();
        let mut buf = [0; MAX_DHT_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        PingRequest {
            pk: *pk,
            nonce,
            payload,
        }
    }
    /** Decrypt payload and try to parse it as `PingRequestPayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as given packet type
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<PingRequestPayload, GetPayloadError> {
        debug!(target: "PingRequest", "Getting packet data from PingRequest.");
        trace!(target: "PingRequest", "With PingRequest: {:?}", self);
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|()| {
                debug!("Decrypting PingRequest failed!");
                GetPayloadError::decrypt()
            })?;

        match PingRequestPayload::from_bytes(&decrypted) {
            Err(error) => {
                debug!(target: "PingRequest", "PingRequestPayload deserialize error: {:?}", error);
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

Packet type `0x00` for request.

Response ID must match ID of the request, otherwise ping is invalid.

Length      | Contents
----------- | --------
`1`         | 0x00
`8`         | Ping ID

Serialized form should be put in the encrypted part of `PingRequest` packet.

[`PingResponsePayload`](./struct.PingResponsePayload.html) can only be created as a response
to [`PingRequestPayload`](./struct.PingRequestPayload.html).
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PingRequestPayload {
    /// Request ping id
    pub id: u64,
}

impl FromBytes for PingRequestPayload {
    named!(from_bytes<PingRequestPayload>, do_parse!(
        tag!("\x00") >>
        id: be_u64 >>
        eof!() >>
        (PingRequestPayload { id })
    ));
}

impl ToBytes for PingRequestPayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x00) >>
            gen_be_u64!(self.id)
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::toxcore::dht::packet::ping_request::*;
    use crate::toxcore::dht::packet::Packet;

    encode_decode_test!(
        ping_request_payload_encode_decode,
        PingRequestPayload { id: 42 }
    );

    dht_packet_encode_decode!(ping_request_encode_decode, PingRequest);

    dht_packet_encrypt_decrypt!(
        ping_request_payload_encrypt_decrypt,
        PingRequest,
        PingRequestPayload { id: 42 }
    );

    dht_packet_encrypt_decrypt_invalid_key!(
        ping_request_payload_encrypt_decrypt_invalid_key,
        PingRequest,
        PingRequestPayload { id: 42 }
    );

    dht_packet_decode_invalid!(ping_request_decode_invalid, PingRequest);
}
