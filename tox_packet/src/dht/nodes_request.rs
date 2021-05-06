/*! NodesRequest packet
*/
use super::*;

use aead::{Aead, Error as AeadError};
use crypto_box::SalsaBox;
use nom::{
    number::complete::be_u64,
    combinator::rest,
};

use tox_binary_io::*;
use tox_crypto::*;
use crate::dht::errors::*;

/** Nodes request packet struct. It's used to get up to 4 closest nodes to
requested public key. Every 20 seconds DHT node sends `NodesRequest` packet to
a random node in ktree and its known friends list.

https://zetok.github.io/tox-spec/#dht-packet

Length  | Content
------- | -------------------------
`1`     | `0x02`
`32`    | Public Key
`24`    | Nonce
`56`    | Payload

where Payload is encrypted [`NodesRequestPayload`](./struct.NodesRequestPayload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodesRequest {
    /// public key used for payload encryption
    pub pk: PublicKey,
    /// one time serial number
    pub nonce: Nonce,
    /// encrypted payload
    pub payload: Vec<u8>,
}

impl ToBytes for NodesRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x02) >>
            gen_slice!(self.pk.as_bytes()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl FromBytes for NodesRequest {
    named!(from_bytes<NodesRequest>, do_parse!(
        tag!("\x02") >>
        pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        payload: map!(rest, |bytes| bytes.to_vec() ) >>
        (NodesRequest { pk, nonce, payload })
    ));
}

impl NodesRequest {
    /// create new NodesRequest object
    pub fn new(shared_secret: &SalsaBox, pk: PublicKey, payload: &NodesRequestPayload) -> NodesRequest {
        let nonce = crypto_box::generate_nonce(&mut rand::thread_rng());
        let mut buf = [0; MAX_DHT_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = shared_secret.encrypt(&nonce, &buf[..size]).unwrap();

        NodesRequest {
            pk,
            nonce: nonce.into(),
            payload,
        }
    }
    /** Decrypt payload and try to parse it as `NodesRequestPayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as given packet type
    */
    pub fn get_payload(&self, shared_secret: &SalsaBox) -> Result<NodesRequestPayload, GetPayloadError> {
        let decrypted = shared_secret.decrypt((&self.nonce).into(), self.payload.as_slice())
            .map_err(|AeadError| {
                GetPayloadError::decrypt()
            })?;

        match NodesRequestPayload::from_bytes(&decrypted) {
            Err(error) => {
                Err(GetPayloadError::deserialize(error, decrypted.clone()))
            },
            Ok((_, payload)) => {
                Ok(payload)
            }
        }
    }
}

/** Request to get address of given DHT PK, or nodes that are closest in DHT
to the given PK. Request id is used for resistance against replay attacks.

Serialized form:

Length | Content
------ | ------
`32`   | DHT Public Key
`8`    | Request ID

Serialized form should be put in the encrypted part of `NodesRequest` packet.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodesRequestPayload {
    /// Public Key of the DHT node `NodesRequestPayload` is supposed to get address of.
    pub pk: PublicKey,
    /// An ID of the request.
    pub id: u64,
}

impl ToBytes for NodesRequestPayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.pk.as_ref()) >>
            gen_be_u64!(self.id)
        )
    }
}

impl FromBytes for NodesRequestPayload {
    named!(from_bytes<NodesRequestPayload>, do_parse!(
        pk: call!(PublicKey::from_bytes) >>
        id: be_u64 >>
        eof!() >>
        (NodesRequestPayload { pk, id })
    ));
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use crate::dht::nodes_request::*;
    use crate::dht::Packet;

    encode_decode_test!(
        nodes_request_payload_encode_decode,
        NodesRequestPayload { pk: SecretKey::generate(&mut thread_rng()).public_key(), id: 42 }
    );

    dht_packet_encode_decode!(nodes_request_encode_decode, NodesRequest);

    dht_packet_encrypt_decrypt!(
        nodes_request_payload_encrypt_decrypt,
        NodesRequest,
        NodesRequestPayload { pk: SecretKey::generate(&mut thread_rng()).public_key(), id: 42 }
    );

    dht_packet_encrypt_decrypt_invalid_key!(
        nodes_request_payload_encrypt_decrypt_invalid_key,
        NodesRequest,
        NodesRequestPayload { pk: SecretKey::generate(&mut thread_rng()).public_key(), id: 42 }
    );

    dht_packet_decode_invalid!(nodes_request_decode_invalid, NodesRequest);
}
