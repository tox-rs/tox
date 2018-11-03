/*! NodesResponse packet
*/

use nom::{le_u8, be_u64, rest};

use std::io::{Error, ErrorKind};

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::dht::packed_node::PackedNode;
use toxcore::dht::codec::*;

/** Nodes response packet struct. When DHT node receives `NodesRequest` it
should respond with `NodesResponse` that contains up to to 4 closest nodes to
requested public key. Ping id should be the same as it was in `NodesRequest`.

https://zetok.github.io/tox-spec/#dht-packet

Length    | Content
--------- | -------------------------
`1`       | `0x04`
`32`      | Public Key
`24`      | Nonce
`1`       | Number of Response Nodes
`[25,229]`| Payload

where Payload is encrypted [`NodesResponsePayload`](./struct.NodesResponsePayload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodesResponse {
    /// public key used for payload encryption
    pub pk: PublicKey,
    /// one time serial number
    pub nonce: Nonce,
    /// encrypted payload
    pub payload: Vec<u8>,
}

impl ToBytes for NodesResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x04) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl FromBytes for NodesResponse {
    named!(from_bytes<NodesResponse>, do_parse!(
        tag!("\x04") >>
        pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        payload: map!(rest, |bytes| bytes.to_vec() ) >>
        (NodesResponse { pk, nonce, payload })
    ));
}

impl NodesResponse {
    /// create new NodesResponse object
    pub fn new(shared_secret: &PrecomputedKey, pk: &PublicKey, payload: &NodesResponsePayload) -> NodesResponse {
        let nonce = gen_nonce();
        let mut buf = [0; MAX_DHT_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        NodesResponse {
            pk: *pk,
            nonce,
            payload,
        }
    }
    /** Decrypt payload and try to parse it as `NodesResponsePayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as given packet type
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<NodesResponsePayload, Error> {
        debug!(target: "NodesResponse", "Getting packet data from NodesResponse.");
        trace!(target: "NodesResponse", "With NodesResponse: {:?}", self);
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|()| {
                debug!("Decrypting NodesResponse failed!");
                Error::new(ErrorKind::Other, "NodesResponse decrypt error.")
            })?;

        match NodesResponsePayload::from_bytes(&decrypted) {
            IResult::Incomplete(e) => {
                debug!(target: "NodesResponse", "NodesResponsePayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("NodesResponsePayload deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                debug!(target: "NodesResponse", "PingRequestPayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("NodesResponsePayload deserialize error: {:?}", e)))
            },
            IResult::Done(_, payload) => {
                Ok(payload)
            }
        }
    }
}

/** Response to [`NodesRequest`](./struct.NodesRequest.html) request, containing up to
`4` nodes closest to the requested node. Request id is used for resistance against
replay attacks.

Serialized form:

Length      | Contents
----------- | --------
`1`         | Number of packed nodes (maximum 4)
`[0, 204]`  | Nodes in packed format
`8`         | Request ID

An IPv4 node is 39 bytes, an IPv6 node is 51 bytes, so the maximum size is
`51 * 4 = 204` bytes.

Serialized form should be put in the encrypted part of `NodesResponse` packet.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodesResponsePayload {
    /** Nodes sent in response to [`NodesRequest`](./struct.NodesRequest.html) request.

    There can be up to 4 nodes in `NodesResponsePayload`.
    */
    pub nodes: Vec<PackedNode>,
    /// request id
    pub id: u64,
}

impl ToBytes for NodesResponsePayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_cond!(self.nodes.len() > 4, |buf| gen_error(buf, 0)) >>
            gen_be_u8!(self.nodes.len() as u8) >>
            gen_many_ref!(&self.nodes, |buf, node| PackedNode::to_bytes(node, buf)) >>
            gen_be_u64!(self.id)
        )
    }
}

impl FromBytes for NodesResponsePayload {
    named!(from_bytes<NodesResponsePayload>, do_parse!(
        nodes_number: le_u8 >>
        nodes: cond_reduce!(
            nodes_number <= 4,
            count!(PackedNode::from_bytes, nodes_number as usize)
        ) >>
        id: be_u64 >>
        eof!() >>
        (NodesResponsePayload { nodes, id })
    ));
}

#[cfg(test)]
mod tests {
    use toxcore::dht::packet::nodes_response::*;
    use toxcore::dht::packet::Packet;
    use std::net::SocketAddr;

    encode_decode_test!(
        nodes_response_payload_encode_decode,
        NodesResponsePayload { nodes: vec![
            PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &gen_keypair().0)
        ], id: 42 }
    );

    dht_packet_encode_decode!(nodes_response_encode_decode, NodesResponse);

//    dht_packet_encrypt_decrypt!(
//        nodes_response_payload_encrypt_decrypt,
//        NodesResponse,
//        NodesResponsePayload { nodes: vec![
//            PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &gen_keypair().0)
//        ], id: 42 }
//    );
//
//    dht_packet_encrypt_decrypt_invalid_key!(
//        nodes_response_payload_encrypt_decrypt_invalid_key,
//        NodesResponse,
//        NodesResponsePayload { nodes: vec![
//            PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &gen_keypair().0)
//        ], id: 42 }
//    );
//
//    dht_packet_decode_invalid!(nodes_response_decode_invalid, NodesResponse);
}
