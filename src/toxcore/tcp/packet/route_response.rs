/*! RouteResponse packet
*/

use toxcore::binary_io::*;
use toxcore::crypto_core::*;

use nom::be_u8;

/** Sent by server to client.
The response to the routing request, tell the client if the
routing request succeeded (valid `connection_id`) and if it did,
tell them the id of the connection (`connection_id`). The public
key sent in the routing request is also sent in the response so
that the client can send many requests at the same time to the
server without having code to track which response belongs to which public key.

Serialized form:

Length | Content
------ | ------
`1`    | `0x01`
`1`    | connection_id
`32`   | Public Key

*/
#[derive(Debug, PartialEq, Clone)]
pub struct RouteResponse {
    /// The id of the requested PK
    pub connection_id: u8,
    /// The requested PK
    pub pk: PublicKey,
}

impl FromBytes for RouteResponse {
    named!(from_bytes<RouteResponse>, do_parse!(
        tag!("\x01") >>
        connection_id: be_u8 >>
        pk: call!(PublicKey::from_bytes) >>
        (RouteResponse { connection_id, pk })
    ));
}

impl ToBytes for RouteResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x01) >>
            gen_be_u8!(self.connection_id) >>
            gen_slice!(self.pk.as_ref())
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        route_response_encode_decode,
        RouteResponse {
            connection_id: 17,
            pk: gen_keypair().0
        }
    );
}
