/*! RouteResponse packet
*/

use super::*;

use crate::relay::connection_id::ConnectionId;
use nom::bytes::complete::tag;
use tox_binary_io::*;
use tox_crypto::*;

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
`1`    | connection_id [ `0x10` .. `0xFF` ]
`32`   | Public Key

*/
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RouteResponse {
    /// The id of the requested PK
    pub connection_id: ConnectionId,
    /// The requested PK
    pub pk: PublicKey,
}

impl FromBytes for RouteResponse {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x01")(input)?;
        let (input, connection_id) = ConnectionId::from_bytes(input)?;
        let (input, pk) = PublicKey::from_bytes(input)?;
        Ok((input, RouteResponse { connection_id, pk }))
    }
}

impl ToBytes for RouteResponse {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x01) >>
            gen_call!(|buf, connection_id| ConnectionId::to_bytes(connection_id, buf), &self.connection_id) >>
            gen_slice!(self.pk.as_bytes())
        )
    }
}

#[cfg(test)]
mod test {
    use rand::thread_rng;

    use super::*;

    encode_decode_test!(
        route_response_encode_decode,
        RouteResponse {
            connection_id: ConnectionId::from_index(1),
            pk: SecretKey::generate(&mut thread_rng()).public_key()
        }
    );
}
