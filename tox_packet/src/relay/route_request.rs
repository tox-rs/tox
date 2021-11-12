/*! RouteRequest packet
*/

use super::*;

use tox_binary_io::*;
use tox_crypto::*;
use nom::bytes::complete::tag;

/** Sent by client to server.
Send a routing request to the server that we want to connect
to peer with public key where the public key is the public the peer
announced themselves as. The server must respond to this with a `RouteResponse`.

Serialized form:

Length | Content
------ | ------
`1`    | `0x00`
`32`   | Public Key

*/
#[derive(Debug, PartialEq, Clone)]
pub struct RouteRequest {
    /// The requested PK
    pub pk: PublicKey,
}

impl FromBytes for RouteRequest {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x00")(input)?;
        let (input, pk) = PublicKey::from_bytes(input)?;
        Ok((input, RouteRequest { pk }))
    }
}

impl ToBytes for RouteRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x00) >>
            gen_slice!(self.pk.as_bytes())
        )
    }
}

#[cfg(test)]
mod test {
    use rand::thread_rng;

    use super::*;

    encode_decode_test!(
        route_request_encode_decode,
        RouteRequest {
            pk: SecretKey::generate(&mut thread_rng()).public_key()
        }
    );
}
