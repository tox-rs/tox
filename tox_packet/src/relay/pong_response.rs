/*! PongResponse packet
*/

use super::*;

use tox_binary_io::*;

use nom::number::complete::be_u64;
use nom::bytes::complete::tag;

/** Sent by both client and server, both will respond.
The server should respond to ping packets with pong packets with the same `ping_id`
as was in the ping packet. The server should check that each pong packet contains
the same `ping_id` as was in the ping, if not the pong packet must be ignored.

Serialized form:

Length | Content
------ | ------
`1`    | `0x05`
`8`    | ping_id in BigEndian

*/
#[derive(Debug, PartialEq, Clone)]
pub struct PongResponse {
    /// The id of ping to respond
    pub ping_id: u64
}

impl FromBytes for PongResponse {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x05")(input)?;
        let (input, ping_id) = be_u64(input)?;
        Ok((input, PongResponse {  ping_id }))
    }
}

impl ToBytes for PongResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x05) >>
            gen_be_u64!(self.ping_id)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        pong_response_encode_decode,
        PongResponse {
            ping_id: 12345
        }
    );
}
