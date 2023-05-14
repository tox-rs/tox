/*! Alive struct
*/

use super::*;

use nom::bytes::complete::tag;

/// Id of the ping packet.
pub const PACKET_ID_ALIVE: u8 = 0x10;

/** Alive is a struct that holds nothing.

This packet is used to check if the friend is online by sending this packet
every 8 seconds using net_crypto connection.
If one node has not received this packet for 32 seconds, the friend connection is timed out
and destroyed.

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Alive;

impl FromBytes for Alive {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag(&[PACKET_ID_ALIVE][..])(input)?;
        Ok((input, Alive))
    }
}

impl ToBytes for Alive {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        gen_be_u8!(buf, PACKET_ID_ALIVE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(alive_encode_decode, Alive);
}
