/*! Online struct
*/

use super::*;
use nom::bytes::complete::tag;

/** Online is a struct that holds nothing.

This packet is used to notify that a friend is online.
When a Tox client receives this message from a friend then
the Tox client stops sending Friend request packets to the friend.
Tox client shows status of it's friend as ONLINE only after receiving this packet.

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Online;

impl FromBytes for Online {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x18")(input)?;
        Ok((input, Online))
    }
}

impl ToBytes for Online {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x18)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(online_encode_decode, Online);
}
