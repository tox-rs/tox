/*! Offline struct
*/

use super::*;

use nom::bytes::complete::tag;

/** Offline is a struct that holds nothing.

This packet is used to notify that a friend is being deleted.
Though the friend is deleted, because of conference, Tox client
may try to connect to the friend, this message prevent this friend to
be shown as Online.

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Offline;

impl FromBytes for Offline {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x19")(input)?;
        Ok((input, Offline))
    }
}

impl ToBytes for Offline {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x19)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(offline_encode_decode, Offline);
}
