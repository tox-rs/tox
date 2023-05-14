/*! Typing struct.
*/

use super::*;

use nom::bytes::complete::tag;
use nom::error::{make_error, ErrorKind};
use nom::number::complete::le_u8;

/// Typing status of user
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypingStatus {
    /// Not typing
    NotTyping = 0,
    /// Typing
    Typing,
}

impl FromBytes for TypingStatus {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, b) = le_u8(input)?;
        match b {
            0 => Ok((input, TypingStatus::NotTyping)),
            1 => Ok((input, TypingStatus::Typing)),
            _ => Err(nom::Err::Error(make_error(input, ErrorKind::Switch))),
        }
    }
}

/** Typing is a struct that holds typing status of user.

This packet is used to transmit sender's typing status to a friend.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x33`
`1`       | Typing status(0 = not typing, 1 = typing)

*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Typing(TypingStatus);

impl FromBytes for Typing {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x33")(input)?;
        let (input, status) = TypingStatus::from_bytes(input)?;
        Ok((input, Typing(status)))
    }
}

impl ToBytes for Typing {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x33) >>
            gen_be_u8!(self.0 as u8)
        )
    }
}

impl Typing {
    /// Create new Typing object.
    pub fn new(status: TypingStatus) -> Self {
        Typing(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(typing_encode_decode, Typing::new(TypingStatus::Typing));
}
