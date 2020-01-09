/*! Typing struct.
*/

use nom::number::complete::le_u8;

use crate::toxcore::binary_io::*;

/// Typing status of user
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypingStatus {
    /// Not typing
    NotTyping = 0,
    /// Typing
    Typing,
}

impl FromBytes for TypingStatus {
    named!(from_bytes<TypingStatus>,
        switch!(le_u8,
            0 => value!(TypingStatus::NotTyping) |
            1 => value!(TypingStatus::Typing)
        )
    );
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
    named!(from_bytes<Typing>, do_parse!(
        tag!("\x33") >>
        status: call!(TypingStatus::from_bytes) >>
        (Typing(status))
    ));
}

impl ToBytes for Typing {
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

    encode_decode_test!(
        typing_encode_decode,
        Typing::new(TypingStatus::Typing)
    );
}
