/*! UserStatus struct.
*/

use super::*;

use nom::number::complete::le_u8;
use nom::bytes::complete::tag;
use nom::error::{ErrorKind, make_error};

/// Status of user
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerStatus {
    /// Online
    Online = 0,
    /// Away
    Away,
    /// Online but I am busy
    Busy,
}

impl FromBytes for PeerStatus {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, b) = le_u8(input)?;
        match b {
            0 => Ok((input, PeerStatus::Online)),
            1 => Ok((input, PeerStatus::Away)),
            2 => Ok((input, PeerStatus::Busy)),
            _ => Err(nom::Err::Error(make_error(input, ErrorKind::Switch))),
        }
    }
}

/** UserStatus is a struct that holds status of user.

This packet is used to transmit sender's status to a friend.
Every time a friend become online or my status is changed,
this packet is sent to the friend or to all friends of mine.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x32`
`1`       | My status(0 = online, 1 = away, 2 = busy)

*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserStatus(PeerStatus);

impl FromBytes for UserStatus {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x32")(input)?;
        let (input, status) = PeerStatus::from_bytes(input)?;
        Ok((input, UserStatus(status)))
    }
}

impl ToBytes for UserStatus {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x32) >>
            gen_be_u8!(self.0 as u8)
        )
    }
}

impl UserStatus {
    /// Create new UserStatus object.
    pub fn new(status: PeerStatus) -> Self {
        UserStatus(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        user_status_encode_decode,
        UserStatus::new(PeerStatus::Online)
    );
}
