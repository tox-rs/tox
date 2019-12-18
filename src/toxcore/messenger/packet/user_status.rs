/*! UserStatus struct.
*/

use nom::number::complete::le_u8;

use crate::toxcore::binary_io::*;

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
    named!(from_bytes<PeerStatus>,
        switch!(le_u8,
            0 => value!(PeerStatus::Online) |
            1 => value!(PeerStatus::Away) |
            2 => value!(PeerStatus::Busy)
        )
    );
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
    named!(from_bytes<UserStatus>, do_parse!(
        tag!("\x32") >>
        status: call!(PeerStatus::from_bytes) >>
        (UserStatus(status))
    ));
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
