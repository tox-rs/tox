/*! Peer leave message struct.
*/

use nom::be_u16;

use crate::toxcore::binary_io::*;

/** PeerLeave is a struct that holds info to notify a peer quit a group chat.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x62`
`2`       | `group number`
`1`       | `0x01`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerLeave(u16);

impl FromBytes for PeerLeave {
    named!(from_bytes<PeerLeave>, do_parse!(
        tag!("\x62") >>
        group_number: be_u16 >>
        tag!("\x01") >>
        (PeerLeave(group_number))
    ));
}

impl ToBytes for PeerLeave {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x62) >>
            gen_be_u16!(self.0) >>
            gen_be_u8!(0x01)
        )
    }
}

impl PeerLeave {
    /// Create new PeerLeave object.
    pub fn new(group_number: u16) -> Self {
        PeerLeave(group_number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        peer_leave_encode_decode,
        PeerLeave::new(1)
    );
}
