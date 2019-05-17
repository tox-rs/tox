/*! Peer leave message struct.
*/

use nom::number::complete::be_u16;

use crate::toxcore::binary_io::*;

/** PeerLeave is a struct that holds info to notify a peer quit a conference.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x62`
`2`       | `conference id`
`1`       | `0x01`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerLeave(pub u16);

impl FromBytes for PeerLeave {
    named!(from_bytes<PeerLeave>, do_parse!(
        tag!("\x62") >>
        conference_id: be_u16 >>
        tag!("\x01") >>
        (PeerLeave(conference_id))
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
    pub fn new(conference_id: u16) -> Self {
        PeerLeave(conference_id)
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
