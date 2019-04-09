/*! Peer online message struct.
*/

use nom::be_u16;

use super::{GroupUID, GroupType};
use crate::toxcore::binary_io::*;

/** PeerOnline is a struct that holds info to notify adding new peer to a group chat.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x60`
`1`       | `0x00`
`2`       | `group number`
`1`       | `group type`(0: text, 1: audio)
`32`      | `unique id`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerOnline {
    group_number: u16,
    group_type: GroupType,
    unique_id: GroupUID,
}

impl FromBytes for PeerOnline {
    named!(from_bytes<PeerOnline>, do_parse!(
        tag!("\x61") >>
        group_number: be_u16 >>
        group_type: call!(GroupType::from_bytes) >>
        unique_id: call!(GroupUID::from_bytes) >>
        (PeerOnline {
            group_number,
            group_type,
            unique_id,
        })
    ));
}

impl ToBytes for PeerOnline {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x61) >>
            gen_be_u16!(self.group_number) >>
            gen_be_u8!(self.group_type as u8) >>
            gen_slice!(self.unique_id.0)
        )
    }
}

impl PeerOnline {
    /// Create new PeerOnline object.
    pub fn new(group_number: u16, group_type: GroupType, unique_id: GroupUID) -> Self {
        PeerOnline {
            group_number,
            group_type,
            unique_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        peer_noline_encode_decode,
        PeerOnline::new(1, GroupType::Text, GroupUID::new())
    );
}
