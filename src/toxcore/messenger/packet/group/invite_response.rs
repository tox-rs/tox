/*! InviteResponse response message struct.
*/

use nom::be_u16;

use super::{GroupUID, GroupType};
use crate::toxcore::binary_io::*;

/** InviteResponse is a struct that holds info to response to invite message from a peer.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x60`
`1`       | `0x01`
`2`       | `group number(local)`
`2`       | `group number to join`
`1`       | `group type`(0: text, 1: audio)
`32`      | `unique id`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InviteResponse {
    group_number_local: u16,
    group_number_join: u16,
    group_type: GroupType,
    unique_id: GroupUID,
}

impl FromBytes for InviteResponse {
    named!(from_bytes<InviteResponse>, do_parse!(
        tag!("\x60") >>
        tag!("\x01") >>
        group_number_local: be_u16 >>
        group_number_join: be_u16 >>
        group_type: call!(GroupType::from_bytes) >>
        unique_id: call!(GroupUID::from_bytes) >>
        (InviteResponse {
            group_number_local,
            group_number_join,
            group_type,
            unique_id,
        })
    ));
}

impl ToBytes for InviteResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x60) >>
            gen_be_u8!(0x01) >>
            gen_be_u16!(self.group_number_local) >>
            gen_be_u16!(self.group_number_join) >>
            gen_be_u8!(self.group_type as u8) >>
            gen_slice!(self.unique_id.0)
        )
    }
}

impl InviteResponse {
    /// Create new InviteResponse object.
    pub fn new(group_number_local: u16, group_number_join: u16, group_type: GroupType, unique_id: GroupUID) -> Self {
        InviteResponse {
            group_number_local,
            group_number_join,
            group_type,
            unique_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        invite_response_encode_decode,
        InviteResponse::new(1, 2, GroupType::Audio, GroupUID::random())
    );
}
