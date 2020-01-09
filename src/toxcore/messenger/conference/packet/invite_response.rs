/*! InviteResponse response message struct.
*/

use nom::number::complete::be_u16;

use super::{ConferenceUID, ConferenceType};
use crate::toxcore::binary_io::*;

/** InviteResponse is a struct that holds info to response to invite message from a peer.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x60`
`1`       | `0x01`
`2`       | `conference id(local)`
`2`       | `conference id to join`
`1`       | `conference type`(0: text, 1: audio)
`32`      | `unique id`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InviteResponse {
    /// Local conference id
    pub conference_id_local: u16,
    /// Conference id to join
    pub conference_id_join: u16,
    /// Type of conference
    pub conference_type: ConferenceType,
    /// Unique id of conference
    pub unique_id: ConferenceUID,
}

impl FromBytes for InviteResponse {
    named!(from_bytes<InviteResponse>, do_parse!(
        tag!("\x60") >>
        tag!("\x01") >>
        conference_id_local: be_u16 >>
        conference_id_join: be_u16 >>
        conference_type: call!(ConferenceType::from_bytes) >>
        unique_id: call!(ConferenceUID::from_bytes) >>
        (InviteResponse {
            conference_id_local,
            conference_id_join,
            conference_type,
            unique_id,
        })
    ));
}

impl ToBytes for InviteResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x60) >>
            gen_be_u8!(0x01) >>
            gen_be_u16!(self.conference_id_local) >>
            gen_be_u16!(self.conference_id_join) >>
            gen_be_u8!(self.conference_type as u8) >>
            gen_slice!(self.unique_id.0)
        )
    }
}

impl InviteResponse {
    /// Create new InviteResponse object.
    pub fn new(conference_id_local: u16, conference_id_join: u16, conference_type: ConferenceType, unique_id: ConferenceUID) -> Self {
        InviteResponse {
            conference_id_local,
            conference_id_join,
            conference_type,
            unique_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        invite_response_encode_decode,
        InviteResponse::new(1, 2, ConferenceType::Audio, ConferenceUID::random())
    );
}
