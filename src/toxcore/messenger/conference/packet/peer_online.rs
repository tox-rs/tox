/*! Peer online message struct.
*/

use nom::number::complete::be_u16;

use super::{ConferenceUID, ConferenceType};
use crate::toxcore::binary_io::*;

/** PeerOnline is a struct that holds info to notify adding new peer to a conference.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x60`
`1`       | `0x00`
`2`       | `conference id`
`1`       | `conference type`(0: text, 1: audio)
`32`      | `unique id`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerOnline {
    /// Id of conference
    pub conference_id: u16,
    /// Type of conference
    pub conference_type: ConferenceType,
    /// Unique id of conference
    pub unique_id: ConferenceUID,
}

impl FromBytes for PeerOnline {
    named!(from_bytes<PeerOnline>, do_parse!(
        tag!("\x61") >>
        conference_id: be_u16 >>
        conference_type: call!(ConferenceType::from_bytes) >>
        unique_id: call!(ConferenceUID::from_bytes) >>
        (PeerOnline {
            conference_id,
            conference_type,
            unique_id,
        })
    ));
}

impl ToBytes for PeerOnline {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x61) >>
            gen_be_u16!(self.conference_id) >>
            gen_be_u8!(self.conference_type as u8) >>
            gen_slice!(self.unique_id.0)
        )
    }
}

impl PeerOnline {
    /// Create new PeerOnline object.
    pub fn new(conference_id: u16, conference_type: ConferenceType, unique_id: ConferenceUID) -> Self {
        PeerOnline {
            conference_id,
            conference_type,
            unique_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        peer_noline_encode_decode,
        PeerOnline::new(1, ConferenceType::Text, ConferenceUID::random())
    );
}
