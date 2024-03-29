/*! InviteResponse response message struct.
*/

use super::*;

use nom::bytes::complete::tag;
use nom::number::complete::be_u16;

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
    pub unique_id: ConferenceUid,
}

impl FromBytes for InviteResponse {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x60")(input)?;
        let (input, _) = tag("\x01")(input)?;
        let (input, conference_id_local) = be_u16(input)?;
        let (input, conference_id_join) = be_u16(input)?;
        let (input, conference_type) = ConferenceType::from_bytes(input)?;
        let (input, unique_id) = ConferenceUid::from_bytes(input)?;
        Ok((
            input,
            InviteResponse {
                conference_id_local,
                conference_id_join,
                conference_type,
                unique_id,
            },
        ))
    }
}

impl ToBytes for InviteResponse {
    #[rustfmt::skip]
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
    pub fn new(
        conference_id_local: u16,
        conference_id_join: u16,
        conference_type: ConferenceType,
        unique_id: ConferenceUid,
    ) -> Self {
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
        InviteResponse::new(1, 2, ConferenceType::Audio, ConferenceUid([42; CONFERENCE_UID_BYTES]))
    );
}
