/*! Conference action action struct.
*/

use std::str;
use nom::{
    number::complete::{be_u16, be_u32},
    combinator::rest,
};

use crate::toxcore::binary_io::*;

/** Action is the struct that holds info to send action to a conference.

Sent to notify action to all member of conference.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x63`
`2`       | `conference id`
`2`       | `peer id`
`4`       | `action id`
`1`       | `0x41`
variable  | `action`(UTF-8 C String)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Action {
    /// Id of conference
    pub conference_id: u16,
    /// Target peer id
    pub peer_id: u16,
    /// Id of this message
    pub message_id: u32,
    /// Maximum length of action is the limit of NetCrypto packet.
    /// Do not check the length here.
    pub action: String,
}

impl FromBytes for Action {
    named!(from_bytes<Action>, do_parse!(
        tag!("\x63") >>
        conference_id: be_u16 >>
        peer_id: be_u16 >>
        message_id: be_u32 >>
        tag!("\x41") >>
        action: map_res!(rest, str::from_utf8) >>
        (Action {
            conference_id,
            peer_id,
            message_id,
            action: action.to_string(),
        })
    ));
}

impl ToBytes for Action {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x63) >>
            gen_be_u16!(self.conference_id) >>
            gen_be_u16!(self.peer_id) >>
            gen_be_u32!(self.message_id) >>
            gen_be_u8!(0x41) >>
            gen_slice!(self.action.as_bytes())
        )
    }
}

impl Action {
    /// Create new Action object.
    pub fn new(conference_id: u16, peer_id: u16, message_id: u32, action: String) -> Self {
        Action {
            conference_id,
            peer_id,
            message_id,
            action,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        conference_action_encode_decode,
        Action::new(1, 2, 3, "1234".to_owned())
    );

    #[test]
    fn conference_action_from_bytes_encoding_error() {
        let err_string = vec![0, 159, 146, 150]; // not UTF8 bytes.
        let mut buf = vec![0x63, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x41];
        buf.extend_from_slice(&err_string);
        assert!(Action::from_bytes(&buf).is_err());
    }
}
