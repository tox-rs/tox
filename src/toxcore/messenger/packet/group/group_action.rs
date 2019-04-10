/*! Group action action struct.
*/

use std::str;
use nom::{be_u16, be_u32, rest};

use crate::toxcore::binary_io::*;

/** GroupAction is the struct that holds info to send action to a group chat.

Sent to notify action to all member of group chat.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x63`
`2`       | `group number`
`2`       | `peer number`
`4`       | `action number`
`1`       | `0x41`
variable  | `action`(UTF-8 C String)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupAction {
    group_number: u16,
    peer_number: u16,
    message_number: u32,
    /// Maximum length of action is the limit of NetCrypto packet.
    /// Do not check the length here.
    action: String,
}

impl FromBytes for GroupAction {
    named!(from_bytes<GroupAction>, do_parse!(
        tag!("\x63") >>
        group_number: be_u16 >>
        peer_number: be_u16 >>
        message_number: be_u32 >>
        tag!("\x41") >>
        action: map_res!(rest, str::from_utf8) >>
        (GroupAction {
            group_number,
            peer_number,
            message_number,
            action: action.to_string(),
        })
    ));
}

impl ToBytes for GroupAction {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x63) >>
            gen_be_u16!(self.group_number) >>
            gen_be_u16!(self.peer_number) >>
            gen_be_u32!(self.message_number) >>
            gen_be_u8!(0x41) >>
            gen_slice!(self.action.as_bytes())
        )
    }
}

impl GroupAction {
    /// Create new GroupAction object.
    pub fn new(group_number: u16, peer_number: u16, message_number: u32, action: String) -> Self {
        GroupAction {
            group_number,
            peer_number,
            message_number,
            action,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        group_action_encode_decode,
        GroupAction::new(1, 2, 3, "1234".to_owned())
    );

    #[test]
    fn group_action_from_bytes_encoding_error() {
        let err_string = vec![0, 159, 146, 150]; // not UTF8 bytes.
        let mut buf = vec![0x63, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x41];
        buf.extend_from_slice(&err_string);
        assert!(GroupAction::from_bytes(&buf).is_err());
    }
}
