/*! Change name message struct.
*/

use std::str;
use nom::{
    number::complete::{be_u16, be_u32},
    combinator::rest,
};

use crate::toxcore::binary_io::*;
use super::MAX_NAME_LENGTH_IN_CONFERENCE;

/** ChangeName is the struct that holds info to notify changing name of a peer to a conference.

Sent by a peer who wants to change its name or by a joining peer to notify its name to members of conference.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x63`
`2`       | `conference id`
`2`       | `peer id`
`4`       | `message id`
`1`       | `0x30`
variable  | `name`(UTF-8 C String)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeName {
    /// Id of conference
    pub conference_id: u16,
    /// Target peer id
    pub peer_id: u16,
    /// Id of this message
    pub message_id: u32,
    /// Name to change
    pub name: String,
}

impl FromBytes for ChangeName {
    named!(from_bytes<ChangeName>, do_parse!(
        tag!("\x63") >>
        conference_id: be_u16 >>
        peer_id: be_u16 >>
        message_id: be_u32 >>
        tag!("\x30") >>
        name: map_res!(verify!(rest, |name: &[u8]| name.len() <= MAX_NAME_LENGTH_IN_CONFERENCE),
            str::from_utf8) >>
        (ChangeName {
            conference_id,
            peer_id,
            message_id,
            name: name.to_string(),
        })
    ));
}

impl ToBytes for ChangeName {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x63) >>
            gen_be_u16!(self.conference_id) >>
            gen_be_u16!(self.peer_id) >>
            gen_be_u32!(self.message_id) >>
            gen_be_u8!(0x30) >>
            gen_cond!(self.name.len() > MAX_NAME_LENGTH_IN_CONFERENCE, |buf| gen_error(buf, 0)) >>
            gen_slice!(self.name.as_bytes())
        )
    }
}

impl ChangeName {
    /// Create new ChangeName object.
    pub fn new(conference_id: u16, peer_id: u16, message_id: u32, name: String) -> Self {
        ChangeName {
            conference_id,
            peer_id,
            message_id,
            name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        change_name_encode_decode,
        ChangeName::new(1, 2, 3, "1234".to_owned())
    );

    #[test]
    fn change_name_from_bytes_encoding_error() {
        let err_string = vec![0, 159, 146, 150]; // not UTF8 bytes.
        let mut buf = vec![0x63, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x30];
        buf.extend_from_slice(&err_string);
        assert!(ChangeName::from_bytes(&buf).is_err());
    }

    #[test]
    fn change_name_from_bytes_overflow() {
        let large_string = vec![32; MAX_NAME_LENGTH_IN_CONFERENCE + 1];
        let mut buf = vec![0x63, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x30];
        buf.extend_from_slice(&large_string);
        assert!(ChangeName::from_bytes(&buf).is_err());
    }

    #[test]
    fn change_name_to_bytes_overflow() {
        let large_string = String::from_utf8(vec![32u8; MAX_NAME_LENGTH_IN_CONFERENCE + 1]).unwrap();
        let large_name = ChangeName::new(1,2, 3, large_string);
        let mut buf = [0; MAX_NAME_LENGTH_IN_CONFERENCE + 1 + 2 + 2 + 4 + 1]; // packet id + conference id + peer id + message id + message kind.
        assert!(large_name.to_bytes((&mut buf, 0)).is_err());
    }
}
