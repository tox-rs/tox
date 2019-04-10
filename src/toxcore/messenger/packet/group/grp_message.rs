/*! Group chat message struct.
*/

use std::str;
use nom::{be_u16, be_u32, rest};

use crate::toxcore::binary_io::*;

/** GrpMessage is the struct that holds info to change message of a group chat.

Sent to send chat message to all member of group chat.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x63`
`2`       | `group number`
`2`       | `peer number`
`4`       | `message number`
`1`       | `0x40`
variable  | `message`(UTF-8 C String)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpMessage {
    group_number: u16,
    peer_number: u16,
    message_number: u32,
    /// Maximum length of message is the limit of NetCrypto packet.
    /// Do not check the length here.
    message: String,
}

impl FromBytes for GrpMessage {
    named!(from_bytes<GrpMessage>, do_parse!(
        tag!("\x63") >>
        group_number: be_u16 >>
        peer_number: be_u16 >>
        message_number: be_u32 >>
        tag!("\x40") >>
        message: map_res!(rest, str::from_utf8) >>
        (GrpMessage {
            group_number,
            peer_number,
            message_number,
            message: message.to_string(),
        })
    ));
}

impl ToBytes for GrpMessage {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x63) >>
            gen_be_u16!(self.group_number) >>
            gen_be_u16!(self.peer_number) >>
            gen_be_u32!(self.message_number) >>
            gen_be_u8!(0x40) >>
            gen_slice!(self.message.as_bytes())
        )
    }
}

impl GrpMessage {
    /// Create new GrpMessage object.
    pub fn new(group_number: u16, peer_number: u16, message_number: u32, message: String) -> Self {
        GrpMessage {
            group_number,
            peer_number,
            message_number,
            message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        change_message_encode_decode,
        GrpMessage::new(1, 2, 3, "1234".to_owned())
    );

    // Test for encoding error of from_bytes.
    #[test]
    fn change_message_from_bytes_encoding_error() {
        let err_string = vec![0, 159, 146, 150]; // not UTF8 bytes.
        let mut buf = vec![0x63, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x31];
        buf.extend_from_slice(&err_string);
        assert!(GrpMessage::from_bytes(&buf).is_err());
    }
}
