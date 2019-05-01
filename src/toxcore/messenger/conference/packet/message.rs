/*! Conference chat message struct.
*/

use std::str;
use nom::{be_u16, be_u32, rest};

use crate::toxcore::binary_io::*;

/** Message is the struct that holds info to send chat message to a conference.

Sent to notify chat message to all member of conference.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x63`
`2`       | `conference number`
`2`       | `peer number`
`4`       | `message number`
`1`       | `0x40`
variable  | `message`(UTF-8 C String)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    conference_number: u16,
    peer_number: u16,
    message_number: u32,
    /// Maximum length of message is the limit of NetCrypto packet.
    /// Do not check the length here.
    message: String,
}

impl FromBytes for Message {
    named!(from_bytes<Message>, do_parse!(
        tag!("\x63") >>
        conference_number: be_u16 >>
        peer_number: be_u16 >>
        message_number: be_u32 >>
        tag!("\x40") >>
        message: map_res!(rest, str::from_utf8) >>
        (Message {
            conference_number,
            peer_number,
            message_number,
            message: message.to_string(),
        })
    ));
}

impl ToBytes for Message {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x63) >>
            gen_be_u16!(self.conference_number) >>
            gen_be_u16!(self.peer_number) >>
            gen_be_u32!(self.message_number) >>
            gen_be_u8!(0x40) >>
            gen_slice!(self.message.as_bytes())
        )
    }
}

impl Message {
    /// Create new Message object.
    pub fn new(conference_number: u16, peer_number: u16, message_number: u32, message: String) -> Self {
        Message {
            conference_number,
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
        conference_message_encode_decode,
        Message::new(1, 2, 3, "1234".to_owned())
    );

    #[test]
    fn conference_message_from_bytes_encoding_error() {
        let err_string = vec![0, 159, 146, 150]; // not UTF8 bytes.
        let mut buf = vec![0x63, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40];
        buf.extend_from_slice(&err_string);
        assert!(Message::from_bytes(&buf).is_err());
    }
}
