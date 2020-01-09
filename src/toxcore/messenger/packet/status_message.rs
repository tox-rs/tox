/*! StatusMessage struct.
It is used to send my status message to a friend.
This packet is sent to my friends every time they become online, or whenever my status message is changed.
*/

use std::str;
use nom::combinator::rest;

use crate::toxcore::binary_io::*;

/// Maximum size in bytes of status message string
const MAX_STATUS_MESSAGE_DATA_SIZE: usize = 1007;

/** StatusMessage is a struct that holds string of my status message.

This packet is used to transmit sender's status message to a friend.
Every time a friend become online or my status message is changed,
this packet is sent to the friend or to all friends of mine.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x31`
`0..1007`  | UTF8 byte string

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusMessage(String);

impl FromBytes for StatusMessage {
    named!(from_bytes<StatusMessage>, do_parse!(
        tag!("\x31") >>
        message: map_res!(verify!(rest, |message: &[u8]| message.len() <= MAX_STATUS_MESSAGE_DATA_SIZE),
            str::from_utf8) >>
        (StatusMessage(message.to_string()))
    ));
}

impl ToBytes for StatusMessage {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x31) >>
            gen_cond!(self.0.len() > MAX_STATUS_MESSAGE_DATA_SIZE, |buf| gen_error(buf, 0)) >>
            gen_slice!(self.0.as_bytes())
        )
    }
}

impl StatusMessage {
    /// Create new StatusMessage object.
    pub fn new(message: String) -> Self {
        StatusMessage(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        status_message_encode_decode,
        StatusMessage::new("Happy!".to_string())
    );

    #[test]
    fn status_message_from_bytes_encoding_error() {
        let err_string = vec![0, 159, 146, 150]; // not UTF8 bytes.
        assert!(StatusMessage::from_bytes(&err_string).is_err());
    }

    #[test]
    fn nickname_from_bytes_overflow() {
        let large_string = vec![32; MAX_STATUS_MESSAGE_DATA_SIZE + 1];
        assert!(StatusMessage::from_bytes(&large_string).is_err());
    }

    #[test]
    fn nickname_to_bytes_overflow() {
        let large_string = String::from_utf8(vec![32u8; MAX_STATUS_MESSAGE_DATA_SIZE + 1]).unwrap();
        let large_message = StatusMessage::new(large_string);
        let mut buf = [0; MAX_STATUS_MESSAGE_DATA_SIZE + 1]; // `1` is for packet_id.
        assert!(large_message.to_bytes((&mut buf, 0)).is_err());
    }
}
