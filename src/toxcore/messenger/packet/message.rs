/*! Message struct.
*/

use std::str;
use nom::combinator::rest;

use crate::toxcore::binary_io::*;

/// Maximum size in bytes of message string of message packet
const MAX_MESSAGE_DATA_SIZE: usize = 1372;

/** Message is a struct that holds string of my message.

This packet is used to transmit sender's message to a friend.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x40`
`0..1372` | UTF8 byte string

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    msg: String,
}

impl FromBytes for Message {
    named!(from_bytes<Message>, do_parse!(
        tag!("\x40") >>
        msg: map_res!(verify!(rest, |msg: &[u8]| msg.len() <= MAX_MESSAGE_DATA_SIZE),
            str::from_utf8) >>
        (Message { msg: msg.to_string() })
    ));
}

impl ToBytes for Message {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x40) >>
            gen_cond!(self.msg.len() > MAX_MESSAGE_DATA_SIZE, |buf| gen_error(buf, 0)) >>
            gen_slice!(self.msg.as_bytes())
        )
    }
}

impl Message {
    /// Create new Message object.
    pub fn new(msg: String) -> Self {
        Message { msg }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        message_encode_decode,
        Message::new("1234".to_string())
    );

    #[test]
    fn message_from_bytes_encoding_error() {
        let err_string = vec![0, 159, 146, 150]; // not UTF8 bytes.
        assert!(Message::from_bytes(&err_string).is_err());
    }

    #[test]
    fn message_from_bytes_overflow() {
        let large_string = vec![32; MAX_MESSAGE_DATA_SIZE + 1];
        assert!(Message::from_bytes(&large_string).is_err());
    }

    #[test]
    fn message_to_bytes_overflow() {
        let large_string = String::from_utf8(vec![32u8; MAX_MESSAGE_DATA_SIZE + 1]).unwrap();
        let large_msg = Message::new(large_string);
        let mut buf = [0; MAX_MESSAGE_DATA_SIZE + 1]; // `1` is for packet_id.
        assert!(large_msg.to_bytes((&mut buf, 0)).is_err());
    }
}
