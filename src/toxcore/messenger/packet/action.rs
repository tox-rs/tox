/*! Action message struct.
*/

use std::str;
use nom::combinator::rest;

use crate::toxcore::binary_io::*;

/// Maximum size in bytes of action message string of action packet
const MAX_ACTION_MESSAGE_DATA_SIZE: usize = 1372;

/** Action is a struct that holds string of my action message.
Here, action message is a something like an IRC action

This packet is used to transmit sender's action message to a friend.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x41`
`0..1372` | UTF8 byte string

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Action {
    msg: String,
}

impl FromBytes for Action {
    named!(from_bytes<Action>, do_parse!(
        tag!("\x41") >>
        msg: map_res!(verify!(rest, |msg: &[u8]| msg.len() <= MAX_ACTION_MESSAGE_DATA_SIZE),
            str::from_utf8) >>
        (Action { msg: msg.to_string() })
    ));
}

impl ToBytes for Action {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x41) >>
            gen_cond!(self.msg.len() > MAX_ACTION_MESSAGE_DATA_SIZE, |buf| gen_error(buf, 0)) >>
            gen_slice!(self.msg.as_bytes())
        )
    }
}

impl Action {
    /// Create new Action object.
    pub fn new(msg: String) -> Self {
        Action { msg }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        action_encode_decode,
        Action::new("1234".to_string())
    );

    #[test]
    fn action_from_bytes_encoding_error() {
        let err_string = vec![0, 159, 146, 150]; // not UTF8 bytes.
        assert!(Action::from_bytes(&err_string).is_err());
    }

    #[test]
    fn action_from_bytes_overflow() {
        let large_string = vec![32; MAX_ACTION_MESSAGE_DATA_SIZE + 1];
        assert!(Action::from_bytes(&large_string).is_err());
    }

    #[test]
    fn action_to_bytes_overflow() {
        let large_string = String::from_utf8(vec![32u8; MAX_ACTION_MESSAGE_DATA_SIZE + 1]).unwrap();
        let large_msg = Action::new(large_string);
        let mut buf = [0; MAX_ACTION_MESSAGE_DATA_SIZE + 1]; // `1` is for packet_id.
        assert!(large_msg.to_bytes((&mut buf, 0)).is_err());
    }
}
