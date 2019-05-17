/*! Nickname struct.
*/

use std::str;
use nom::combinator::rest;

use crate::toxcore::binary_io::*;

/// Maximum size in bytes of nickname string of nickname packet
const MAX_NICKNAME_DATA_SIZE: usize = 128;

/** Nickname is a struct that holds string of my nickname.

This packet is used to transmit sender's nickname to a friend.
Every time a friend become online or my nickname is changed,
this packet is sent to the friend or to all friends of mine.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x30`
`0..128`  | UTF8 byte string

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nickname {
    nickname: String,
}

impl FromBytes for Nickname {
    named!(from_bytes<Nickname>, do_parse!(
        tag!("\x30") >>
        nickname: map_res!(verify!(rest, |nickname: &[u8]| nickname.len() <= MAX_NICKNAME_DATA_SIZE),
            str::from_utf8) >>
        (Nickname { nickname: nickname.to_string() })
    ));
}

impl ToBytes for Nickname {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x30) >>
            gen_cond!(self.nickname.len() > MAX_NICKNAME_DATA_SIZE, |buf| gen_error(buf, 0)) >>
            gen_slice!(self.nickname.as_bytes())
        )
    }
}

impl Nickname {
    /// Create new Nickname object.
    pub fn new(nickname: String) -> Self {
        Nickname { nickname }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        nickname_encode_decode,
        Nickname::new("1234".to_string())
    );

    #[test]
    fn nickname_from_bytes_encoding_error() {
        let err_string = vec![0, 159, 146, 150]; // not UTF8 bytes.
        assert!(Nickname::from_bytes(&err_string).is_err());
    }

    #[test]
    fn nickname_from_bytes_overflow() {
        let large_string = vec![32; 300];
        assert!(Nickname::from_bytes(&large_string).is_err());
    }

    #[test]
    fn nickname_to_bytes_overflow() {
        let large_string = String::from_utf8(vec![32u8; 300]).unwrap();
        let large_nickname = Nickname::new(large_string);
        let mut buf = [0; MAX_NICKNAME_DATA_SIZE + 1]; // `1` is for packet_id.
        assert!(large_nickname.to_bytes((&mut buf, 0)).is_err());
    }
}
