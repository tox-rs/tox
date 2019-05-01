/*! Change title message struct.
*/

use std::str;
use nom::{be_u16, be_u32, rest};

use crate::toxcore::binary_io::*;
use super::MAX_NAME_LENGTH_IN_CONFERENCE;

/** ChangeTitle is the struct that holds info to change title of a conference.

Sent by anyone who is member of conference.
This packet is used to change the title of conference.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x63`
`2`       | `conference number`
`2`       | `peer number`
`4`       | `message number`
`1`       | `0x31`
variable  | `title`(UTF-8 C String)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeTitle {
    conference_number: u16,
    peer_number: u16,
    message_number: u32,
    title: String,
}

impl FromBytes for ChangeTitle {
    named!(from_bytes<ChangeTitle>, do_parse!(
        tag!("\x63") >>
        conference_number: be_u16 >>
        peer_number: be_u16 >>
        message_number: be_u32 >>
        tag!("\x31") >>
        title: map_res!(verify!(rest, |title: &[u8]| title.len() <= MAX_NAME_LENGTH_IN_CONFERENCE),
            str::from_utf8) >>
        (ChangeTitle {
            conference_number,
            peer_number,
            message_number,
            title: title.to_string(),
        })
    ));
}

impl ToBytes for ChangeTitle {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x63) >>
            gen_be_u16!(self.conference_number) >>
            gen_be_u16!(self.peer_number) >>
            gen_be_u32!(self.message_number) >>
            gen_be_u8!(0x31) >>
            gen_cond!(self.title.len() > MAX_NAME_LENGTH_IN_CONFERENCE, |buf| gen_error(buf, 0)) >>
            gen_slice!(self.title.as_bytes())
        )
    }
}

impl ChangeTitle {
    /// Create new ChangeTitle object.
    pub fn new(conference_number: u16, peer_number: u16, message_number: u32, title: String) -> Self {
        ChangeTitle {
            conference_number,
            peer_number,
            message_number,
            title,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        change_title_encode_decode,
        ChangeTitle::new(1, 2, 3, "1234".to_owned())
    );

    #[test]
    fn change_title_from_bytes_encoding_error() {
        let err_string = vec![0, 159, 146, 150]; // not UTF8 bytes.
        let mut buf = vec![0x63, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x31];
        buf.extend_from_slice(&err_string);
        assert!(ChangeTitle::from_bytes(&buf).is_err());
    }

    #[test]
    fn change_title_from_bytes_overflow() {
        let large_string = vec![32; MAX_NAME_LENGTH_IN_CONFERENCE + 1];
        let mut buf = vec![0x63, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x31];
        buf.extend_from_slice(&large_string);
        assert!(ChangeTitle::from_bytes(&buf).is_err());
    }

    #[test]
    fn change_title_to_bytes_overflow() {
        let large_string = String::from_utf8(vec![32u8; MAX_NAME_LENGTH_IN_CONFERENCE + 1]).unwrap();
        let large_title = ChangeTitle::new(1,2, 3, large_string);
        let mut buf = [0; MAX_NAME_LENGTH_IN_CONFERENCE + 1 + 2 + 2 + 4 + 1]; // packet id + conference number + peer number + message number + message kind.
        assert!(large_title.to_bytes((&mut buf, 0)).is_err());
    }
}
