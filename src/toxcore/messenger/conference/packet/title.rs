/*! Title message struct.
*/

use std::str;
use nom::{
    number::complete::be_u16,
    combinator::rest,
};

use crate::toxcore::binary_io::*;
use super::MAX_NAME_LENGTH_IN_CONFERENCE;

/** Title is a struct that holds info to send a title packet to a conference.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x62`
`2`       | `conference id`
`1`       | `0x0a`
variable  | title(UTF-8 C String)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Title {
    /// Id of conference
    pub conference_id: u16,
    /// Title of conference
    pub title: String,
}

impl FromBytes for Title {
    named!(from_bytes<Title>, do_parse!(
        tag!("\x62") >>
        conference_id: be_u16 >>
        tag!("\x0a") >>
        title: map_res!(verify!(rest, |title: &[u8]| title.len() <= MAX_NAME_LENGTH_IN_CONFERENCE),
            str::from_utf8) >>
        (Title {
            conference_id,
            title: title.to_string(),
        })
    ));
}

impl ToBytes for Title {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x62) >>
            gen_be_u16!(self.conference_id) >>
            gen_be_u8!(0x0a) >>
            gen_cond!(self.title.len() > MAX_NAME_LENGTH_IN_CONFERENCE, |buf| gen_error(buf, 0)) >>
            gen_slice!(self.title.as_bytes())
        )
    }
}

impl Title {
    /// Create new Title object.
    pub fn new(conference_id: u16, title: String) -> Self {
        Title {
            conference_id,
            title,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        title_encode_decode,
        Title::new(1, "1234".to_owned())
    );

    #[test]
    fn title_from_bytes_encoding_error() {
        let err_string = vec![0, 159, 146, 150]; // not UTF8 bytes.
        let mut buf = vec![0x62, 0x01, 0x00, 0x0a];
        buf.extend_from_slice(&err_string);
        assert!(Title::from_bytes(&buf).is_err());
    }

    #[test]
    fn title_from_bytes_overflow() {
        let large_string = vec![32; MAX_NAME_LENGTH_IN_CONFERENCE + 1];
        let mut buf = vec![0x62, 0x01, 0x00, 0x0a];
        buf.extend_from_slice(&large_string);
        assert!(Title::from_bytes(&buf).is_err());
    }

    #[test]
    fn title_to_bytes_overflow() {
        let large_string = String::from_utf8(vec![32u8; MAX_NAME_LENGTH_IN_CONFERENCE + 1]).unwrap();
        let large_title = Title::new(1,large_string);
        let mut buf = [0; MAX_NAME_LENGTH_IN_CONFERENCE + 1 + 2 + 1]; // packet id + conference id + packet kind.
        assert!(large_title.to_bytes((&mut buf, 0)).is_err());
    }
}
