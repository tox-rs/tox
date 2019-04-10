/*! Change name message struct.
*/

use std::str;
use nom::{be_u16, be_u32, rest};

use crate::toxcore::binary_io::*;
use super::MAX_NAME_LENGTH_IN_GROUP;

/** ChangeName is the struct that holds info to notify changing name of a peer to a group chat.

Sent by a peer who wants to change its name or by a joining peer to notify its name to members of group chat.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x63`
`2`       | `group number`
`2`       | `peer number`
`4`       | `message number`
`1`       | `0x30`
variable  | `name`(UTF-8 C String)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeName {
    group_number: u16,
    peer_number: u16,
    message_number: u32,
    name: String,
}

impl FromBytes for ChangeName {
    named!(from_bytes<ChangeName>, do_parse!(
        tag!("\x63") >>
        group_number: be_u16 >>
        peer_number: be_u16 >>
        message_number: be_u32 >>
        tag!("\x30") >>
        name: map_res!(verify!(rest, |name: &[u8]| name.len() <= MAX_NAME_LENGTH_IN_GROUP),
            str::from_utf8) >>
        (ChangeName {
            group_number,
            peer_number,
            message_number,
            name: name.to_string(),
        })
    ));
}

impl ToBytes for ChangeName {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x63) >>
            gen_be_u16!(self.group_number) >>
            gen_be_u16!(self.peer_number) >>
            gen_be_u32!(self.message_number) >>
            gen_be_u8!(0x30) >>
            gen_slice!(self.name.as_bytes())
        )
    }
}

impl ChangeName {
    /// Create new ChangeName object.
    pub fn new(group_number: u16, peer_number: u16, message_number: u32, name: String) -> Self {
        ChangeName {
            group_number,
            peer_number,
            message_number,
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
}
