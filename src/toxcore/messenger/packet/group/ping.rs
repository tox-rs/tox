/*! Ping message struct.
*/

use nom::{be_u16, be_u32};

use crate::toxcore::binary_io::*;

/** Ping is a struct that holds info to send ping message to a group chat.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x63`
`2`       | `group number`
`2`       | `peer number`
`4`       | `message number`
`1`       | `0x00`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ping {
    group_number: u16,
    peer_number: u16,
    message_number: u32,
}

impl FromBytes for Ping {
    named!(from_bytes<Ping>, do_parse!(
        tag!("\x63") >>
        group_number: be_u16 >>
        peer_number: be_u16 >>
        message_number: be_u32 >>
        tag!("\x00") >>
        (Ping {
            group_number,
            peer_number,
            message_number,
        })
    ));
}

impl ToBytes for Ping {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x63) >>
            gen_be_u16!(self.group_number) >>
            gen_be_u16!(self.peer_number) >>
            gen_be_u32!(self.message_number) >>
            gen_be_u8!(0x00)
        )
    }
}

impl Ping {
    /// Create new Ping object.
    pub fn new(group_number: u16, peer_number: u16, message_number: u32) -> Self {
        Ping {
            group_number,
            peer_number,
            message_number,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        ping_encode_decode,
        Ping::new(1, 2, 3)
    );
}
