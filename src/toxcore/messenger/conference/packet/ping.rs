/*! Ping message struct.
*/

use nom::number::complete::{be_u16, be_u32};

use crate::toxcore::binary_io::*;

/** Ping is a struct that holds info to send ping message to a conference.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x63`
`2`       | `conference id`
`2`       | `peer id`
`4`       | `message id`
`1`       | `0x00`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ping {
    /// Id of conference
    pub conference_id: u16,
    /// Target peer id
    pub peer_id: u16,
    /// Id of this message
    pub message_id: u32,
}

impl FromBytes for Ping {
    named!(from_bytes<Ping>, do_parse!(
        tag!("\x63") >>
        conference_id: be_u16 >>
        peer_id: be_u16 >>
        message_id: be_u32 >>
        tag!("\x00") >>
        (Ping {
            conference_id,
            peer_id,
            message_id,
        })
    ));
}

impl ToBytes for Ping {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x63) >>
            gen_be_u16!(self.conference_id) >>
            gen_be_u16!(self.peer_id) >>
            gen_be_u32!(self.message_id) >>
            gen_be_u8!(0x00)
        )
    }
}

impl Ping {
    /// Create new Ping object.
    pub fn new(conference_id: u16, peer_id: u16, message_id: u32) -> Self {
        Ping {
            conference_id,
            peer_id,
            message_id,
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
