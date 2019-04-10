/*! Freeze peer message struct.
*/

use nom::{be_u16, be_u32};

use crate::toxcore::binary_io::*;

/** Freeze peer is a struct that holds info to send freeze peer message to a group chat.

When a peer quit running, it need to freeze group chat rather than remove it.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x63`
`2`       | `group number`
`2`       | `peer number`
`4`       | `message number`
`1`       | `0x12`
`2`       | `peer number`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreezePeer {
    group_number: u16,
    peer_number: u16,
    message_number: u32,
    freeze_peer_number: u16,
}

impl FromBytes for FreezePeer {
    named!(from_bytes<FreezePeer>, do_parse!(
        tag!("\x63") >>
        group_number: be_u16 >>
        peer_number: be_u16 >>
        message_number: be_u32 >>
        tag!("\x12") >>
        freeze_peer_number: be_u16 >>
        (FreezePeer {
            group_number,
            peer_number,
            message_number,
            freeze_peer_number,
        })
    ));
}

impl ToBytes for FreezePeer {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x63) >>
            gen_be_u16!(self.group_number) >>
            gen_be_u16!(self.peer_number) >>
            gen_be_u32!(self.message_number) >>
            gen_be_u8!(0x12) >>
            gen_be_u16!(self.freeze_peer_number)
        )
    }
}

impl FreezePeer {
    /// Create new FreezePeer object.
    pub fn new(group_number: u16, peer_number: u16, message_number: u32, freeze_peer_number: u16) -> Self {
        FreezePeer {
            group_number,
            peer_number,
            message_number,
            freeze_peer_number,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        freeze_peer_encode_decode,
        FreezePeer::new(1, 2, 3, 4)
    );
}
