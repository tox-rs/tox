/*! Kill peer message struct.
*/

use nom::{be_u16, be_u32};

use crate::toxcore::binary_io::*;

/** KillPeer is a struct that holds info to send kill peer message to a group chat.

When a peer quit a group chat, right before quit, it send this packet.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x63`
`2`       | `group number`
`2`       | `peer number`
`4`       | `message number`
`1`       | `0x11`
`2`       | `peer number`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KillPeer {
    group_number: u16,
    peer_number: u16,
    message_number: u32,
    kill_peer_number: u16,
}

impl FromBytes for KillPeer {
    named!(from_bytes<KillPeer>, do_parse!(
        tag!("\x63") >>
        group_number: be_u16 >>
        peer_number: be_u16 >>
        message_number: be_u32 >>
        tag!("\x11") >>
        kill_peer_number: be_u16 >>
        (KillPeer {
            group_number,
            peer_number,
            message_number,
            kill_peer_number,
        })
    ));
}

impl ToBytes for KillPeer {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x63) >>
            gen_be_u16!(self.group_number) >>
            gen_be_u16!(self.peer_number) >>
            gen_be_u32!(self.message_number) >>
            gen_be_u8!(0x11) >>
            gen_be_u16!(self.kill_peer_number)
        )
    }
}

impl KillPeer {
    /// Create new KillPeer object.
    pub fn new(group_number: u16, peer_number: u16, message_number: u32, kill_peer_number: u16) -> Self {
        KillPeer {
            group_number,
            peer_number,
            message_number,
            kill_peer_number,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        kill_peer_encode_decode,
        KillPeer::new(1, 2, 3, 4)
    );
}
