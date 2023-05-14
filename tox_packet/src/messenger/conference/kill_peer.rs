/*! Kill peer message struct.
*/

use super::*;
use nom::bytes::complete::tag;
use nom::number::complete::{be_u16, be_u32};

/** KillPeer is a struct that holds info to send kill peer message to a conference.

When a peer quit a conference, right before quit, it send this packet.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x63`
`2`       | `conference id`
`2`       | `peer id`
`4`       | `message id`
`1`       | `0x11`
`2`       | `peer id`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KillPeer {
    /// Id of conference
    pub conference_id: u16,
    /// Target peer id
    pub peer_id: u16,
    /// Id of this message
    pub message_id: u32,
    /// Peer id to kill
    pub kill_peer_id: u16,
}

impl FromBytes for KillPeer {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x63")(input)?;
        let (input, conference_id) = be_u16(input)?;
        let (input, peer_id) = be_u16(input)?;
        let (input, message_id) = be_u32(input)?;
        let (input, _) = tag("\x11")(input)?;
        let (input, kill_peer_id) = be_u16(input)?;
        Ok((
            input,
            KillPeer {
                conference_id,
                peer_id,
                message_id,
                kill_peer_id,
            },
        ))
    }
}

impl ToBytes for KillPeer {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x63) >>
            gen_be_u16!(self.conference_id) >>
            gen_be_u16!(self.peer_id) >>
            gen_be_u32!(self.message_id) >>
            gen_be_u8!(0x11) >>
            gen_be_u16!(self.kill_peer_id)
        )
    }
}

impl KillPeer {
    /// Create new KillPeer object.
    pub fn new(conference_id: u16, peer_id: u16, message_id: u32, kill_peer_id: u16) -> Self {
        KillPeer {
            conference_id,
            peer_id,
            message_id,
            kill_peer_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(kill_peer_encode_decode, KillPeer::new(1, 2, 3, 4));
}
