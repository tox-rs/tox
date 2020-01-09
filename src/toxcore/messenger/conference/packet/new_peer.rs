/*! New peer message struct.
*/

use nom::number::complete::{be_u16, be_u32};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/** NewPeer is a struct that holds info to send new peer message to a conference.

Tell everyone about a new peer in the chat.
The peer who invited joining peer sends this packet to warn everyone that there is a new peer.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x63`
`2`       | `conference id`
`2`       | `peer id`
`4`       | `message id`
`1`       | `0x10`
`2`       | `peer id`
`32`      | Long term PK
`32`      | DHT PK

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewPeer {
    /// Id of conference
    pub conference_id: u16,
    /// Target peer id
    pub peer_id: u16,
    /// Id of this message
    pub message_id: u32,
    /// Peer id to join
    pub new_peer_id: u16,
    /// Long term PK of new peer
    pub long_term_pk: PublicKey,
    /// DHT PK of new peer
    pub dht_pk: PublicKey,
}

impl FromBytes for NewPeer {
    named!(from_bytes<NewPeer>, do_parse!(
        tag!("\x63") >>
        conference_id: be_u16 >>
        peer_id: be_u16 >>
        message_id: be_u32 >>
        tag!("\x10") >>
        new_peer_id: be_u16 >>
        long_term_pk: call!(PublicKey::from_bytes) >>
        dht_pk: call!(PublicKey::from_bytes) >>
        (NewPeer {
            conference_id,
            peer_id,
            message_id,
            new_peer_id,
            long_term_pk,
            dht_pk,
        })
    ));
}

impl ToBytes for NewPeer {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x63) >>
            gen_be_u16!(self.conference_id) >>
            gen_be_u16!(self.peer_id) >>
            gen_be_u32!(self.message_id) >>
            gen_be_u8!(0x10) >>
            gen_be_u16!(self.new_peer_id) >>
            gen_slice!(self.long_term_pk.as_ref()) >>
            gen_slice!(self.dht_pk.as_ref())
        )
    }
}

impl NewPeer {
    /// Create new NewPeer object.
    pub fn new(conference_id: u16, peer_id: u16, message_id: u32, new_peer_id: u16, long_term_pk: PublicKey, dht_pk: PublicKey) -> Self {
        NewPeer {
            conference_id,
            peer_id,
            message_id,
            new_peer_id,
            long_term_pk,
            dht_pk,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        new_peer_encode_decode,
        NewPeer::new(1, 2, 3, 4, gen_keypair().0, gen_keypair().0)
    );
}
