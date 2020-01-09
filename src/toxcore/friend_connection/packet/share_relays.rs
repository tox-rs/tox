/*! ShareRalays struct
*/

use crate::toxcore::binary_io::*;
use crate::toxcore::dht::packed_node::*;

/// Id of the `ShareRelays` packet.
pub const PACKET_ID_SHARE_RELAYS: u8 = 0x11;

/// Maximum number of TCP relays `ShareRelays` packet can carry.
pub const MAX_SHARED_RELAYS: usize = 3;

/** ShareRelays is a struct that holds at most 3 TCP relays in a `PackedNode` format.

This packet is used to share relays between two friends.

Serialized form:

Length     | Content
---------- | ------
`1`        | `0x11`
`[0, 153]` | Nodes in packed format

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareRelays {
    /// TCP relays.
    pub relays: Vec<PackedNode>,
}

impl FromBytes for ShareRelays {
    named!(from_bytes<ShareRelays>, do_parse!(
        tag!(&[PACKET_ID_SHARE_RELAYS][..]) >>
        relays: many0!(PackedNode::from_tcp_bytes) >>
        verify!(value!(relays.len()), |len| *len <= MAX_SHARED_RELAYS) >>
        (ShareRelays {
            relays,
        })
    ));
}

impl ToBytes for ShareRelays {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(PACKET_ID_SHARE_RELAYS) >>
            gen_cond!(self.relays.len() > MAX_SHARED_RELAYS, |buf| gen_error(buf, 0)) >>
            gen_many_ref!(&self.relays, |buf, relay| PackedNode::to_tcp_bytes(relay, buf))
        )
    }
}

impl ShareRelays {
    /// Create new ShareRelays object
    pub fn new(relays: Vec<PackedNode>) -> Self {
        ShareRelays { relays }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        share_relays_encode_decode,
        ShareRelays::new(vec![
            PackedNode {
                saddr: "1.1.1.1:33445".parse().unwrap(),
                pk: gen_keypair().0,
            },
            PackedNode {
                saddr: "1.1.1.1:33446".parse().unwrap(),
                pk: gen_keypair().0,
            },
            PackedNode {
                saddr: "1.1.1.1:33447".parse().unwrap(),
                pk: gen_keypair().0,
            },
        ])
    );
}
