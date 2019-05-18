/*! ShareRalays struct
*/

use crate::toxcore::binary_io::*;
use crate::toxcore::dht::packed_node::*;

/** ShareRelays is a struct that holds at most 3 TCP relays as a PackedNode format.

This packet is used to share relay info. between two friends.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x11`
variable  | 3 PackedNodes

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareRelays {
    relays: Vec<PackedNode>,
}

impl FromBytes for ShareRelays {
    named!(from_bytes<ShareRelays>, do_parse!(
        tag!("\x11") >>
        relays: many0!(PackedNode::from_tcp_bytes) >>
        verify!(value!(relays.len()), |len| len <= 3) >>
        (ShareRelays {
            relays,
        })
    ));
}

impl ShareRelays {
    /// Create new ShareRelays object
    pub fn new(relays: Vec<PackedNode>) -> Self {
        ShareRelays { relays }
    }
}

impl ToBytes for ShareRelays {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x11) >>
            gen_cond!(self.relays.len() > 3, |buf| gen_error(buf, 0)) >>
            gen_many_ref!(&self.relays, |buf, relay| PackedNode::to_tcp_bytes(relay, buf))
        )
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
