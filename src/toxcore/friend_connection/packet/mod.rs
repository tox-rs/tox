/*! Top-level Friend connection Packets
*/

use crate::toxcore::binary_io::*;

mod alive;
mod share_relays;
mod friend_requests;

pub use self::alive::*;
pub use self::share_relays::*;
pub use self::friend_requests::*;

/** Friend connection packet enum that encapsulates all types of Friend connection packets.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    /// [`Alive`](./struct.Alive.html) structure.
    Alive(Alive),
    /// [`ShareRelays`](./struct.ShareRelays.html) structure.
    ShareRelays(ShareRelays),
    /// [`FriendRequests`](./struct.FriendRequests.html) structure.
    FriendRequests(FriendRequests),
}

impl ToBytes for Packet {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            Packet::Alive(ref p) => p.to_bytes(buf),
            Packet::ShareRelays(ref p) => p.to_bytes(buf),
            Packet::FriendRequests(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for Packet {
    named!(from_bytes<Packet>, alt!(
        map!(Alive::from_bytes, Packet::Alive) |
        map!(ShareRelays::from_bytes, Packet::ShareRelays) |
        map!(FriendRequests::from_bytes, Packet::FriendRequests)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toxcore::toxid::NoSpam;
    use crate::toxcore::dht::packed_node::*;

    encode_decode_test!(
        packet_alive_encode_decode,
        Packet::Alive(Alive)
    );

    encode_decode_test!(
        packet_friend_requests_encode_decode,
        Packet::FriendRequests(FriendRequests::new(NoSpam::random(), vec![1,2,3,4]))
    );

    encode_decode_test!(
        packet_share_relays_encode_decode,
        Packet::ShareRelays(ShareRelays::new(vec![
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
        ]))
    );
}
