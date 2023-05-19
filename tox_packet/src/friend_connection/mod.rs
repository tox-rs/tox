/*! Top-level Friend connection Packets
*/

use tox_binary_io::*;

mod alive;
mod friend_requests;
mod share_relays;

pub use self::alive::*;
pub use self::friend_requests::*;
pub use self::share_relays::*;

use nom::branch::alt;
use nom::combinator::map;

use cookie_factory::{do_gen, gen_be_u8, gen_call, gen_cond, gen_many_ref, gen_slice};

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
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        alt((
            map(Alive::from_bytes, Packet::Alive),
            map(ShareRelays::from_bytes, Packet::ShareRelays),
            map(FriendRequests::from_bytes, Packet::FriendRequests),
        ))(input)
    }
}

#[cfg(test)]
mod tests {
    use crypto_box::SecretKey;
    use rand::thread_rng;

    use super::*;
    use crate::dht::packed_node::*;
    use crate::toxid::{NoSpam, NOSPAMBYTES};

    encode_decode_test!(packet_alive_encode_decode, Packet::Alive(Alive));

    encode_decode_test!(
        packet_friend_requests_encode_decode,
        Packet::FriendRequests(FriendRequests::new(NoSpam([42; NOSPAMBYTES]), vec![1, 2, 3, 4]))
    );

    encode_decode_test!(
        packet_share_relays_encode_decode,
        Packet::ShareRelays(ShareRelays::new(vec![
            PackedNode {
                saddr: "1.1.1.1:33445".parse().unwrap(),
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
            },
            PackedNode {
                saddr: "1.1.1.1:33446".parse().unwrap(),
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
            },
            PackedNode {
                saddr: "1.1.1.1:33447".parse().unwrap(),
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
            },
        ]))
    );
}
