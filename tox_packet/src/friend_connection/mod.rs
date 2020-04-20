/*! Top-level Friend connection Packets
*/

use tox_binary_io::*;

mod alive;
mod share_relays;
mod friend_requests;

pub use self::alive::*;
pub use self::share_relays::*;
pub use self::friend_requests::*;

use nom::{
    named,
    do_parse,
    tag,
    call,
    alt,
    many0,
    map,
    value,
    verify,
};
use nom::combinator::rest;

use cookie_factory::{
    do_gen,
    gen_slice,
    gen_call,
    gen_cond,
    gen_be_u8,
    gen_many_ref
};

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
    use crate::toxid::NoSpam;
    use crate::dht::packed_node::*;

    encode_decode_test!(
        tox_crypto::crypto_init().unwrap(),
        packet_alive_encode_decode,
        Packet::Alive(Alive)
    );

    encode_decode_test!(
        tox_crypto::crypto_init().unwrap(),
        packet_friend_requests_encode_decode,
        Packet::FriendRequests(FriendRequests::new(NoSpam::random(), vec![1,2,3,4]))
    );

    encode_decode_test!(
        tox_crypto::crypto_init().unwrap(),
        packet_share_relays_encode_decode,
        Packet::ShareRelays(ShareRelays::new(vec![
            PackedNode {
                saddr: "1.1.1.1:33445".parse().unwrap(),
                pk: tox_crypto::gen_keypair().0,
            },
            PackedNode {
                saddr: "1.1.1.1:33446".parse().unwrap(),
                pk: tox_crypto::gen_keypair().0,
            },
            PackedNode {
                saddr: "1.1.1.1:33447".parse().unwrap(),
                pk: tox_crypto::gen_keypair().0,
            },
        ]))
    );
}
