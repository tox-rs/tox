/*! Top-level Friend connection Packets
*/

use toxcore::binary_io::*;

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
