/*! Top-level Messenger Packets
*/

use crate::toxcore::binary_io::*;

mod online;
mod offline;
mod nickname;

pub use self::online::*;
pub use self::offline::*;
pub use self::nickname::*;

/** Messenger packet enum that encapsulates all types of Messenger packets.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    /// [`Online`](./struct.Online.html) structure.
    Online(Online),
    /// [`Offline`](./struct.Offline.html) structure.
    Offline(Offline),
    /// [`Nickname`](./struct.Nickname.html) structure.
    Nickname(Nickname),
}

impl ToBytes for Packet {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            Packet::Online(ref p) => p.to_bytes(buf),
            Packet::Offline(ref p) => p.to_bytes(buf),
            Packet::Nickname(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for Packet {
    named!(from_bytes<Packet>, alt!(
        map!(Online::from_bytes, Packet::Online) |
        map!(Offline::from_bytes, Packet::Offline) |
        map!(Nickname::from_bytes, Packet::Nickname)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        packet_online_encode_decode,
        Packet::Online(Online)
    );

    encode_decode_test!(
        packet_offline_encode_decode,
        Packet::Offline(Offline)
    );

    encode_decode_test!(
        packet_nickname_encode_decode,
        Packet::Nickname(Nickname::new("1234".to_string()))
    );
}
