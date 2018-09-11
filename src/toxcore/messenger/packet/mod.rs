/*! Top-level Messenger Packets
*/

use toxcore::binary_io::*;

mod online;
mod offline;

pub use self::online::*;
pub use self::offline::*;

/** Messenger packet enum that encapsulates all types of Messenger packets.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    /// [`Online`](./struct.Online.html) structure.
    Online(Online),
    /// [`Offline`](./struct.Offline.html) structure.
    Offline(Offline),
}

impl ToBytes for Packet {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            Packet::Online(ref p) => p.to_bytes(buf),
            Packet::Offline(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for Packet {
    named!(from_bytes<Packet>, alt!(
        map!(Online::from_bytes, Packet::Online) |
        map!(Offline::from_bytes, Packet::Offline)
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
}
