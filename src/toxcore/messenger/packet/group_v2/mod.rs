/*! Group chat version 2 packets
*/

use crate::toxcore::binary_io::*;

mod status;
mod nickname_v2;
mod message_v2;
mod action_v2;

pub use self::status::*;
pub use self::nickname_v2::*;
pub use self::message_v2::*;
pub use self::action_v2::*;

/** Group chat version 2 packet enum that encapsulates all types of group chat v2 packets.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    /// [`Status`](./struct.Status.html) structure.
    Status(Status),
    /// [`NicknameV2`](./struct.NicknameV2.html) structure.
    NicknameV2(NicknameV2),
    /// [`MessageV2`](./struct.MessageV2.html) structure.
    MessageV2(MessageV2),
    /// [`ActionV2`](./struct.ActionV2.html) structure.
    ActionV2(ActionV2),
}

impl ToBytes for Packet {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            Packet::Status(ref p) => p.to_bytes(buf),
            Packet::NicknameV2(ref p) => p.to_bytes(buf),
            Packet::MessageV2(ref p) => p.to_bytes(buf),
            Packet::ActionV2(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for Packet {
    named!(from_bytes<Packet>, alt!(
        map!(Status::from_bytes, Packet::Status) |
        map!(NicknameV2::from_bytes, Packet::NicknameV2) |
        map!(MessageV2::from_bytes, Packet::MessageV2) |
        map!(ActionV2::from_bytes, Packet::ActionV2)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        packet_status_encode_decode,
        Packet::Status(Status::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, PeerStatusV2::GsAway))
    );

    encode_decode_test!(
        packet_nickname_v2_encode_decode,
        Packet::NicknameV2(NicknameV2::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, "1234".to_owned()))
    );

    encode_decode_test!(
        packet_message_v2_encode_decode,
        Packet::MessageV2(MessageV2::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, "1234".to_owned()))
    );

    encode_decode_test!(
        packet_action_v2_encode_decode,
        Packet::ActionV2(ActionV2::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, "1234".to_owned()))
    );
}