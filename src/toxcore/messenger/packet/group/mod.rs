/*! The implementation of group chat packets.
*/

mod invite;
mod invite_response;
mod peer_online;

pub use self::invite::*;
pub use self::invite_response::*;
pub use self::peer_online::*;

use nom::be_u8;
use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/// Length of group chat unique bytes
pub const GROUP_UID_BYTES: usize = 32;

/// Unique id used in group chat
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupUID([u8; GROUP_UID_BYTES]);

impl GroupUID {
    /// Create new object
    pub fn random() -> GroupUID {
        let mut array = [0; GROUP_UID_BYTES];
        randombytes_into(&mut array);
        GroupUID(array)
    }

    /// Custom from_slice function of GroupUID
    pub fn from_slice(bs: &[u8]) -> Option<GroupUID> {
        if bs.len() != GROUP_UID_BYTES {
            return None
        }
        let mut n = GroupUID([0; GROUP_UID_BYTES]);
        for (ni, &bsi) in n.0.iter_mut().zip(bs.iter()) {
            *ni = bsi
        }
        Some(n)
    }
}

impl FromBytes for GroupUID {
    named!(from_bytes<GroupUID>, map_opt!(take!(GROUP_UID_BYTES), GroupUID::from_slice));
}

impl ToBytes for GroupUID {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.0)
        )
    }
}

/// Type of group chat
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupType {
    /// Text group conference.
    Text = 0x00,
    /// Audio group conference.
    Audio,
}

impl FromBytes for GroupType {
    named!(from_bytes<GroupType>,
        switch!(be_u8,
            0 => value!(GroupType::Text) |
            1 => value!(GroupType::Audio)
        )
    );
}

/** Group chat packet enum that encapsulates all types of group chat packets.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    /// [`Invite`](./struct.Invite.html) structure.
    Invite(Invite),
    /// [`InviteResponse`](./struct.InviteResponse.html) structure.
    InviteResponse(InviteResponse),
    /// [`PeerOnline`](./struct.PeerOnline.html) structure.
    PeerOnline(PeerOnline),
}

impl ToBytes for Packet {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            Packet::Invite(ref p) => p.to_bytes(buf),
            Packet::InviteResponse(ref p) => p.to_bytes(buf),
            Packet::PeerOnline(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for Packet {
    named!(from_bytes<Packet>, alt!(
        map!(Invite::from_bytes, Packet::Invite) |
        map!(InviteResponse::from_bytes, Packet::InviteResponse) |
        map!(PeerOnline::from_bytes, Packet::PeerOnline)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        group_uid_encode_decode,
        GroupUID::random()
    );

    #[test]
    fn group_type_from_bytes() {
        let raw = [0];
        let (_, group_type) = GroupType::from_bytes(&raw).unwrap();
        assert_eq!(GroupType::Text, group_type);
    }

    encode_decode_test!(
        packet_invite_encode_decode,
        Packet::Invite(Invite::new(1, GroupType::Audio, GroupUID::new()))
    );

    encode_decode_test!(
        packet_invite_response_encode_decode,
        Packet::InviteResponse(InviteResponse::new(1, 2, GroupType::Text, GroupUID::new()))
    );

    encode_decode_test!(
        packet_peer_noline_encode_decode,
        Packet::PeerOnline(PeerOnline::new(1, GroupType::Text, GroupUID::new()))
    );
}
