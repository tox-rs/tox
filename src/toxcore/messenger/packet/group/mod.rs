/*! The implementation of group chat packets.
*/

mod invite;
mod invite_response;
mod peer_online;
mod peer_leave;
mod query;
mod query_response;
mod title;
mod ping;
mod new_peer;
mod kill_peer;
mod freeze_peer;
mod chane_name;
mod change_title;

pub use self::invite::*;
pub use self::invite_response::*;
pub use self::peer_online::*;
pub use self::peer_leave::*;
pub use self::query::*;
pub use self::query_response::*;
pub use self::title::*;
pub use self::ping::*;
pub use self::new_peer::*;
pub use self::kill_peer::*;
pub use self::freeze_peer::*;
pub use self::chane_name::*;
pub use self::change_title::*;

use nom::be_u8;
use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/// Length in bytes of group chat unique bytes
pub const GROUP_UID_BYTES: usize = 32;

/// Length in bytes of various names in group chat
pub const MAX_NAME_LENGTH_IN_GROUP: usize = 128;

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
    /// [`PeerLeave`](./struct.PeerLeave.html) structure.
    PeerLeave(PeerLeave),
    /// [`PeerLeave`](./struct.PeerLeave.html) structure.
    Query(Query),
    /// [`Title`](./struct.Title.html) structure.
    Title(Title),
    /// [`Ping`](./struct.Ping.html) structure.
    Ping(Ping),
    /// [`NewPeer`](./struct.NewPeer.html) structure.
    NewPeer(NewPeer),
    /// [`KillPeer`](./struct.KillPeer.html) structure.
    KillPeer(KillPeer),
    /// [`FreezePeer`](./struct.FreezePeer.html) structure.
    FreezePeer(FreezePeer),
    /// [`ChangeName`](./struct.ChangeName.html) structure.
    ChangeName(ChangeName),
    /// [`ChangeTitle`](./struct.ChangeTitle.html) structure.
    ChangeTitle(ChangeTitle),
}

impl ToBytes for Packet {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            Packet::Invite(ref p) => p.to_bytes(buf),
            Packet::InviteResponse(ref p) => p.to_bytes(buf),
            Packet::PeerOnline(ref p) => p.to_bytes(buf),
            Packet::PeerLeave(ref p) => p.to_bytes(buf),
            Packet::Query(ref p) => p.to_bytes(buf),
            Packet::Title(ref p) => p.to_bytes(buf),
            Packet::Ping(ref p) => p.to_bytes(buf),
            Packet::NewPeer(ref p) => p.to_bytes(buf),
            Packet::KillPeer(ref p) => p.to_bytes(buf),
            Packet::FreezePeer(ref p) => p.to_bytes(buf),
            Packet::ChangeName(ref p) => p.to_bytes(buf),
            Packet::ChangeTitle(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for Packet {
    named!(from_bytes<Packet>, alt!(
        map!(Invite::from_bytes, Packet::Invite) |
        map!(InviteResponse::from_bytes, Packet::InviteResponse) |
        map!(PeerOnline::from_bytes, Packet::PeerOnline) |
        map!(PeerLeave::from_bytes, Packet::PeerLeave) |
        map!(Query::from_bytes, Packet::Query) |
        map!(Title::from_bytes, Packet::Title) |
        map!(Ping::from_bytes, Packet::Ping) |
        map!(NewPeer::from_bytes, Packet::NewPeer) |
        map!(KillPeer::from_bytes, Packet::KillPeer) |
        map!(FreezePeer::from_bytes, Packet::FreezePeer) |
        map!(ChangeName::from_bytes, Packet::ChangeName) |
        map!(ChangeTitle::from_bytes, Packet::ChangeTitle)
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

    encode_decode_test!(
        packet_peer_leave_encode_decode,
        Packet::PeerLeave(PeerLeave::new(1))
    );

    encode_decode_test!(
        packet_query_encode_decode,
        Packet::Query(Query::new(1))
    );

    encode_decode_test!(
        packet_title_encode_decode,
        Packet::Title(Title::new(1, "1234".to_owned()))
    );

    encode_decode_test!(
        packet_ping_encode_decode,
        Packet::Ping(Ping::new(1, 2, 3))
    );

    encode_decode_test!(
        packet_new_peer_encode_decode,
        Packet::NewPeer(NewPeer::new(1, 2, 3, 4, gen_keypair().0, gen_keypair().0))
    );

    encode_decode_test!(
        packet_kill_peer_encode_decode,
        Packet::KillPeer(KillPeer::new(1, 2, 3, 4))
    );

    encode_decode_test!(
        packet_freeze_peer_encode_decode,
        Packet::FreezePeer(FreezePeer::new(1, 2, 3, 4))
    );

    encode_decode_test!(
        packet_hange_name_encode_decode,
        Packet::ChangeName(ChangeName::new(1, 2, 3, "1234".to_owned()))
    );

    encode_decode_test!(
        packet_hange_title_encode_decode,
        Packet::ChangeTitle(ChangeTitle::new(1, 2, 3, "1234".to_owned()))
    );
}
