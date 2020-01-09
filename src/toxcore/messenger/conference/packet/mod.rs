/*! The implementation of conference packets.
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
mod change_name;
mod change_title;
mod message;
mod action;

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
pub use self::change_name::*;
pub use self::change_title::*;
pub use self::message::*;
pub use self::action::*;

use nom::number::complete::be_u8;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/// Length in bytes of conference unique identifier.
pub const CONFERENCE_UID_BYTES: usize = 32;

/// Length in bytes of various names in conference.
pub const MAX_NAME_LENGTH_IN_CONFERENCE: usize = 128;

/// Unique id used in conference
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConferenceUID([u8; CONFERENCE_UID_BYTES]);

impl ConferenceUID {
    /// Create new object
    pub fn random() -> ConferenceUID {
        let mut array = [0; CONFERENCE_UID_BYTES];
        randombytes_into(&mut array);
        ConferenceUID(array)
    }

    /// Custom from_slice function of ConferenceUID
    pub fn from_slice(bs: &[u8]) -> Option<ConferenceUID> {
        if bs.len() != CONFERENCE_UID_BYTES {
            return None
        }
        let mut n = ConferenceUID([0; CONFERENCE_UID_BYTES]);
        for (ni, &bsi) in n.0.iter_mut().zip(bs.iter()) {
            *ni = bsi
        }
        Some(n)
    }
}

impl FromBytes for ConferenceUID {
    named!(from_bytes<ConferenceUID>, map_opt!(take!(CONFERENCE_UID_BYTES), ConferenceUID::from_slice));
}

impl ToBytes for ConferenceUID {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.0)
        )
    }
}

/// Type of conference
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConferenceType {
    /// Text conference.
    Text = 0x00,
    /// Audio conference.
    Audio,
}

impl FromBytes for ConferenceType {
    named!(from_bytes<ConferenceType>,
        switch!(be_u8,
            0 => value!(ConferenceType::Text) |
            1 => value!(ConferenceType::Audio)
        )
    );
}

/** Conference chat packet enum that encapsulates all types of conference packets.
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
    /// [`QueryResponse`](./struct.QueryResponse.html) structure.
    QueryResponse(QueryResponse),
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
    /// [`Message`](./struct.Message.html) structure.
    Message(Message),
    /// [`Action`](./struct.Action.html) structure.
    Action(Action),
}

impl ToBytes for Packet {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            Packet::Invite(ref p) => p.to_bytes(buf),
            Packet::InviteResponse(ref p) => p.to_bytes(buf),
            Packet::PeerOnline(ref p) => p.to_bytes(buf),
            Packet::PeerLeave(ref p) => p.to_bytes(buf),
            Packet::Query(ref p) => p.to_bytes(buf),
            Packet::QueryResponse(ref p) => p.to_bytes(buf),
            Packet::Title(ref p) => p.to_bytes(buf),
            Packet::Ping(ref p) => p.to_bytes(buf),
            Packet::NewPeer(ref p) => p.to_bytes(buf),
            Packet::KillPeer(ref p) => p.to_bytes(buf),
            Packet::FreezePeer(ref p) => p.to_bytes(buf),
            Packet::ChangeName(ref p) => p.to_bytes(buf),
            Packet::ChangeTitle(ref p) => p.to_bytes(buf),
            Packet::Message(ref p) => p.to_bytes(buf),
            Packet::Action(ref p) => p.to_bytes(buf),
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
        map!(QueryResponse::from_bytes, Packet::QueryResponse) |
        map!(Title::from_bytes, Packet::Title) |
        map!(Ping::from_bytes, Packet::Ping) |
        map!(NewPeer::from_bytes, Packet::NewPeer) |
        map!(KillPeer::from_bytes, Packet::KillPeer) |
        map!(FreezePeer::from_bytes, Packet::FreezePeer) |
        map!(ChangeName::from_bytes, Packet::ChangeName) |
        map!(ChangeTitle::from_bytes, Packet::ChangeTitle) |
        map!(Message::from_bytes, Packet::Message) |
        map!(Action::from_bytes, Packet::Action)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        conference_uid_encode_decode,
        ConferenceUID::random()
    );

    #[test]
    fn conference_type_from_bytes() {
        let raw = [0];
        let (_, conference_type) = ConferenceType::from_bytes(&raw).unwrap();
        assert_eq!(ConferenceType::Text, conference_type);
    }

    encode_decode_test!(
        packet_invite_encode_decode,
        Packet::Invite(Invite::new(1, ConferenceType::Audio, ConferenceUID::random()))
    );

    encode_decode_test!(
        packet_invite_response_encode_decode,
        Packet::InviteResponse(InviteResponse::new(1, 2, ConferenceType::Text, ConferenceUID::random()))
    );

    encode_decode_test!(
        packet_peer_noline_encode_decode,
        Packet::PeerOnline(PeerOnline::new(1, ConferenceType::Text, ConferenceUID::random()))
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
        packet_query_response_encode_decode,
        Packet::QueryResponse(QueryResponse::new(1, vec![
            PeerInfo::new(1, gen_keypair().0, gen_keypair().0, "1234".to_owned()),
            PeerInfo::new(2, gen_keypair().0, gen_keypair().0, "56789".to_owned()),
            ]))
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

    encode_decode_test!(
        packet_conference_message_encode_decode,
        Packet::Message(Message::new(1, 2, 3, "1234".to_owned()))
    );

    encode_decode_test!(
        packet_conference_action_encode_decode,
        Packet::Action(Action::new(1, 2, 3, "1234".to_owned()))
    );
}
