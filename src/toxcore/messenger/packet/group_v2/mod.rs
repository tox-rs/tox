/*! Group chat version 2 packets
*/

use crate::toxcore::binary_io::*;

mod status;
mod nickname_v2;
mod message_v2;
mod action_v2;
mod private_message;
mod peer_exit;
mod remove_peer;
mod remove_ban;
mod set_moderator;
mod set_observer;
mod announce_peer;
mod peer_info_request;
mod peer_info_response;
mod sync_request;
mod sync_response;
mod invite_request;
mod invite_response;
mod topic;
mod shared_state;
mod mod_list;

pub use self::status::*;
pub use self::nickname_v2::*;
pub use self::message_v2::*;
pub use self::action_v2::*;
pub use self::private_message::*;
pub use self::peer_exit::*;
pub use self::remove_peer::*;
pub use self::remove_ban::*;
pub use self::set_moderator::*;
pub use self::set_observer::*;
pub use self::announce_peer::*;
pub use self::peer_info_request::*;
pub use self::peer_info_response::*;
pub use self::sync_request::*;
pub use self::sync_response::*;
pub use self::invite_request::*;
pub use self::invite_response::*;
pub use self::topic::*;
pub use self::shared_state::*;
pub use self::mod_list::*;

/// Maximum size in bytes of action string of message packet
pub const MAX_MESSAGE_V2_DATA_SIZE: usize = 1289;


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
    /// [`PrivateMessage`](./struct.PrivateMessage.html) structure.
    PrivateMessage(PrivateMessage),
    /// [`PeerExit`](./struct.PeerExit.html) structure.
    PeerExit(PeerExit),
    /// [`RemovePeer`](./struct.RemovePeer.html) structure.
    RemovePeer(RemovePeer),
    /// [`RemoveBan`](./struct.RemoveBan.html) structure.
    RemoveBan(RemoveBan),
    /// [`SetModerator`](./struct.SetModerator.html) structure.
    SetModerator(SetModerator),
    /// [`SetObserver`](./struct.SetObserver.html) structure.
    SetObserver(SetObserver),
    /// [`AnnouncePeer`](./struct.AnnouncePeer.html) structure.
    AnnouncePeer(AnnouncePeer),
    /// [`PeerInfoRequest`](./struct.PeerInfoRequest.html) structure.
    PeerInfoRequest(PeerInfoRequest),
    /// [`PeerInfoResponse`](./struct.PeerInfoResponse.html) structure.
    PeerInfoResponse(PeerInfoResponse),
    /// [`SyncRequest`](./struct.SyncRequest.html) structure.
    SyncRequest(SyncRequest),
    /// [`SyncResponse`](./struct.SyncResponse.html) structure.
    SyncResponse(SyncResponse),
    /// [`InviteRequest`](./struct.InviteRequest.html) structure.
    InviteRequest(InviteRequest),
    /// [`InviteResponse`](./struct.InviteResponse.html) structure.
    InviteResponse(InviteResponse),
    /// [`Topic`](./struct.Topic.html) structure.
    Topic(Topic),
    /// [`SharedState`](./struct.SharedState.html) structure.
    SharedState(SharedState),
    /// [`ModList`](./struct.ModList.html) structure.
    ModList(ModList),
}

impl ToBytes for Packet {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            Packet::Status(ref p) => p.to_bytes(buf),
            Packet::NicknameV2(ref p) => p.to_bytes(buf),
            Packet::MessageV2(ref p) => p.to_bytes(buf),
            Packet::ActionV2(ref p) => p.to_bytes(buf),
            Packet::PrivateMessage(ref p) => p.to_bytes(buf),
            Packet::PeerExit(ref p) => p.to_bytes(buf),
            Packet::RemovePeer(ref p) => p.to_bytes(buf),
            Packet::RemoveBan(ref p) => p.to_bytes(buf),
            Packet::SetModerator(ref p) => p.to_bytes(buf),
            Packet::SetObserver(ref p) => p.to_bytes(buf),
            Packet::AnnouncePeer(ref p) => p.to_bytes(buf),
            Packet::PeerInfoRequest(ref p) => p.to_bytes(buf),
            // `UsePassword::Use` is for temporary use, it will be replaced with checked value from chatting room info.
            // Or the packet structure should be changed to carry the flag of existence of password.
            Packet::PeerInfoResponse(ref p) => p.to_custom_bytes(buf, UsePassword::Use),
            // `UsePassword::Use` is for temporary use, it will be replaced with checked value from chatting room info.
            // Or the packet structure should be changed to carry the flag of existence of password.
            Packet::SyncRequest(ref p) => p.to_custom_bytes(buf, UsePassword::Use),
            Packet::SyncResponse(ref p) => p.to_bytes(buf),
            // `UsePassword::Use` is for temporary use, it will be replaced with checked value from chatting room info.
            // Or the packet structure should be changed to carry the flag of existence of password.
            Packet::InviteRequest(ref p) => p.to_custom_bytes(buf, UsePassword::Use),
            Packet::InviteResponse(ref p) => p.to_bytes(buf),
            Packet::Topic(ref p) => p.to_bytes(buf),
            Packet::SharedState(ref p) => p.to_bytes(buf),
            Packet::ModList(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for Packet {
    named!(from_bytes<Packet>, alt!(
        map!(Status::from_bytes, Packet::Status) |
        map!(NicknameV2::from_bytes, Packet::NicknameV2) |
        map!(MessageV2::from_bytes, Packet::MessageV2) |
        map!(ActionV2::from_bytes, Packet::ActionV2) |
        map!(PrivateMessage::from_bytes, Packet::PrivateMessage) |
        map!(PeerExit::from_bytes, Packet::PeerExit) |
        map!(RemovePeer::from_bytes, Packet::RemovePeer) |
        map!(RemoveBan::from_bytes, Packet::RemoveBan) |
        map!(SetModerator::from_bytes, Packet::SetModerator) |
        map!(SetObserver::from_bytes, Packet::SetObserver) |
        map!(AnnouncePeer::from_bytes, Packet::AnnouncePeer) |
        map!(PeerInfoRequest::from_bytes, Packet::PeerInfoRequest) |
        map!(call!(PeerInfoResponse::from_custom_bytes, UsePassword::Use), Packet::PeerInfoResponse) |
        map!(call!(SyncRequest::from_custom_bytes, UsePassword::Use), Packet::SyncRequest) |
        map!(SyncResponse::from_bytes, Packet::SyncResponse) |
        map!(call!(InviteRequest::from_custom_bytes, UsePassword::Use), Packet::InviteRequest) |
        map!(InviteResponse::from_bytes, Packet::InviteResponse) |
        map!(Topic::from_bytes, Packet::Topic) |
        map!(SharedState::from_bytes, Packet::SharedState) |
        map!(ModList::from_bytes, Packet::ModList)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toxcore::crypto_core::*;
    use crate::toxcore::ip_port::*;
    use crate::toxcore::packed_node::TcpUdpPackedNode;

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

    encode_decode_test!(
        packet_private_message_encode_decode,
        Packet::PrivateMessage(PrivateMessage::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, "1234".to_owned()))
    );

    encode_decode_test!(
        packet_peer_exit_encode_decode,
        Packet::PeerExit(PeerExit::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4))
    );

    encode_decode_test!(
        packet_remove_peer_encode_decode,
        Packet::RemovePeer(RemovePeer::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, EventV2::Ban, gen_keypair().0, vec![
            Sanction(SanctionType::BanIpPort(
                BanIpPort::new(
                    gen_keypair().0, 1, 2, IpPort::from_udp_saddr("127.0.0.1:33445".parse().unwrap())
                )
            )),
            Sanction(SanctionType::BanPublicKey(
                BanPublicKey::new(gen_keypair().0, 3, 4, gen_keypair().0
                )
            )),
            Sanction(SanctionType::BanNickname(
                BanNickname::new(gen_keypair().0, 5, 6, String::from_utf8([32; 128].to_vec()).unwrap()
                )
            )),
            Sanction(SanctionType::Observer(
                Observer::new(gen_keypair().0, 7, gen_keypair().0
                )
            ))
        ]))
    );

    encode_decode_test!(
        packet_remove_ban_encode_decode,
        Packet::RemoveBan(RemoveBan::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, 5,
            vec![
                Sanction(SanctionType::BanIpPort(
                    BanIpPort::new(
                        gen_keypair().0, 1, 2, IpPort::from_udp_saddr("127.0.0.1:33445".parse().unwrap())
                    )
                ))]
            )
        )
    );

    encode_decode_test!(
        packet_set_moderator_encode_decode,
        Packet::SetModerator(SetModerator::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, SetRole::ToUser(ToUser::new(gen_keypair().0))))
    );

    encode_decode_test!(
        packet_set_observer_encode_decode,
        Packet::SetObserver(SetObserver::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, SetOrUnset::Unset, gen_keypair().0,
            vec![
                Sanction(SanctionType::BanIpPort(
                    BanIpPort::new(
                        gen_keypair().0, 1, 2, IpPort::from_udp_saddr("127.0.0.1:33445".parse().unwrap())
                    )
                )
            )])
        )
    );

    encode_decode_test!(
        packet_announce_peer_encode_decode,
        Packet::AnnouncePeer(AnnouncePeer::new(1, gen_keypair().0, gen_nonce(), 2, 3, gen_keypair().0, None,
            vec![
                TcpUdpPackedNode {
                    ip_port: IpPort::from_tcp_saddr("127.0.0.1:33447".parse().unwrap()),
                    pk: gen_keypair().0,
                },
                TcpUdpPackedNode {
                    ip_port: IpPort::from_tcp_saddr("127.0.0.1:33448".parse().unwrap()),
                    pk: gen_keypair().0,
                },
                TcpUdpPackedNode {
                    ip_port: IpPort::from_tcp_saddr("127.0.0.1:33449".parse().unwrap()),
                    pk: gen_keypair().0,
                },
            ]
        ))
    );

    encode_decode_test!(
        packet_peer_info_request_encode_decode,
        Packet::PeerInfoRequest(PeerInfoRequest::new(1, gen_keypair().0, gen_nonce(), 2, 3))
    );

    encode_decode_test!(
        packet_sync_response_encode_decode,
        Packet::SyncResponse(SyncResponse::new(1, gen_keypair().0, gen_nonce(), 2, 3, vec![
            Announce::new(gen_keypair().0, Some(IpPort::from_tcp_saddr("127.0.0.1:33445".parse().unwrap())),
                vec![
                    TcpUdpPackedNode {
                    ip_port: IpPort::from_tcp_saddr("127.0.0.1:33447".parse().unwrap()),
                    pk: gen_keypair().0,
                },
            ]),
        ]))
    );

    encode_decode_test!(
        packet_invite_response_encode_decode,
        Packet::InviteResponse(InviteResponse::new(1, gen_keypair().0, gen_nonce(), 2, 3))
    );

    encode_decode_test!(
        packet_topic_encode_decode,
        Packet::Topic(Topic::new(1, gen_keypair().0, gen_nonce(), 2, 3, vec![32; SIGNATURE_DATA_SIZE], "1234".to_owned(), gen_keypair().0, 4))
    );

    encode_decode_test!(
        packet_shared_state_encode_decode,
        Packet::SharedState(SharedState::new(1, gen_keypair().0, gen_nonce(), 2, 3, vec![32u8; SIGNATURE_DATA_SIZE], gen_keypair().0,
            String::from_utf8(vec![32u8; GROUP_NAME_DATA_SIZE]).unwrap(),
            PrivacyState::Private, GroupPassword([32u8; GROUP_PASSWORD_BYTES]),
            ModerationHash([32u8; MODERATION_HASH_DATA_SIZE]), 4))
    );

    encode_decode_test!(
        packet_mod_list_encode_decode,
        Packet::ModList(ModList::new(1, gen_keypair().0, gen_nonce(), 2, 3, vec![gen_keypair().0, gen_keypair().0, gen_keypair().0]))
    );
}
