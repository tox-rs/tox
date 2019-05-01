/*! Top-level Messenger Packets
*/

use crate::toxcore::binary_io::*;

mod online;
mod action;
mod offline;
mod message;
mod nickname;
mod msi;
mod file_control;
mod typing;
mod user_status;
mod file_data;
mod status_message;
mod file_send_request;

pub use self::online::*;
pub use self::action::*;
pub use self::offline::*;
pub use self::message::*;
pub use self::nickname::*;
pub use self::msi::*;
pub use self::file_control::*;
pub use self::typing::*;
pub use self::user_status::*;
pub use self::file_data::*;
pub use self::status_message::*;
pub use self::file_send_request::*;

pub use crate::toxcore::messenger::conference::packet::Packet as ConferencePacket;

/** Messenger packet enum that encapsulates all types of Messenger packets.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    /// [`Online`](./struct.Online.html) structure.
    Online(Online),
    /// [`Action`](./struct.Action.html) structure.
    Action(Action),
    /// [`Offline`](./struct.Offline.html) structure.
    Offline(Offline),
    /// [`Message`](./struct.Message.html) structure.
    Message(Message),
    /// [`Nickname`](./struct.Nickname.html) structure.
    Nickname(Nickname),
    /// [`UserStatus`](./struct.UserStatus.html) structure.
    UserStatus(UserStatus),
    /// [`FileControl`](./struct.FileControl.html) structure.
    FileControl(FileControl),
    /// [`Typing`](./struct.Typing.html) structure.
    Typing(Typing),
    /// [`FileData`](./struct.FileData.html) structure.
    FileData(FileData),
    /// [`FileSendRequest`](./struct.FileSendRequest.html) structure.
    FileSendRequest(FileSendRequest),
    /// [`StatusMessage`](./struct.StatusMessage.html) structure.
    StatusMessage(StatusMessage),
    /// [`Msi`](./struct.Msi.html) structure.
    Msi(Msi),
    /// Packets of conference.
    Conference(ConferencePacket),
}

impl ToBytes for Packet {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            Packet::Online(ref p) => p.to_bytes(buf),
            Packet::Action(ref p) => p.to_bytes(buf),
            Packet::Offline(ref p) => p.to_bytes(buf),
            Packet::Message(ref p) => p.to_bytes(buf),
            Packet::Nickname(ref p) => p.to_bytes(buf),
            Packet::UserStatus(ref p) => p.to_bytes(buf),
            Packet::FileControl(ref p) => p.to_bytes(buf),
            Packet::Typing(ref p) => p.to_bytes(buf),
            Packet::FileData(ref p) => p.to_bytes(buf),
            Packet::Msi(ref p) => p.to_bytes(buf),
            Packet::FileSendRequest(ref p) => p.to_bytes(buf),
            Packet::StatusMessage(ref p) => p.to_bytes(buf),
            Packet::Conference(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for Packet {
    named!(from_bytes<Packet>, alt!(
        map!(Online::from_bytes, Packet::Online) |
        map!(Action::from_bytes, Packet::Action) |
        map!(Offline::from_bytes, Packet::Offline) |
        map!(Nickname::from_bytes, Packet::Nickname) |
        map!(Message::from_bytes, Packet::Message) |
        map!(UserStatus::from_bytes, Packet::UserStatus) |
        map!(FileControl::from_bytes, Packet::FileControl) |
        map!(FileData::from_bytes, Packet::FileData) |
        map!(FileSendRequest::from_bytes, Packet::FileSendRequest) |
        map!(Msi::from_bytes, Packet::Msi) |
        map!(StatusMessage::from_bytes, Packet::StatusMessage) |
        map!(Typing::from_bytes, Packet::Typing) |
        map!(ConferencePacket::from_bytes, Packet::Conference)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toxcore::messenger::conference::packet::{ConferenceType, ConferenceUID, Invite};

    encode_decode_test!(
        packet_online_encode_decode,
        Packet::Online(Online)
    );

    encode_decode_test!(
        packet_action_encode_decode,
        Packet::Action(Action::new("1234".to_string()))
    );

    encode_decode_test!(
        packet_offline_encode_decode,
        Packet::Offline(Offline)
    );

    encode_decode_test!(
        packet_message_encode_decode,
        Packet::Message(Message::new("1234".to_string()))
    );

    encode_decode_test!(
        packet_nickname_encode_decode,
        Packet::Nickname(Nickname::new("1234".to_string()))
    );

    encode_decode_test!(
        packet_user_status_encode_decode,
        Packet::UserStatus(UserStatus::new(PeerStatus::Busy))
    );

    encode_decode_test!(
        packet_file_control_encode_decode,
        Packet::FileControl(FileControl::new(TransferDirection::Send, 1, ControlType::Seek(100)))
    );

    encode_decode_test!(
        packet_typing_encode_decode,
        Packet::Typing(Typing::new(TypingStatus::NotTyping))
    );

    encode_decode_test!(
        packet_file_data_encode_decode,
        Packet::FileData(FileData::new(1, vec![1,2,3,4]))
    );

    encode_decode_test!(
        packet_msi_encode_decode,
        Packet::Msi(Msi::new(RequestKind::Init, None, CapabilitiesKind::SEND_AUDIO))
    );

    encode_decode_test!(
        packet_status_message_encode_decode,
        Packet::StatusMessage(StatusMessage::new("1234".to_string()))
    );

    encode_decode_test!(
        packet_file_send_request_encode_decode,
        Packet::FileSendRequest(FileSendRequest::new(1, FileType::Avatar, 4, FileUID::new(), "data".to_string()))
    );

    encode_decode_test!(
        packet_conference_request_encode_decode,
        Packet::Conference(ConferencePacket::Invite(Invite::new(1, ConferenceType::Text, ConferenceUID::random())))
    );
}
