/*!
Module for errors of Messenger.
*/

use std::fmt;

use failure::{Backtrace, Context, Fail};
use cookie_factory::GenError;

use tox_packet::messenger::FileTransferPacket;
use crate::net_crypto::errors::SendLosslessPacketError;
use tox_crypto::PublicKey;
use futures::channel::mpsc;

/// Error that can happen when sending file_* packet.
#[derive(Debug)]
pub struct SendPacketError {
    ctx: Context<SendPacketErrorKind>,
}

impl SendPacketError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &SendPacketErrorKind {
        self.ctx.get_context()
    }
    pub(crate) fn serialize(error: GenError) -> SendPacketError {
        SendPacketError::from(SendPacketErrorKind::Serialize { error })
    }
}

impl Fail for SendPacketError {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for SendPacketError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Debug, Fail)]
pub enum SendPacketErrorKind {
    /// Error indicates that serializing packet failed.
    #[fail(display = "Serialize packet error: {:?}", error)]
    Serialize {
        /// Serialize error
        error: GenError,
    },
    /// Error indicates that sending packet using net_crytpo failed.
    #[fail(display = "Sending packet using net_crypto failed")]
    SendToLossless,
    /// Error indicates that there is no net_crypto assigned.
    #[fail(display = "There is no net_crypto object assigned")]
    NoNetCrypto,
    /// Error indicates that the friend is not online.
    #[fail(display = "The friend is not online")]
    NotOnline,
    /// Error indicates that the file transfer is not accepted by peer.
    #[fail(display = "File transfer is not accepted by peer")]
    NotAccepted,
    /// Error indicates that the position is larger than file size.
    #[fail(display = "Position of file chunk request is larger than file size")]
    LargerPosition,
    /// Error indicates that there is no file transfer session opened.
    #[fail(display = "There is no file transfer session opened")]
    NoFileTransfer,
    /// Error indicates that the friend don't exist in messenger's friend list.
    #[fail(display = "The friend don't exist in messenger's friend list")]
    NoFriend,
    /// Error indicates that file control request is invalid on current status.
    #[fail(display = "File control request is invalid on current status")]
    InvalidRequest,
    /// Error indicates that file control request is invalid on current status.
    #[fail(display = "File control request is invalid on current status")]
    InvalidRequest2,
    /// Error indicates that file control request is invalid on current status.
    #[fail(display = "File control request is invalid on current status")]
    InvalidRequest3,
    /// Error indicates that file control request is invalid on current status.
    #[fail(display = "File control request is invalid on current status")]
    InvalidRequest4,
    /// Error indicates that file control request is invalid on current status.
    #[fail(display = "File control request is invalid on current status")]
    InvalidRequest5,
}

impl From<SendPacketErrorKind> for SendPacketError {
    fn from(kind: SendPacketErrorKind) -> SendPacketError {
        SendPacketError::from(Context::new(kind))
    }
}

impl From<SendLosslessPacketError> for SendPacketError {
    fn from(error: SendLosslessPacketError) -> SendPacketError {
        SendPacketError {
            ctx: error.context(SendPacketErrorKind::SendToLossless)
        }
    }
}

impl From<Context<SendPacketErrorKind>> for SendPacketError {
    fn from(ctx: Context<SendPacketErrorKind>) -> SendPacketError {
        SendPacketError { ctx }
    }
}

/// Error that can happen when handle packet.
#[derive(Debug)]
pub struct RecvPacketError {
    ctx: Context<RecvPacketErrorKind>,
}

impl RecvPacketError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &RecvPacketErrorKind {
        self.ctx.get_context()
    }
    /// Error indicates that file control request is invalid for current status.
    pub(crate) fn invalid_request(pk: PublicKey, file_id: u8) -> RecvPacketError {
        RecvPacketError::from(RecvPacketErrorKind::InvalidReq {
            pk,
            file_id,
        })
    }
    /// Error indicates that seek control position exceeds the file size.
    pub(crate) fn exceed_size(pk: PublicKey, file_id: u8, file_size: u64) -> RecvPacketError {
        RecvPacketError::from(RecvPacketErrorKind::ExceedSize {
            pk,
            file_id,
            file_size,
        })
    }
}

impl Fail for RecvPacketError {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for RecvPacketError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Debug, Eq, PartialEq, Fail)]
pub enum RecvPacketErrorKind {
    /// Error indicates that sending packet to client failed.
    #[fail(display = "Sending packet to client failed")]
    SendTo,
    /// Error indicates that there is no sink to client for file control packet.
    #[fail(display = "No sink to client for file control packet")]
    NoSink,
    /// Error indicates that there is no sink to client for file data packet.
    #[fail(display = "No sink to client for file data packet")]
    NoDataSink,
    /// Error indicates that file control request is invalid for current status.
    #[fail(display = "File control request is invalid for current status: PK = {:?} file_id = {:?}", pk, file_id)]
    InvalidReq {
        /// Friend PK
        pk: PublicKey,
        /// File id for this friend
        file_id: u8,
    },
    /// Error indicates that seek control position exceeds the file size.
    #[fail(display = "File seek position exceeds file size: PK = {:?} file_id = {:?} file size = {:?}", pk, file_id, file_size)]
    ExceedSize {
        /// Friend PK
        pk: PublicKey,
        /// File id for this friend
        file_id: u8,
        /// File size to transfer
        file_size: u64,
    },
    /// Error indicates that file control packet has unknown control type.
    #[fail(display = "File control packet has unknown control type")]
    UnknownControlType,
    /// Error indicates that file transfer session already exist on new file sending request.
    #[fail(display = "File transfer session already exists")]
    AlreadyExist,
    /// Error indicates that the friend don't exist in messenger's friend list.
    #[fail(display = "The friend don't exist in messenger's friend list")]
    NoFriend,
    /// Error indicates that file transfer session is not status of transferring.
    #[fail(display = "File transfer session is not status of transferring")]
    NotTransferring,
    /// Error indicates that there is no file transfer session opened.
    #[fail(display = "There is no file transfer session opened")]
    NoFileTransfer,
    /// Error indicates that sending response packet failed.
    #[fail(display = "Sending response packet error")]
    SendPacket,
}

impl From<RecvPacketErrorKind> for RecvPacketError {
    fn from(kind: RecvPacketErrorKind) -> RecvPacketError {
        RecvPacketError::from(Context::new(kind))
    }
}

impl From<Context<RecvPacketErrorKind>> for RecvPacketError {
    fn from(ctx: Context<RecvPacketErrorKind>) -> RecvPacketError {
        RecvPacketError { ctx }
    }
}

impl From<mpsc::SendError<(PublicKey, Packet)>> for RecvPacketError {
    fn from(error: mpsc::SendError<(PublicKey, Packet)>) -> RecvPacketError {
        RecvPacketError {
            ctx: error.context(RecvPacketErrorKind::SendTo)
        }
    }
}

impl From<mpsc::SendError<(PublicKey, Packet, u64)>> for RecvPacketError {
    fn from(error: mpsc::SendError<(PublicKey, Packet, u64)>) -> RecvPacketError {
        RecvPacketError {
            ctx: error.context(RecvPacketErrorKind::SendTo)
        }
    }
}

impl From<SendPacketError> for RecvPacketError {
    fn from(error: SendPacketError) -> RecvPacketError {
        RecvPacketError {
            ctx: error.context(RecvPacketErrorKind::SendPacket)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_packet_error() {
        let error = SendPacketError::from(SendPacketErrorKind::SendToLossless);
        assert!(error.cause().is_none());
        assert_eq!(format!("{}", error), "Sending packet using net_crypto failed".to_owned());
    }
    #[test]
    fn send_packet_serialize() {
        let gen_error = GenError::InvalidOffset;
        let error = SendPacketError::serialize(gen_error);
        assert_eq!(format!("{}", error), "Serialize packet error: InvalidOffset".to_owned());
    }
    #[test]
    fn send_packet_no_net_crypto() {
        let error = SendPacketError::from(SendPacketErrorKind::NoNetCrypto);
        assert_eq!(format!("{}", error), "There is no net_crypto object assigned".to_owned());
    }
    #[test]
    fn send_packet_not_online() {
        let error = SendPacketError::from(SendPacketErrorKind::NotOnline);
        assert_eq!(format!("{}", error), "The friend is not online".to_owned());
    }
    #[test]
    fn send_packet_not_acepted() {
        let error = SendPacketError::from(SendPacketErrorKind::NotAccepted);
        assert_eq!(format!("{}", error), "File transfer is not accepted by peer".to_owned());
    }
    #[test]
    fn send_packet_larger_position() {
        let error = SendPacketError::from(SendPacketErrorKind::LargerPosition);
        assert_eq!(format!("{}", error), "Position of file chunk request is larger than file size".to_owned());
    }
    #[test]
    fn send_packet_no_file_transfer() {
        let error = SendPacketError::from(SendPacketErrorKind::NoFileTransfer);
        assert_eq!(format!("{}", error), "There is no file transfer session opened".to_owned());
    }
    #[test]
    fn send_packet_no_friend() {
        let error = SendPacketError::from(SendPacketErrorKind::NoFriend);
        assert_eq!(format!("{}", error), "The friend don't exist in messenger's friend list".to_owned());
    }
    #[test]
    fn send_packet_invalid_request() {
        let error = SendPacketError::from(SendPacketErrorKind::InvalidRequest);
        assert_eq!(format!("{}", error), "File control request is invalid on current status".to_owned());
    }
    #[test]
    fn send_packet_invalid_request2() {
        let error = SendPacketError::from(SendPacketErrorKind::InvalidRequest2);
        assert_eq!(format!("{}", error), "File control request is invalid on current status".to_owned());
    }
    #[test]
    fn send_packet_invalid_request3() {
        let error = SendPacketError::from(SendPacketErrorKind::InvalidRequest3);
        assert_eq!(format!("{}", error), "File control request is invalid on current status".to_owned());
    }
    #[test]
    fn send_packet_invalid_request4() {
        let error = SendPacketError::from(SendPacketErrorKind::InvalidRequest4);
        assert_eq!(format!("{}", error), "File control request is invalid on current status".to_owned());
    }
    #[test]
    fn send_packet_invalid_request5() {
        let error = SendPacketError::from(SendPacketErrorKind::InvalidRequest5);
        assert_eq!(format!("{}", error), "File control request is invalid on current status".to_owned());
    }
    #[test]
    fn recv_packet_error() {
        let error = RecvPacketError::from(RecvPacketErrorKind::SendTo);
        assert!(error.cause().is_none());
        assert_eq!(format!("{}", error), "Sending packet to client failed".to_owned());
    }
    #[test]
    fn recv_packet_invalid_request() {
        let pk = PublicKey([103, 172, 218, 234, 171, 161, 30, 254, 31, 40, 20, 147, 203, 248, 235, 88, 113, 171, 62,
            142, 166, 125, 78, 57, 26, 16, 80, 5, 65, 113, 68, 15]);
        let error = RecvPacketError::invalid_request(pk, 1);
        assert_eq!(*error.kind(), RecvPacketErrorKind::InvalidReq { pk: pk, file_id: 1 });
        assert_eq!(format!("{}", error), "File control request is invalid for current status: PK = \
        PublicKey([103, 172, 218, 234, 171, 161, 30, 254, 31, 40, 20, 147, 203, 248, 235, 88, 113, 171, 62, \
        142, 166, 125, 78, 57, 26, 16, 80, 5, 65, 113, 68, 15]) file_id = 1".to_owned());
    }
    #[test]
    fn recv_packet_exceed_size() {
        let pk = PublicKey([103, 172, 218, 234, 171, 161, 30, 254, 31, 40, 20, 147, 203, 248, 235, 88, 113, 171, 62,
            142, 166, 125, 78, 57, 26, 16, 80, 5, 65, 113, 68, 15]);
        let error = RecvPacketError::exceed_size(pk, 1, 100);
        assert_eq!(*error.kind(), RecvPacketErrorKind::ExceedSize { pk, file_id: 1, file_size: 100 });
        assert_eq!(format!("{}", error), "File seek position exceeds file size: PK = \
        PublicKey([103, 172, 218, 234, 171, 161, 30, 254, 31, 40, 20, 147, 203, 248, 235, 88, 113, 171, 62, \
        142, 166, 125, 78, 57, 26, 16, 80, 5, 65, 113, 68, 15]) file_id = 1 file size = 100".to_owned());
    }
    #[test]
    fn recv_packet_no_sink() {
        let error = RecvPacketError::from(RecvPacketErrorKind::NoSink);
        assert_eq!(*error.kind(), RecvPacketErrorKind::NoSink);
        assert_eq!(format!("{}", error), "No sink to client for file control packet".to_owned());
    }
    #[test]
    fn recv_packet_no_data_sink() {
        let error = RecvPacketError::from(RecvPacketErrorKind::NoDataSink);
        assert_eq!(*error.kind(), RecvPacketErrorKind::NoDataSink);
        assert_eq!(format!("{}", error), "No sink to client for file data packet".to_owned());
    }
    #[test]
    fn recv_packet_no_unknown_control_type() {
        let error = RecvPacketError::from(RecvPacketErrorKind::UnknownControlType);
        assert_eq!(*error.kind(), RecvPacketErrorKind::UnknownControlType);
        assert_eq!(format!("{}", error), "File control packet has unknown control type".to_owned());
    }
    #[test]
    fn recv_packet_no_alrady_exist() {
        let error = RecvPacketError::from(RecvPacketErrorKind::AlreadyExist);
        assert_eq!(*error.kind(), RecvPacketErrorKind::AlreadyExist);
        assert_eq!(format!("{}", error), "File transfer session already exists".to_owned());
    }
    #[test]
    fn recv_packet_no_friend() {
        let error = RecvPacketError::from(RecvPacketErrorKind::NoFriend);
        assert_eq!(*error.kind(), RecvPacketErrorKind::NoFriend);
        assert_eq!(format!("{}", error), "The friend don't exist in messenger's friend list".to_owned());
    }
    #[test]
    fn recv_packet_not_fransferring() {
        let error = RecvPacketError::from(RecvPacketErrorKind::NotTransferring);
        assert_eq!(*error.kind(), RecvPacketErrorKind::NotTransferring);
        assert_eq!(format!("{}", error), "File transfer session is not status of transferring".to_owned());
    }
    #[test]
    fn recv_packet_no_file_transfer() {
        let error = RecvPacketError::from(RecvPacketErrorKind::NoFileTransfer);
        assert_eq!(*error.kind(), RecvPacketErrorKind::NoFileTransfer);
        assert_eq!(format!("{}", error), "There is no file transfer session opened".to_owned());
    }
    #[test]
    fn recv_packet_send_packet() {
        let error = RecvPacketError::from(RecvPacketErrorKind::SendPacket);
        assert_eq!(*error.kind(), RecvPacketErrorKind::SendPacket);
        assert_eq!(format!("{}", error), "Sending response packet error".to_owned());
    }
}
