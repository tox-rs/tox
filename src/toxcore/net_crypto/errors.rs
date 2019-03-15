/*!
Module for errors of NetCrypto.
*/

use std::fmt;
use std::net::SocketAddr;

use futures::sync::mpsc;
use failure::{Backtrace, Context, Fail};
use tokio::timer::Error as TimerError;
use tokio::timer::timeout::Error as TimeoutError;

use crate::toxcore::dht::packet::*;
use crate::toxcore::crypto_core::*;

/// Error that can happen while processing packets array
#[derive(Debug)]
pub struct PacketsArrayError {
    ctx: Context<PacketsArrayErrorKind>,
}

impl PacketsArrayError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &PacketsArrayErrorKind {
        self.ctx.get_context()
    }

    pub(crate) fn too_big(index: u32) -> PacketsArrayError {
        PacketsArrayError::from(PacketsArrayErrorKind::TooBig { index })
    }

    pub(crate) fn already_exist(index: u32) -> PacketsArrayError {
        PacketsArrayError::from(PacketsArrayErrorKind::AlreadyExist { index })
    }

    pub(crate) fn lower_index(index: u32) -> PacketsArrayError {
        PacketsArrayError::from(PacketsArrayErrorKind::LowerIndex { index })
    }

    pub(crate) fn outside_index(index: u32) -> PacketsArrayError {
        PacketsArrayError::from(PacketsArrayErrorKind::OutsideIndex { index })
    }
}

impl Fail for PacketsArrayError {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for PacketsArrayError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Debug, Eq, PartialEq, Fail)]
pub enum PacketsArrayErrorKind {
    /// Index is too big error
    #[fail(display = "The index {:?} is too big and can't be hold", index)]
    TooBig {
        /// The index that can't be hold
        index: u32,
    },
    /// Index already exists error
    #[fail(display = "The packet with index {:?} already exists", index)]
    AlreadyExist {
        /// The index that already exists
        index: u32,
    },
    /// Packets array is full
    #[fail(display = "Packets array is full")]
    ArrayFull,
    /// Index is lower than the end index
    #[fail(display = "Index {:?} is lower than the end index", index)]
    LowerIndex {
        /// The index that lower than end index
        index: u32,
    },
    /// Index is outside of buffer bounds
    #[fail(display = "Index {:?} is outside of buffer bounds", index)]
    OutsideIndex {
        /// The index that is outside of buffer bounds
        index: u32,
    },
}

impl From<PacketsArrayErrorKind> for PacketsArrayError {
    fn from(kind: PacketsArrayErrorKind) -> PacketsArrayError {
        PacketsArrayError::from(Context::new(kind))
    }
}

impl From<Context<PacketsArrayErrorKind>> for PacketsArrayError {
    fn from(ctx: Context<PacketsArrayErrorKind>) -> PacketsArrayError {
        PacketsArrayError { ctx }
    }
}

/// Error that can happen when calling `handle_*` of packet.
#[derive(Debug)]
pub struct HandlePacketError {
    ctx: Context<HandlePacketErrorKind>,
}

impl HandlePacketError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &HandlePacketErrorKind {
        self.ctx.get_context()
    }

    pub(crate) fn invalid_request_id(expect: u64, got: u64) -> HandlePacketError {
        HandlePacketError::from(HandlePacketErrorKind::InvalidRequestId {
            expect,
            got,
        })
    }

    pub(crate) fn no_connection(addr: SocketAddr) -> HandlePacketError {
        HandlePacketError::from(HandlePacketErrorKind::NoConnection {
            addr,
        })
    }

    pub(crate) fn packet_id(id: u8) -> HandlePacketError {
        HandlePacketError::from(HandlePacketErrorKind::PacketId {
            id,
        })
    }
}

impl Fail for HandlePacketError {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for HandlePacketError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Debug, Eq, PartialEq, Fail)]
pub enum HandlePacketErrorKind {
    /// Error indicates that getting payload of received packet error.
    #[fail(display = "Get payload of received packet error")]
    GetPayload,
    /// Error indicates that sending response packet error.
    #[fail(display = "Sending response error")]
    SendTo,
    /// Error indicates that sending lossless response packet error.
    #[fail(display = "Sending lossless response error")]
    SendToLossless,
    /// Error indicates that sending dhtpk packet error.
    #[fail(display = "Sending dhtpk packet error")]
    SendToDhtpk,
    /// Error indicates that NetCrypto can't handle packet in current connection state.
    #[fail(display = "Can't handle CookieResponse in current connection state")]
    InvalidState,
    /// Error indicates that NetCrypto can't handle crypto data packet in current connection state.
    #[fail(display = "Can't handle CryptoData in current connection state")]
    CannotHandleCryptoData,
    /// Error indicates that invalid cookie request id.
    #[fail(display = "Invalid cookie request id: expected {:?} but got {:?}", expect, got)]
    InvalidRequestId {
        /// Expected request id
        expect: u64,
        /// Gotten request id
        got: u64,
    },
    /// Error indicates that no crypto connection for address.
    #[fail(display = "No crypto connection for address: {:?}", addr)]
    NoConnection {
        /// The address for connection which don't exist
        addr: SocketAddr,
    },
    /// Unexpected crypto handshake.
    #[fail(display = "Unexpected crypto handshake")]
    UnexpectedCryptoHandshake,
    /// Error indicates that invalid SHA512 hash of cookie
    #[fail(display = "Invalid SHA512 hash of cookie")]
    BadSha512,
    /// Error indicates that cookie is timed out
    #[fail(display = "Cookie is timed out")]
    CookieTimedOut,
    /// Error indicates that cookie contains invalid real pk
    #[fail(display = "Cookie contains invalid real pk")]
    InvalidRealPk,
    /// Error indicates that cookie contains invalid dht pk
    #[fail(display = "Cookie contains invalid dht pk")]
    InvalidDhtPk,
    /// Error indicates that there is PacketsArrayError
    #[fail(display = "PacketsArrayError occurs")]
    PacketsArrayError,
    /// Error indicates that real data is empty
    #[fail(display = "Real data is empty")]
    DataEmpty,
    /// Error indicates that invalid packet id.
    #[fail(display = "Invalid packet id: {:?}", id)]
    PacketId {
        /// The packet id that is invalid
        id: u8,
    },
}

impl From<HandlePacketErrorKind> for HandlePacketError {
    fn from(kind: HandlePacketErrorKind) -> HandlePacketError {
        HandlePacketError::from(Context::new(kind))
    }
}

impl From<TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> for HandlePacketError {
    fn from(error: TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>) -> HandlePacketError {
        HandlePacketError {
            ctx: error.context(HandlePacketErrorKind::SendTo)
        }
    }
}

impl From<mpsc::SendError<(PublicKey, Vec<u8>)>> for HandlePacketError {
    fn from(error: mpsc::SendError<(PublicKey, Vec<u8>)>) -> HandlePacketError {
        HandlePacketError {
            ctx: error.context(HandlePacketErrorKind::SendToLossless)
        }
    }
}

impl From<mpsc::SendError<(PublicKey, PublicKey)>> for HandlePacketError {
    fn from(error: mpsc::SendError<(PublicKey, PublicKey)>) -> HandlePacketError {
        HandlePacketError {
            ctx: error.context(HandlePacketErrorKind::SendToDhtpk)
        }
    }
}

impl From<Context<HandlePacketErrorKind>> for HandlePacketError {
    fn from(ctx: Context<HandlePacketErrorKind>) -> HandlePacketError {
        HandlePacketError { ctx }
    }
}

impl From<GetPayloadError> for HandlePacketError {
    fn from(error: GetPayloadError) -> HandlePacketError {
        HandlePacketError {
            ctx: error.context(HandlePacketErrorKind::GetPayload)
        }
    }
}

impl From<PacketsArrayError> for HandlePacketError {
    fn from(error: PacketsArrayError) -> HandlePacketError {
        HandlePacketError {
            ctx: error.context(HandlePacketErrorKind::PacketsArrayError)
        }
    }
}

/// Error that can happen while processing packets array
#[derive(Debug)]
pub struct SendDataError {
    ctx: Context<SendDataErrorKind>,
}

impl SendDataError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &SendDataErrorKind {
        self.ctx.get_context()
    }
}

impl Fail for SendDataError {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for SendDataError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Debug, Eq, PartialEq, Fail)]
pub enum SendDataErrorKind {
    /// Connection is not established.
    #[fail(display = "Connection is not established")]
    NoConnection,
    /// Error indicates that sending response packet error.
    #[fail(display = "Sending response error")]
    SendTo,
}

impl From<SendDataErrorKind> for SendDataError {
    fn from(kind: SendDataErrorKind) -> SendDataError {
        SendDataError::from(Context::new(kind))
    }
}

impl From<Context<SendDataErrorKind>> for SendDataError {
    fn from(ctx: Context<SendDataErrorKind>) -> SendDataError {
        SendDataError { ctx }
    }
}

impl From<TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> for SendDataError {
    fn from(error: TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>) -> SendDataError {
        SendDataError {
            ctx: error.context(SendDataErrorKind::SendTo)
        }
    }
}

/// Error that can happen when calling `run`.
#[derive(Debug)]
pub struct RunError {
    ctx: Context<RunErrorKind>,
}

impl RunError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &RunErrorKind {
        self.ctx.get_context()
    }
}

impl Fail for RunError {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Clone, Debug, Eq, PartialEq, Fail)]
pub enum RunErrorKind {
    /// Sending pings error
    #[fail(display = "Sending crypto data packet error")]
    SendData,
    /// NetCrypto periodical wakeup timer error
    #[fail(display = "Netcrypto periodical wakeup timer error")]
    Wakeup,
}

impl From<RunErrorKind> for RunError {
    fn from(kind: RunErrorKind) -> RunError {
        RunError::from(Context::new(kind))
    }
}

impl From<Context<RunErrorKind>> for RunError {
    fn from(ctx: Context<RunErrorKind>) -> RunError {
        RunError { ctx }
    }
}

impl From<TimerError> for RunError {
    fn from(error: TimerError) -> RunError {
        RunError {
            ctx: error.context(RunErrorKind::Wakeup)
        }
    }
}

impl From<SendDataError> for RunError {
    fn from(error: SendDataError) -> RunError {
        RunError {
            ctx: error.context(RunErrorKind::SendData)
        }
    }
}

/// Error that can happen during a lossless packet sending.
#[derive(Debug)]
pub struct SendLosslessPacketError {
    ctx: Context<SendLosslessPacketErrorKind>,
}

impl SendLosslessPacketError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &SendLosslessPacketErrorKind {
        self.ctx.get_context()
    }
}

impl Fail for SendLosslessPacketError {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for SendLosslessPacketError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Debug, Eq, PartialEq, Fail)]
pub enum SendLosslessPacketErrorKind {
    /// Packet ID is outside lossless packets range.
    #[fail(display = "Packet ID is outside lossless packets range")]
    InvalidPacketId,
    /// Connection to a friend is not established.
    #[fail(display = "Connection to a friend is not established")]
    NoConnection,
    /// Packets send array is full.
    #[fail(display = "Packets send array is full")]
    FullSendArray,
    /// Failed to send packet.
    #[fail(display = "Failed to send packet")]
    SendTo,
}

impl From<SendLosslessPacketErrorKind> for SendLosslessPacketError {
    fn from(kind: SendLosslessPacketErrorKind) -> SendLosslessPacketError {
        SendLosslessPacketError::from(Context::new(kind))
    }
}

impl From<Context<SendLosslessPacketErrorKind>> for SendLosslessPacketError {
    fn from(ctx: Context<SendLosslessPacketErrorKind>) -> SendLosslessPacketError {
        SendLosslessPacketError { ctx }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::toxcore::io_tokio::*;

    use std::time::Duration;
    use futures::future::Future;

    #[test]
    fn packets_array_error() {
        let error = PacketsArrayError::from(PacketsArrayErrorKind::ArrayFull);
        assert!(error.cause().is_none());
        assert_eq!(format!("{}", error), "Packets array is full".to_owned());
    }

    #[test]
    fn packets_array_too_big() {
        let error = PacketsArrayError::too_big(1);
        assert_eq!(*error.kind(), PacketsArrayErrorKind::TooBig { index: 1 });
        assert_eq!(format!("{}", error), "The index 1 is too big and can't be hold".to_owned());
    }

    #[test]
    fn packets_array_already_exist() {
        let error = PacketsArrayError::already_exist(1);
        assert_eq!(*error.kind(), PacketsArrayErrorKind::AlreadyExist { index: 1 });
        assert_eq!(format!("{}", error), "The packet with index 1 already exists".to_owned());
    }

    #[test]
    fn packets_array_lower_index() {
        let error = PacketsArrayError::lower_index(1);
        assert_eq!(*error.kind(), PacketsArrayErrorKind::LowerIndex { index: 1 });
        assert_eq!(format!("{}", error), "Index 1 is lower than the end index".to_owned());
    }

    #[test]
    fn packets_array_outside_index() {
        let error = PacketsArrayError::outside_index(1);
        assert_eq!(*error.kind(), PacketsArrayErrorKind::OutsideIndex { index: 1 });
        assert_eq!(format!("{}", error), "Index 1 is outside of buffer bounds".to_owned());
    }

    #[test]
    fn handle_packet_error() {
        let error = HandlePacketError::from(HandlePacketErrorKind::InvalidState);
        assert!(error.cause().is_none());
    }

    #[test]
    fn handle_packet_invalid_request_id() {
        let error = HandlePacketError::invalid_request_id(1, 0);
        assert_eq!(*error.kind(), HandlePacketErrorKind::InvalidRequestId { expect: 1, got: 0 });
        assert_eq!(format!("{}", error), "Invalid cookie request id: expected 1 but got 0".to_owned());
    }

    #[test]
    fn handle_packet_no_connection() {
        let sock = "127.0.0.1:33445".parse().unwrap();
        let error = HandlePacketError::no_connection(sock);
        assert_eq!(*error.kind(), HandlePacketErrorKind::NoConnection { addr: sock });
        assert_eq!(format!("{}", error), "No crypto connection for address: V4(127.0.0.1:33445)".to_owned());
    }

    #[test]
    fn handle_packet_unexpected_crypto_handshake() {
        let error = HandlePacketError::from(HandlePacketErrorKind::UnexpectedCryptoHandshake);
        assert_eq!(*error.kind(), HandlePacketErrorKind::UnexpectedCryptoHandshake);
        assert_eq!(format!("{}", error), "Unexpected crypto handshake".to_owned());
    }

    #[test]
    fn handle_packet_packet_id() {
        let error = HandlePacketError::packet_id(1);
        assert_eq!(*error.kind(), HandlePacketErrorKind::PacketId { id: 1 });
        assert_eq!(format!("{}", error), "Invalid packet id: 1".to_owned());
    }

    #[test]
    fn handle_packet_get_payload() {
        let error = HandlePacketError::from(HandlePacketErrorKind::GetPayload);
        assert_eq!(*error.kind(), HandlePacketErrorKind::GetPayload);
        assert_eq!(format!("{}", error), "Get payload of received packet error".to_owned());

        let get_payload_error = GetPayloadError::from(GetPayloadErrorKind::Decrypt);
        let error = HandlePacketError::from(get_payload_error);
        assert_eq!(*error.kind(), HandlePacketErrorKind::GetPayload);
        assert_eq!(format!("{}", error), "Get payload of received packet error".to_owned());
    }

    #[test]
    fn handle_packet_send_to() {
        let (tx, rx) = mpsc::channel(32);

        let packet = Packet::BootstrapInfo(BootstrapInfo {
            version: 1717,
            motd: vec![1, 2, 3, 4],
        });
        let sock: SocketAddr = "127.0.0.1:33445".parse().unwrap();

        drop(rx);
        let res = send_to_bounded(&tx, (packet, sock), Duration::from_secs(1)).wait();
        assert!(res.is_err());
        let error = HandlePacketError::from(res.err().unwrap());
        assert_eq!(*error.kind(), HandlePacketErrorKind::SendTo);
        assert_eq!(format!("{}", error), "Sending response error".to_owned());
    }

    #[test]
    fn handle_packet_send_to_lossless() {
        let (tx, rx) = mpsc::channel(32);

        let pk = gen_keypair().0;
        let data = vec![1, 2, 3];

        drop(rx);
        let res = send_to(&tx, (pk, data)).wait();
        assert!(res.is_err());
        let error = HandlePacketError::from(res.err().unwrap());
        assert_eq!(*error.kind(), HandlePacketErrorKind::SendToLossless);
        assert_eq!(format!("{}", error), "Sending lossless response error".to_owned());
    }

    #[test]
    fn handle_packet_send_to_dhtpk() {
        let (tx, rx) = mpsc::channel(32);

        let pk = gen_keypair().0;
        let dhtpk = gen_keypair().0;

        drop(rx);
        let res = send_to(&tx, (pk, dhtpk)).wait();
        assert!(res.is_err());
        let error = HandlePacketError::from(res.err().unwrap());
        assert_eq!(*error.kind(), HandlePacketErrorKind::SendToDhtpk);
        assert_eq!(format!("{}", error), "Sending dhtpk packet error".to_owned());
    }

    #[test]
    fn handle_packet_invalid_state() {
        let error = HandlePacketError::from(HandlePacketErrorKind::InvalidState);
        assert_eq!(*error.kind(), HandlePacketErrorKind::InvalidState);
        assert_eq!(format!("{}", error), "Can't handle CookieResponse in current connection state".to_owned());
    }

    #[test]
    fn handle_packet_cannot_handle_crypto_data() {
        let error = HandlePacketError::from(HandlePacketErrorKind::CannotHandleCryptoData);
        assert_eq!(*error.kind(), HandlePacketErrorKind::CannotHandleCryptoData);
        assert_eq!(format!("{}", error), "Can't handle CryptoData in current connection state".to_owned());
    }

    #[test]
    fn handle_packet_bad_sha512() {
        let error = HandlePacketError::from(HandlePacketErrorKind::BadSha512);
        assert_eq!(*error.kind(), HandlePacketErrorKind::BadSha512);
        assert_eq!(format!("{}", error), "Invalid SHA512 hash of cookie".to_owned());
    }

    #[test]
    fn handle_packet_cookie_timedout() {
        let error = HandlePacketError::from(HandlePacketErrorKind::CookieTimedOut);
        assert_eq!(*error.kind(), HandlePacketErrorKind::CookieTimedOut);
        assert_eq!(format!("{}", error), "Cookie is timed out".to_owned());
    }

    #[test]
    fn handle_packet_invalid_real_pk() {
        let error = HandlePacketError::from(HandlePacketErrorKind::InvalidRealPk);
        assert_eq!(*error.kind(), HandlePacketErrorKind::InvalidRealPk);
        assert_eq!(format!("{}", error), "Cookie contains invalid real pk".to_owned());
    }

    #[test]
    fn handle_packet_invalid_dht_pk() {
        let error = HandlePacketError::from(HandlePacketErrorKind::InvalidDhtPk);
        assert_eq!(*error.kind(), HandlePacketErrorKind::InvalidDhtPk);
        assert_eq!(format!("{}", error), "Cookie contains invalid dht pk".to_owned());
    }

    #[test]
    fn handle_packet_packets_array_error() {
        let error = PacketsArrayError::from(PacketsArrayErrorKind::ArrayFull);
        let error = HandlePacketError::from(error);
        assert_eq!(*error.kind(), HandlePacketErrorKind::PacketsArrayError);
        assert_eq!(format!("{}", error), "PacketsArrayError occurs".to_owned());
    }

    #[test]
    fn handle_packet_data_empty() {
        let error = HandlePacketError::from(HandlePacketErrorKind::DataEmpty);
        assert_eq!(*error.kind(), HandlePacketErrorKind::DataEmpty);
        assert_eq!(format!("{}", error), "Real data is empty".to_owned());
    }

    #[test]
    fn send_data_error() {
        let error = SendDataError::from(SendDataErrorKind::NoConnection);
        assert!(error.cause().is_none());
    }

    #[test]
    fn send_data_no_connection() {
        let error = SendDataError::from(SendDataErrorKind::NoConnection);
        assert_eq!(*error.kind(), SendDataErrorKind::NoConnection);
        assert_eq!(format!("{}", error), "Connection is not established".to_owned());
    }

    #[test]
    fn send_data_send_to() {
        let (tx, rx) = mpsc::channel(32);

        let packet = Packet::BootstrapInfo(BootstrapInfo {
            version: 1717,
            motd: vec![1, 2, 3, 4],
        });
        let sock: SocketAddr = "127.0.0.1:33445".parse().unwrap();

        drop(rx);
        let res = send_to_bounded(&tx, (packet, sock), Duration::from_secs(1)).wait();
        assert!(res.is_err());
        let error = SendDataError::from(res.err().unwrap());
        assert_eq!(*error.kind(), SendDataErrorKind::SendTo);
        assert_eq!(format!("{}", error), "Sending response error".to_owned());
    }

    #[test]
    fn run_error() {
        let error = RunError::from(RunErrorKind::Wakeup);
        assert!(error.cause().is_none());
    }

    #[test]
    fn run_send_data() {
        let error = SendDataError::from(SendDataErrorKind::NoConnection);
        let error = RunError::from(error);
        assert_eq!(*error.kind(), RunErrorKind::SendData);
        assert_eq!(format!("{}", error), "Sending crypto data packet error".to_owned());
    }

    #[test]
    fn run_wakeup() {
        let error = RunError::from(RunErrorKind::Wakeup);
        assert_eq!(*error.kind(), RunErrorKind::Wakeup);
        assert_eq!(format!("{}", error), "Netcrypto periodical wakeup timer error".to_owned());
    }

    #[test]
    fn send_lossless_packet_error() {
        let error = SendLosslessPacketError::from(SendLosslessPacketErrorKind::InvalidPacketId);
        assert!(error.cause().is_none());
    }

    #[test]
    fn send_lossless_packet_invalid_packet_id() {
        let error = SendLosslessPacketError::from(SendLosslessPacketErrorKind::InvalidPacketId);
        assert_eq!(*error.kind(), SendLosslessPacketErrorKind::InvalidPacketId);
        assert_eq!(format!("{}", error), "Packet ID is outside lossless packets range".to_owned());
    }

    #[test]
    fn send_lossless_packet_no_connection() {
        let error = SendLosslessPacketError::from(SendLosslessPacketErrorKind::NoConnection);
        assert_eq!(*error.kind(), SendLosslessPacketErrorKind::NoConnection);
        assert_eq!(format!("{}", error), "Connection to a friend is not established".to_owned());
    }

    #[test]
    fn send_lossless_packet_full_send_array() {
        let error = SendLosslessPacketError::from(SendLosslessPacketErrorKind::FullSendArray);
        assert_eq!(*error.kind(), SendLosslessPacketErrorKind::FullSendArray);
        assert_eq!(format!("{}", error), "Packets send array is full".to_owned());
    }

    #[test]
    fn send_lossless_packet_send_to() {
        let error = SendLosslessPacketError::from(SendLosslessPacketErrorKind::SendTo);
        assert_eq!(*error.kind(), SendLosslessPacketErrorKind::SendTo);
        assert_eq!(format!("{}", error), "Failed to send packet".to_owned());
    }
}
