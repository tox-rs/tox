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

error_kind! {
    #[doc = "Error that can happen while processing packets array"]
    #[derive(Debug)]
    PacketsArrayError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Debug, Eq, PartialEq, Fail)]
    PacketsArrayErrorKind {
        #[doc = "Index is too big error."]
        #[fail(display = "The index {:?} is too big and can't be hold", index)]
        TooBig {
            #[doc = "The index that can't be hold."]
            index: u32,
        },
        #[doc = "Index already exists error."]
        #[fail(display = "The packet with index {:?} already exists", index)]
        AlreadyExist {
            #[doc = "The index that already exists."]
            index: u32,
        },
        #[doc = "Packets array is full."]
        #[fail(display = "Packets array is full")]
        ArrayFull,
        #[doc = "Index is lower than the end index."]
        #[fail(display = "Index {:?} is lower than the end index", index)]
        LowerIndex {
            #[doc = "The index that lower than end index."]
            index: u32,
        },
        #[doc = "Index is outside of buffer bounds."]
        #[fail(display = "Index {:?} is outside of buffer bounds", index)]
        OutsideIndex {
            #[doc = "The index that is outside of buffer bounds."]
            index: u32,
        },
    }
}

impl PacketsArrayError {
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

error_kind! {
    #[doc = "Error that can happen when calling `handle_*` of packet."]
    #[derive(Debug)]
    HandlePacketError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Debug, Eq, PartialEq, Fail)]
    HandlePacketErrorKind {
        #[doc = "Error indicates that getting payload of received packet error."]
        #[fail(display = "Get payload of received packet error")]
        GetPayload,
        #[doc = "Error indicates that sending response packet error."]
        #[fail(display = "Sending response error")]
        SendTo,
        #[doc = "Error indicates that sending lossless response packet error."]
        #[fail(display = "Sending lossless response error")]
        SendToLossless,
        #[doc = "Error indicates that sending lossy response packet error."]
        #[fail(display = "Sending lossy response error")]
        SendToLossy,
        #[doc = "Error indicates that sending dhtpk packet error."]
        #[fail(display = "Sending dhtpk packet error")]
        SendToDhtpk,
        #[doc = "Error indicates that NetCrypto can't handle packet in current connection state."]
        #[fail(display = "Can't handle CookieResponse in current connection state")]
        InvalidState,
        #[doc = "Error indicates that NetCrypto can't handle crypto data packet in current connection state."]
        #[fail(display = "Can't handle CryptoData in current connection state")]
        CannotHandleCryptoData,
        #[doc = "Error indicates that invalid cookie request id."]
        #[fail(display = "Invalid cookie request id: expected {:?} but got {:?}", expect, got)]
        InvalidRequestId {
            #[doc = "Expected request id."]
            expect: u64,
            #[doc = "Gotten request id."]
            got: u64,
        },
        #[doc = "Error indicates that no crypto connection for address."]
        #[fail(display = "No crypto connection for address: {:?}", addr)]
        NoConnection {
            #[doc = "The address for connection which don't exist."]
            addr: SocketAddr,
        },
        #[doc = "Unexpected crypto handshake."]
        #[fail(display = "Unexpected crypto handshake")]
        UnexpectedCryptoHandshake,
        #[doc = "Error indicates that invalid SHA512 hash of cookie."]
        #[fail(display = "Invalid SHA512 hash of cookie")]
        BadSha512,
        #[doc = "Error indicates that cookie is timed out."]
        #[fail(display = "Cookie is timed out")]
        CookieTimedOut,
        #[doc = "Error indicates that cookie contains invalid real pk."]
        #[fail(display = "Cookie contains invalid real pk")]
        InvalidRealPk,
        #[doc = "Error indicates that cookie contains invalid dht pk."]
        #[fail(display = "Cookie contains invalid dht pk")]
        InvalidDhtPk,
        #[doc = "Error indicates that there is PacketsArrayError."]
        #[fail(display = "PacketsArrayError occurs")]
        PacketsArrayError,
        #[doc = "Error indicates that real data is empty."]
        #[fail(display = "Real data is empty")]
        DataEmpty,
        #[doc = "Error indicates that invalid packet id."]
        #[fail(display = "Invalid packet id: {:?}", id)]
        PacketId {
            #[doc = "The packet id that is invalid."]
            id: u8,
        },
    }
}

impl HandlePacketError {
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

/// Error that can happen during a lossless packet sending.
#[derive(Debug)]
pub struct KillConnectionError {
    ctx: Context<KillConnectionErrorKind>,
}

impl KillConnectionError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &KillConnectionErrorKind {
        self.ctx.get_context()
    }
}

impl Fail for KillConnectionError {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for KillConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Debug, Eq, PartialEq, Fail)]
pub enum KillConnectionErrorKind {
    /// Connection to a friend is not established.
    #[fail(display = "Connection to a friend is not established")]
    NoConnection,
    /// Failed to send kill packet.
    #[fail(display = "Failed to send kill packet")]
    SendTo,
}

impl From<KillConnectionErrorKind> for KillConnectionError {
    fn from(kind: KillConnectionErrorKind) -> KillConnectionError {
        KillConnectionError::from(Context::new(kind))
    }
}

impl From<Context<KillConnectionErrorKind>> for KillConnectionError {
    fn from(ctx: Context<KillConnectionErrorKind>) -> KillConnectionError {
        KillConnectionError { ctx }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::toxcore::io_tokio::*;

    use std::time::Duration;
    use futures::future::Future;

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

    #[test]
    fn kill_connection_error() {
        let error = KillConnectionError::from(KillConnectionErrorKind::NoConnection);
        assert!(error.cause().is_none());
    }

    #[test]
    fn kill_connection_no_connection() {
        let error = KillConnectionError::from(KillConnectionErrorKind::NoConnection);
        assert_eq!(*error.kind(), KillConnectionErrorKind::NoConnection);
        assert_eq!(format!("{}", error), "Connection to a friend is not established".to_owned());
    }

    #[test]
    fn kill_connection_send_to() {
        let error = KillConnectionError::from(KillConnectionErrorKind::SendTo);
        assert_eq!(*error.kind(), KillConnectionErrorKind::SendTo);
        assert_eq!(format!("{}", error), "Failed to send kill packet".to_owned());
    }
}
