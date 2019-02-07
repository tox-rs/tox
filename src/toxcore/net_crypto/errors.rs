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
    /// Error indicates that NetCrypto can't handle packet in current connection state.
    #[fail(display = "Can't handle CookieResponse in current connection state")]
    CannotHandle,
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
    /// Error indicates that invalid SHA512 hash of cookie
    #[fail(display = "Invalid SHA512 hash of cookie")]
    Sha512,
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
    PacketsArray,
    /// Error indicates that real data is empty
    #[fail(display = "Real data is empty")]
    Empty,
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
            ctx: error.context(HandlePacketErrorKind::PacketsArray)
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
        /// The index that lower than the end index
        index: u32,
    },
    /// Index is outside of buffer bounds
    #[fail(display = "Index {:?} is outside of buffer bounds", index)]
    OutsideIndex {
        /// The index that is outside of buffer bounds
        index: u32,
    },
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
