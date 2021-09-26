/*!
Module for errors of NetCrypto.
*/

use std::net::SocketAddr;

use futures::channel::mpsc::SendError;
use thiserror::Error;

use tokio::time::error::Elapsed;
use tox_crypto::*;
use tox_packet::dht::GetPayloadError;

/// Error that can happen while processing packets array
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum PacketsArrayError {
    /// Index is too big error.
    #[error("The index {:?} is too big and can't be hold", index)]
    TooBig {
        /// The index that can't be hold.
        index: u32,
    },
    /// Index already exists error.
    #[error("The packet with index {:?} already exists", index)]
    AlreadyExist {
        /// The index that already exists.
        index: u32,
    },
    /// Packets array is full.
    #[error("Packets array is full")]
    ArrayFull,
    /// Index is lower than the end index.
    #[error("Index {:?} is lower than the end index", index)]
    LowerIndex {
        /// The index that lower than end index.
        index: u32,
    },
    /// Index is outside of buffer bounds.
    #[error("Index {:?} is outside of buffer bounds", index)]
    OutsideIndex {
        /// The index that is outside of buffer bounds.
        index: u32,
    },
}

impl PacketsArrayError {
    pub(crate) fn too_big(index: u32) -> PacketsArrayError {
        PacketsArrayError::TooBig { index }
    }

    pub(crate) fn already_exist(index: u32) -> PacketsArrayError {
        PacketsArrayError::AlreadyExist { index }
    }

    pub(crate) fn lower_index(index: u32) -> PacketsArrayError {
        PacketsArrayError::LowerIndex { index }
    }

    pub(crate) fn outside_index(index: u32) -> PacketsArrayError {
        PacketsArrayError::OutsideIndex { index }
    }
}

/// Error that can happen when calling `handle_*` of packet.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum HandlePacketError {
    /// Error indicates that getting payload of received packet error.
    #[error("Get payload of received packet error")]
    GetPayload(GetPayloadError),
    /// Error indicates that sending response packet error.
    #[error("Sending response error")]
    SendTo(SendPacketError),
    /// Error indicates that sending response packet error.
    #[error("Sending response error")]
    SendDataTo(SendDataError),
    /// Error indicates that sending lossless response packet error.
    #[error("Sending lossless response error")]
    SendToLossless(SendError),
    /// Error indicates that sending lossy response packet error.
    #[error("Sending lossy response error")]
    SendToLossy(SendError),
    /// Error indicates that sending dhtpk packet error.
    #[error("Sending dhtpk packet error")]
    SendToDhtpk(SendError),
    /// Error indicates that sending connection status error.
    #[error("Sending connection status error")]
    SendToConnectionStatus(SendError),
    /// Error indicates that NetCrypto can't handle packet in current connection state.
    #[error("Can't handle CookieResponse in current connection state")]
    InvalidState,
    /// Error indicates that NetCrypto can't handle crypto data packet in current connection state.
    #[error("Can't handle CryptoData in current connection state")]
    CannotHandleCryptoData,
    /// Error indicates that invalid cookie request id.
    #[error("Invalid cookie request id: expected {:?} but got {:?}", expect, got)]
    InvalidRequestId {
        /// Expected request id.
        expect: u64,
        /// Gotten request id.
        got: u64,
    },
    /// Error indicates that no crypto connection for address.
    #[error("No crypto connection for address: {:?}", addr)]
    NoUdpConnection {
        /// The address for connection which don't exist.
        addr: SocketAddr,
    },
    /// Error indicates that no crypto connection for address.
    #[error("No crypto connection for DHT key: {:?}", pk)]
    NoTcpConnection {
        /// The DHT key for connection which don't exist.
        pk: PublicKey,
    },
    /// Unexpected crypto handshake.
    #[error("Unexpected crypto handshake")]
    UnexpectedCryptoHandshake,
    /// Error indicates that invalid SHA512 hash of cookie.
    #[error("Invalid SHA512 hash of cookie")]
    BadSha512,
    /// Error indicates that cookie is timed out.
    #[error("Cookie is timed out")]
    CookieTimedOut,
    /// Error indicates that cookie contains invalid real pk.
    #[error("Cookie contains invalid real pk")]
    InvalidRealPk,
    /// Error indicates that cookie contains invalid dht pk.
    #[error("Cookie contains invalid dht pk")]
    InvalidDhtPk,
    /// Error indicates that there is PacketsArrayError.
    #[error("PacketsArrayError occurs")]
    PacketsArrayError(PacketsArrayError),
    /// Error indicates that real data is empty.
    #[error("Real data is empty")]
    DataEmpty,
    /// Error indicates that invalid packet id.
    #[error("Invalid packet id: {:?}", id)]
    PacketId {
        /// The packet id that is invalid.
        id: u8,
    },
}

impl HandlePacketError {
    pub(crate) fn invalid_request_id(expect: u64, got: u64) -> HandlePacketError {
        HandlePacketError::InvalidRequestId {
            expect,
            got,
        }
    }

    pub(crate) fn no_udp_connection(addr: SocketAddr) -> HandlePacketError {
        HandlePacketError::NoUdpConnection {
            addr,
        }
    }

    pub(crate) fn no_tcp_connection(pk: PublicKey) -> HandlePacketError {
        HandlePacketError::NoTcpConnection {
            pk,
        }
    }

    pub(crate) fn packet_id(id: u8) -> HandlePacketError {
        HandlePacketError::PacketId {
            id,
        }
    }
}

/// Error that can happen while processing packets array.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SendDataError {
    /// Connection is not established.
    #[error("Connection is not established")]
    NoConnection,
    /// Error indicates that sending response packet error.
    #[error("Sending response error")]
    SendTo(SendPacketError),
    /// Error indicates that sending connection status error.
    #[error("Sending connection status error")]
    SendToConnectionStatus(SendError),
}

/// Error that can happen when calling `run`.
#[derive(Debug, PartialEq, Error)]
pub enum RunError {
    /// Sending pings error.
    #[error("Sending crypto data packet error")]
    SendData(SendDataError),
    /// Timeout error.
    #[error("Timeout error")]
    Timeout(Elapsed),
    /// NetCrypto periodical wakeup timer error.
    #[error("Netcrypto periodical wakeup timer error")]
    Wakeup,
}

/// Error that can happen during a lossless packet sending.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SendLosslessPacketError {
    /// Packet ID is outside lossless packets range.
    #[error("Packet ID is outside lossless packets range")]
    InvalidPacketId,
    /// Connection to a friend is not established.
    #[error("Connection to a friend is not established")]
    NoConnection,
    /// Packets send array is full.
    #[error("Packets send array is full")]
    FullSendArray(PacketsArrayError),
    /// Failed to send packet.
    #[error("Failed to send packet")]
    SendTo(SendDataError),
}

/// Error that can happen during a lossless packet sending.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum KillConnectionError {
    /// Connection to a friend is not established.
    #[error("Connection to a friend is not established")]
    NoConnection,
    /// Failed to send kill packet.
    #[error("Failed to send kill packet")]
    SendTo(SendDataError),
    /// Error indicates that sending connection status error.
    #[error("Sending connection status error")]
    SendToConnectionStatus(SendError),
}

/// Error that can happen during a packet sending.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SendPacketError {
    /// Failed to send TCP packet.
    #[error("Failed to send TCP packet")]
    Tcp(SendError),
    /// Failed to send UDP packet.
    #[error("Failed to send UDP packet")]
    Udp(SendError),
}
