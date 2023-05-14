use futures::channel::mpsc::SendError;
use std::io::Error as IoError;
use thiserror::Error;

use crate::relay::codec::{DecodeError, EncodeError};

/// Error that can happen when handling `Tcp relay` packet.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum HandlePacketError {
    /// Send packet(s) error.
    #[error("Send packet(s) error")]
    SendTo(SendError),
    /// Send packet(s) error.
    #[error("Send packet(s) error")]
    SendPacket(SendPacketError),
    /// Server must not send this packet to client.
    #[error("Server must not send this packet to client")]
    MustNotSend,
    /// Invalid connection ID when handling RouteResponse.
    #[error("Invalid connection ID when handling RouteResponse")]
    InvalidConnectionId,
    /// Connection ID is already linked.
    #[error("Connection ID is already linked")]
    AlreadyLinked,
    /// Unexpected route response packet is received.
    #[error("Unexpected route response packet is received")]
    UnexpectedRouteResponse,
}

/// Error that can happen when sending packet.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SendPacketError {
    /// Send packet(s) error.
    #[error("Send packet(s) error")]
    SendTo(SendError),
    /// Send packet(s) with wrong status.
    #[error("Send packet(s) with wrong status")]
    WrongStatus,
    /// Send packet(s) with destination_pk is not online.
    #[error("Send packet(s) with destination_pk is not online")]
    NotOnline,
    /// Send packet(s) with destination_pk is not linked.
    #[error("Send packet(s) with destination_pk is not linked")]
    NotLinked,
    /// Send packet(s) to a connection but no such connection.
    #[error("Send packet(s) to a connection but no such connection")]
    NoSuchConnection,
}

/// Error that can happen when spawning a connection.
#[derive(Debug, Error)]
pub enum SpawnError {
    /// Read socket to receive packet error.
    #[error("Read socket to receive packet error")]
    ReadSocket(DecodeError),
    /// Send packet(s) error.
    #[error("Send packet(s) error")]
    SendTo(SendPacketError),
    /// Handle packet(s) error.
    #[error("Handle packet(s) error")]
    HandlePacket(HandlePacketError),
    /// Tcp client io error.
    #[error("Tcp client io error")]
    Io(IoError),
    /// Tcp codec encode error.
    #[error("Tcp codec encode error")]
    Encode(EncodeError),
}

/// Error that can happen when handling a connection.
#[derive(Debug, Error)]
pub enum ConnectionError {
    /// Spawing after adding global connection error.
    #[error("Spawing after adding global connection error")]
    Spawn(SpawnError),
    /// Search relay by relay's PK, but no such relay.
    #[error("Search relay by relay's PK, but no such relay")]
    NoSuchRelay,
    /// Send packet(s) error.
    #[error("Send packet(s) error")]
    SendTo(SendPacketError),
    /// No connection to the node.
    #[error("No connection to the node")]
    NoConnection,
    /// Relay is not connected.
    #[error("Relay is not connected")]
    NotConnected,
    /// Tcp Connections wakeup timer error.
    #[error("Tcp Connections wakeup timer error")]
    Wakeup,
    /// Add connection to client error.
    #[error("Add connection to client error")]
    AddConnection,
}
