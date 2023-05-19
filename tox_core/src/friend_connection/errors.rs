//! Errors for friend connections module.

use futures::channel::mpsc::SendError;
use thiserror::Error;
use tokio::time::error::Elapsed;

use crate::{
    net_crypto::errors::{KillConnectionError, SendLosslessPacketError},
    relay::client::ConnectionError,
};

/// Error that can happen while removing a friend
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum RemoveFriendError {
    /// Failed to kill net_crypto connection.
    #[error("Failed to kill net_crypto connection")]
    KillConnection(KillConnectionError),
    /// There is no such friend.
    #[error("There is no such friend")]
    NoFriend,
}

/// Error that can happen while removing a friend
#[derive(Debug, Error)]
pub enum RunError {
    /// Wakeup timer error.
    #[error("Wakeup timer error")]
    Wakeup,
    /// Timeout error.
    #[error("Timeout error")]
    Timeout(Elapsed),
    /// Failed to kill net_crypto connection.
    #[error("Failed to kill net_crypto connection")]
    KillConnection(KillConnectionError),
    /// Failed to send packet.
    #[error("Failed to send packet")]
    SendTo(SendLosslessPacketError),
    /// Failed to add TCP connection.
    #[error("Failed to TCP connection")]
    AddTcpConnection(ConnectionError),
    /// Failed to send connection status.
    #[error("Failed to send connection status")]
    SendToConnectionStatus(SendError),
}

/// Error that can happen while handling `ShareRelays` packet.
#[derive(Debug, Error)]
pub enum HandleShareRelaysError {
    /// Failed to add TCP connection.
    #[error("Failed to TCP connection")]
    AddTcpConnection(ConnectionError),
}
