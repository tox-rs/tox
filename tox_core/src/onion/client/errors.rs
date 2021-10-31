use futures::channel::mpsc::SendError;
use thiserror::Error;
use tox_packet::dht::GetPayloadError;

use crate::{dht::server::errors::PingError, relay::client::ConnectionError};

/// Error that can happen when handling `OnionAnnounceResponse` packet.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum HandleAnnounceResponseError {
    /// Invalid request ID when handling OnionAnnounceResponse.
    #[error("Invalid request ID when handling OnionAnnounceResponse")]
    InvalidRequestId,
    /// Invalid announce status in OnionAnnounceResponse.
    #[error("Invalid announce status in OnionAnnounceResponse")]
    InvalidAnnounceStatus,
    /// No friend with PK specified in OnionAnnounceResponse.
    #[error("No friend with PK specified in OnionAnnounceResponse")]
    NoFriendWithPk,
    /// Invalid payload.
    #[error("Invalid payload")]
    InvalidPayload(GetPayloadError),
    /// Send packet(s) error.
    #[error("Send packet(s) error")]
    SendTo(SendError),
}

/// Error that can happen when handling `DhtPkAnnounce` packet.
#[derive(Debug, Error)]
pub enum HandleDhtPkAnnounceError {
    /// No friend with PK specified in OnionAnnounceResponse.
    #[error("No friend with PK specified in OnionAnnounceResponse")]
    NoFriendWithPk,
    /// Invalid no_reply.
    #[error("Invalid no_reply")]
    InvalidNoReply,
    /// Failed to ping node.
    #[error("Failed to ping node")]
    PingNode(PingError),
    /// Failed to add TCP relay.
    #[error("Failed to add TCP relay")]
    AddRelay(ConnectionError),
    /// Send packet(s) error.
    #[error("Send packet(s) error")]
    SendTo(SendError),
}

/// Error that can happen when handling `OnionDataResponse` packet.
#[derive(Debug, Error)]
pub enum HandleDataResponseError {
    /// Invalid payload.
    #[error("Invalid payload")]
    InvalidPayload(GetPayloadError),
    /// Invalid inner payload.
    #[error("Invalid inner payload")]
    InvalidInnerPayload(GetPayloadError),
    /// Failed to handle DHT `PublicKey` announce.
    #[error("Failed to handle DHT PublicKey announce")]
    DhtPkAnnounce(HandleDhtPkAnnounceError),
    /// Failed to send a friend request.
    #[error("Failed to send a friend request")]
    FriendRequest(SendError),
}

/// Error that can happen when calling `run_*`.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum RunError {
    /// Timer error.
    #[error("Timer error")]
    Wakeup,
    /// Send packet(s) error.
    #[error("Send packet(s) error")]
    SendTo(SendError),
}
