/*! Errors enum for DHT server.
*/

use futures::channel::mpsc::SendError;
use thiserror::Error;
use tokio::time::error::Elapsed;
use tox_packet::dht::GetPayloadError;

use crate::onion::{client::errors::{HandleAnnounceResponseError, HandleDataResponseError}, onion_announce::HandleDataRequestError};
use crate::net_crypto::errors::HandlePacketError as HandleNetCryptoPacketError;

/// Error that can happen when calling `handle_*` of packet.
#[derive(Debug, Error)]
pub enum HandlePacketError {
    /// Error indicates that getting payload of received packet error.
    #[error("Get payload of received packet error")]
    GetPayload(GetPayloadError),
    /// Error indicates that next_onion_return is none.
    #[error("Next onion return is none")]
    OnionResponseNext,
    /// Error indicates that sending response packet faces redirecting failure.
    #[error("Sending response redirecting error")]
    OnionResponseRedirect,
    /// Error indicates that sending response packet faces redirecting failure.
    #[error("Sending response redirecting error")]
    OnionResponseRedirectSend(SendError),
    /// Error indicates that BootstrapInfo error.
    #[error("BootstrapInfo handling error")]
    BootstrapInfoLength,
    /// Error indicates that sending response packet error.
    #[error("Sending response error")]
    SendTo(SendError),
    /// Error indicates that received packet's ping_id is zero.
    #[error("Zero ping id error")]
    ZeroPingId,
    /// Error indicates that received packet's ping_id does not match.
    #[error("Ping id mismatch error")]
    PingIdMismatch,
    /// Error indicates that there is no friend.
    #[error("Friend does not exist error")]
    NoFriend,
    /// Error indicates that NetCrypto is not initialized.
    #[error("NetCrypto is not initialized error")]
    NetCrypto,
    /// Error indicates that OnionClient is not initialized.
    #[error("OnionClient is not initialized error")]
    OnionClient,
    /// Error indicates that handling NetCrypto packet made an error.
    #[error("Handling NetCrypto packet failed")]
    HandleNetCrypto(HandleNetCryptoPacketError),
    /// Error indicates that handling OnionClient data packet made an error.
    #[error("Handling OnionClient data packet failed")]
    HandleOnionClientData(HandleDataResponseError),
    /// Error indicates that handling OnionClient announce packet made an error.
    #[error("Handling OnionClient announce packet failed")]
    HandleOnionClientAnnounce(HandleAnnounceResponseError),
    /// Error indicates that onion processing fails.
    #[error("Onion or NetCrypto related error")]
    Onion(HandleDataRequestError),
    /// Failed to send friend's IP address to the sink.
    #[error("Failed to send friend's IP address to the sink")]
    FriendSaddr(SendError),
}

/// Error that can happen when calling `run_*`.
#[derive(Debug, PartialEq, Error)]
pub enum RunError {
    /// Send packet(s) error.
    #[error("Send packet(s) error")]
    SendTo(SendError),
    /// Send packet(s) time out.
    #[error("Send packet(s) time out")]
    Timeout(Elapsed),
}

/// Error that can happen when calling `run_*`.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum PingError {
    /// Send packet(s) error.
    #[error("Send packet(s) error")]
    SendTo(SendError),
}
