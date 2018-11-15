/*! Error enums for DHT.
*/

use nom::{ErrorKind, Needed};

use std::convert::From;
use std::io::Error as IoError;
use std::io::ErrorKind as IoErrorKind;
use tokio::timer::Error as TimerError;
use toxcore::io_tokio::*;

/// Error that can happen when calling `get_payload` of packet.
#[derive(Debug, Fail)]
pub enum GetPayloadError {
    /// Error indicates that received payload of encrypted packet can't be decrypted
    #[fail(display = "Decrypt encrypted payload of {:?} packet error.", packet)]
    DecryptError {
        /// Packet type
        packet: String
    },
    /// Error indicates that more data is needed to parse decrypted payload of packet
    #[fail(display = "Payload of {:?} packet should not be incomplete: {:?}, payload: {:?}", packet, needed, payload)]
    IncompletePayload {
        /// Packet type
        packet: String,
        /// Required data size to be parsed
        needed: Needed,
        /// Received payload of packet
        payload: Vec<u8>,
    },
    /// Error indicates that decrypted payload of packet can't be parsed
    #[fail(display = "Deserialize payload of {:?} packet. error: {:?}, payload: {:?}", packet, error, payload)]
    DeserializeError {
        /// Packet type
        packet: String,
        /// Parsing error
        error: ErrorKind,
        /// Received payload of packet
        payload: Vec<u8>,
    }
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum SendNatPingReqError {
    /// Send error
    #[fail(display = "Send packet error: {:?}", error)]
    Inner {
        /// Send packet error
        error: SendToError
    },
    /// Send error
    #[fail(display = "Send packet error: {:?}", error)]
    PunchHoles {
        /// Send packet error
        error: SendAllToError
    },
}

/// Error that can happen during server execution
#[derive(Debug, Fail)]
pub enum ServerRunError {
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    RunPingsSending {
        /// IO error
        error: RunPingsSendingError
    },
    /// Ping wakeups timer error
    #[fail(display = "Ping wakeups timer error: {:?}", error)]
    RunMainLoop {
        /// Timer error
        error: RunMainLoopError
    },
    /// Ping wakeups timer error
    #[fail(display = "Ping wakeups timer error: {:?}", error)]
    RunBootstrapReqSending {
        /// Timer error
        error: RunBootstrapReqSendingError
    },
    /// Temporary error to map onion and others
    #[fail(display = "Send pings error: {:?}", error)]
    Other {
        error: IoError
    }
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum RunPingsSendingError {
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    PingsSending {
        /// IO error
        error: SendPingsError
    },
    /// Ping wakeups timer error
    #[fail(display = "Ping wakeups timer error: {:?}", error)]
    WakeupsError {
        /// Timer error
        error: TimerError
    },
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum RunMainLoopError {
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    DhtMainLoop {
        /// IO error
        error: DhtMainLoopError
    },
    /// Ping wakeups timer error
    #[fail(display = "Ping wakeups timer error: {:?}", error)]
    WakeupsError {
        /// Timer error
        error: TimerError
    },
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum HandlePacketError {
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    PingReq {
        /// IO error
        error: HandlePingReqError
    },
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    PingResp {
        /// IO error
        error: HandlePingRespError
    },
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    NodesReq {
        /// IO error
        error: HandleNodesReqError
    },
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    NodesResp {
        /// IO error
        error: HandleNodesRespError
    },
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    DhtReq {
        /// IO error
        error: HandleDhtReqError
    },
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    LanDiscovery {
        /// IO error
        error: HandleLanDiscoveryError
    },
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    Other {
        /// IO error
        error: IoError
    },
    /// Incoming IO error
    #[fail(display = "Incoming IO error: ")]
    ClientOnly,
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum HandlePingReqError {
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    GetPayload {
        /// IO error
        error: GetPayloadError
    },
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    PingAdd {
        /// IO error
        error: PingAddError
    },
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    PingResp {
        /// IO error
        error: SendToError
    },
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum HandlePingRespError {
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    GetPayload {
        /// IO error
        error: GetPayloadError
    },
    /// Incoming IO error
    #[fail(display = "Incoming IO ")]
    PingIdIsZero,
    /// Incoming IO error
    #[fail(display = "Incoming IO error")]
    PingIdMismatch,
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum HandleNodesReqError {
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    GetPayload {
        /// IO error
        error: GetPayloadError
    },
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    PingAdd {
        /// IO error
        error: PingAddError
    },
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    NodesResp {
        /// IO error
        error: SendToError
    },
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum HandleNodesRespError {
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    GetPayload {
        /// IO error
        error: GetPayloadError
    },
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum HandleDhtReqError {
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    GetPayload {
        /// IO error
        error: GetPayloadError
    },
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    NatPingReq {
        /// IO error
        error: HandleNatPingReqError
    },
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    NatPingResp {
        /// IO error
        error: HandleNatPingRespError
    },
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    SendToNode {
        /// IO error
        error: SendToError
    },
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum HandleNatPingReqError {
    /// Incoming IO error
    #[fail(display = "Incoming IO error")]
    CannotFindFriend,
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    SendNatPingResp {
        /// IO error
        error: SendToError
    },
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum HandleLanDiscoveryError {
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    SendNodesReq {
        /// IO error
        error: SendToError
    },
}
/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum HandleNatPingRespError {
    /// Incoming IO error
    #[fail(display = "Incoming IO error")]
    CannotFindFriend,
    /// Incoming IO error
    #[fail(display = "Incoming IO ")]
    PingIdIsZero,
    /// Incoming IO error
    #[fail(display = "Incoming IO error")]
    PingIdMismatch,
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum SendBootstrapReqsError {
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    SendNodesReq {
        /// IO error
        error: SendToError
    },
}
/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum RunBootstrapReqSendingError {
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    SendBootstrapReqs {
        /// IO error
        error: SendBootstrapReqsError
    },
    /// Ping wakeups timer error
    #[fail(display = "Ping wakeups timer error: {:?}", error)]
    WakeupsError {
        /// Timer error
        error: TimerError
    },
}
/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum SendPingsError {
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    SendPingReq {
        /// IO error
        error: SendToError
    },
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum PingAddError {
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    SendPingReq {
        /// IO error
        error: SendToError
    },
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum DhtMainLoopError {
    /// Send error
    #[fail(display = "Send packet error: {:?}", error)]
    SendNodesReqToFriends {
        /// Send packet error
        error: SendNodesReqToFriendsError
    },
    /// Send error
    #[fail(display = "Send packet error: {:?}", error)]
    PingNodesToBootstrap {
        /// Send packet error
        error: PingNodesToBootstrapError
    },
    /// Send error
    #[fail(display = "Send packet error: {:?}", error)]
    PingCloseNodes {
        /// Send packet error
        error: PingCloseNodesError
    },
    /// Send error
    #[fail(display = "Send packet error: {:?}", error)]
    SendNodesReqRandom {
        /// Send packet error
        error: SendNodesReqRandomError
    },
    /// Send error
    #[fail(display = "Send packet error: {:?}", error)]
    SendNatPingReq {
        /// Send packet error
        error: SendNatPingReqError
    },
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum SendNodesReqToFriendsError {
    #[fail(display = "Send packet error: {:?}", error)]
    PingNodesToBootstrap {
        /// Send packet error
        error: PingNodesToBootstrapError
    },
    /// Send error
    #[fail(display = "Send packet error: {:?}", error)]
    PingCloseNodes {
        /// Send packet error
        error: PingCloseNodesError
    },
    /// Send error
    #[fail(display = "Send packet error: {:?}", error)]
    SendNodesReqRandom {
        /// Send packet error
        error: SendNodesReqRandomError
    },
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum PingNodesToBootstrapError {
    /// Send error
    #[fail(display = "Send packet error: {:?}", error)]
    SendNodesReq {
        /// Send packet error
        error: SendToError
    },
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum PingCloseNodesError {
    /// Send error
    #[fail(display = "Send packet error: {:?}", error)]
    SendNodesReq {
        /// Send packet error
        error: SendToError
    },
}

/// Error that can happen during sending packet to peer.
#[derive(Debug, Fail)]
pub enum SendNodesReqRandomError {
    /// Send error
    #[fail(display = "Send packet error: {:?}", error)]
    SendNodesReq {
        /// Send packet error
        error: SendToError
    },
}

/// From trait for temporary use during transition from io:Error to custom enum error of failure crate
impl From<GetPayloadError> for IoError {
    fn from(_item: GetPayloadError) -> Self {
        IoError::new(IoErrorKind::Other, "GetPayloadError occurred.")
    }
}
