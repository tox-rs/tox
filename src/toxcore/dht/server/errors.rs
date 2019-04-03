/*! Errors enum for DHT server.
*/

use std::fmt;
use std::net::SocketAddr;
use futures::sync::mpsc;
use tokio::timer::Error as TimerError;
use tokio::timer::timeout::Error as TimeoutError;

use failure::{Backtrace, Context, Fail};
use crate::toxcore::dht::packet::*;
use crate::toxcore::onion::packet::*;

error_kind! {
    #[doc = "Error that can happen when calling `handle_*` of packet."]
    #[derive(Debug)]
    HandlePacketError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Clone, Debug, Eq, PartialEq, Fail)]
    HandlePacketErrorKind {
        #[doc = "Error indicates that getting payload of received packet error."]
        #[fail(display = "Get payload of received packet error")]
        GetPayload,
        #[doc = "Error indicates that onion response error."]
        #[fail(display = "Onion response error")]
        OnionResponse,
        #[doc = "Error indicates that BootstrapInfo error."]
        #[fail(display = "BootstrapInfo handling error")]
        BootstrapInfoLength,
        #[doc = "Error indicates that sending response packet error."]
        #[fail(display = "Sending response error")]
        SendTo,
        #[doc = "Error indicates that received packet is not handled here."]
        #[fail(display = "This packet kind is not handled here error")]
        NotHandled,
        #[doc = "Error indicates that received packet's ping_id is zero."]
        #[fail(display = "Zero ping id error")]
        ZeroPingId,
        #[doc = "Error indicates that received packet's ping_id does not match."]
        #[fail(display = "Ping id mismatch error")]
        PingIdMismatch,
        #[doc = "Error indicates that there is no friend."]
        #[fail(display = "Friend does not exist error")]
        NoFriend,
        #[doc = "Error indicates that NetCrypto is not initialized."]
        #[fail(display = "NetCrypto is not initialized error")]
        NetCrypto,
        #[doc = "Error indicates that handling NetCrypto packet made an error."]
        #[fail(display = "Handling NetCrypto packet failed")]
        HandleNetCrypto,
        #[doc = "Error indicates that onion or net crypto processing fails."]
        #[doc = "## This enum entry is temporary for onion or net crypto module's transition to failure"]
        #[fail(display = "Onion or NetCrypto related error")]
        OnionOrNetCrypto,
        #[doc = "Failed to send friend's IP address to the sink."]
        #[fail(display = "Failed to send friend's IP address to the sink")]
        FriendSaddr
    }
}

/// Error that can happen when calling `handle_onion_response_*` of packet.
#[derive(Debug)]
pub struct OnionResponseError {
    ctx: Context<OnionResponseErrorKind>,
}

impl OnionResponseError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &OnionResponseErrorKind {
        self.ctx.get_context()
    }
}

impl Fail for OnionResponseError {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for OnionResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Clone, Debug, Eq, PartialEq, Fail)]
pub enum OnionResponseErrorKind {
    /// Error indicates that next_onion_return is none"
    #[fail(display = "Next onion return is none")]
    Next,
    /// Error indicates that sending response packet error.
    #[fail(display = "Sending response error")]
    SendTo,
    /// Error indicates that sending response packet faces unexpected eof.
    #[fail(display = "Sending response faces unexpected eof")]
    Eof,
    /// Error indicates that sending response packet faces redirecting failure.
    #[fail(display = "Sending response redirecting error")]
    Redirect,
}

impl From<mpsc::SendError<(Packet, SocketAddr)>> for OnionResponseError {
    fn from(error: mpsc::SendError<(Packet, SocketAddr)>) -> OnionResponseError {
        OnionResponseError {
            ctx: error.context(OnionResponseErrorKind::SendTo)
        }
    }
}

impl From<OnionResponseErrorKind> for OnionResponseError {
    fn from(kind: OnionResponseErrorKind) -> OnionResponseError {
        OnionResponseError::from(Context::new(kind))
    }
}

impl From<Context<OnionResponseErrorKind>> for OnionResponseError {
    fn from(ctx: Context<OnionResponseErrorKind>) -> OnionResponseError {
        OnionResponseError { ctx }
    }
}

impl From<mpsc::SendError<(InnerOnionResponse, SocketAddr)>> for OnionResponseError {
    fn from(error: mpsc::SendError<(InnerOnionResponse, SocketAddr)>) -> OnionResponseError {
        OnionResponseError {
            ctx: error.context(OnionResponseErrorKind::Eof)
        }
    }
}

/// Error that can happen when calling `run_*`.
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
    /// Various loop wakeup timer error
    #[fail(display = "Dht loop wakeup timer error")]
    Wakeup,
    /// Send packet(s) error
    #[fail(display = "Send packet(s) error")]
    SendTo,
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

impl From<TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> for RunError {
    fn from(error: TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>) -> RunError {
        RunError {
            ctx: error.context(RunErrorKind::SendTo)
        }
    }
}

/// Error that can happen when calling `run_*`.
#[derive(Debug)]
pub struct PingError {
    ctx: Context<PingErrorKind>,
}

impl PingError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &PingErrorKind {
        self.ctx.get_context()
    }
}

impl Fail for PingError {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for PingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Clone, Debug, Eq, PartialEq, Fail)]
pub enum PingErrorKind {
    /// Send packet(s) error
    #[fail(display = "Send packet(s) error")]
    SendTo,
}

impl From<PingErrorKind> for PingError {
    fn from(kind: PingErrorKind) -> PingError {
        PingError::from(Context::new(kind))
    }
}

impl From<Context<PingErrorKind>> for PingError {
    fn from(ctx: Context<PingErrorKind>) -> PingError {
        PingError { ctx }
    }
}

impl From<TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> for PingError {
    fn from(error: TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>) -> PingError {
        PingError {
            ctx: error.context(PingErrorKind::SendTo)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onion_response_error() {
        let error = OnionResponseError::from(OnionResponseErrorKind::Next);
        assert!(error.cause().is_none());
        assert!(error.backtrace().is_some());
        assert_eq!(format!("{}", error), "Next onion return is none".to_owned());
    }

    #[test]
    fn onion_response_error_kind() {
        let next = OnionResponseErrorKind::Next;
        assert_eq!(format!("{}", next), "Next onion return is none".to_owned());

        let send_to = OnionResponseErrorKind::SendTo;
        assert_eq!(format!("{}", send_to), "Sending response error".to_owned());

        let eof = OnionResponseErrorKind::Eof;
        assert_eq!(format!("{}", eof), "Sending response faces unexpected eof".to_owned());

        let redirect = OnionResponseErrorKind::Redirect;
        assert_eq!(format!("{}", redirect), "Sending response redirecting error".to_owned());
    }

    #[test]
    fn run_error() {
        let error = RunError::from(RunErrorKind::Wakeup);
        assert!(error.cause().is_none());
        assert!(error.backtrace().is_some());
        assert_eq!(format!("{}", error), "Dht loop wakeup timer error".to_owned());
    }

    #[test]
    fn run_error_kind() {
        let wake_up = RunErrorKind::Wakeup;
        assert_eq!(format!("{}", wake_up), "Dht loop wakeup timer error".to_owned());

        let send_to = RunErrorKind::SendTo;
        assert_eq!(format!("{}", send_to), "Send packet(s) error".to_owned());
    }

    #[test]
    fn ping_error() {
        let error = PingError::from(PingErrorKind::SendTo);
        assert!(error.cause().is_none());
        assert!(error.backtrace().is_some());
        assert_eq!(format!("{}", error), "Send packet(s) error".to_owned());
    }

    #[test]
    fn ping_error_kind() {
        let send_to = PingErrorKind::SendTo;
        assert_eq!(format!("{}", send_to), "Send packet(s) error".to_owned());
    }
}
