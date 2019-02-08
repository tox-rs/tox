/*! Errors enum for DHT server.
*/

use std::fmt;
use std::net::SocketAddr;
use futures::sync::mpsc;
use std::io::Error as IoError;
use tokio::timer::Error as TimerError;
use tokio::timer::timeout::Error as TimeoutError;

use failure::{Backtrace, Context, Fail};
use crate::toxcore::dht::packet::*;
use crate::toxcore::onion::packet::*;
use crate::toxcore::net_crypto::errors::HandlePacketError as NetCryptoHandlePacketError;

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
#[derive(Clone, Debug, Eq, PartialEq, Fail)]
pub enum HandlePacketErrorKind {
    /// Error indicates that getting payload of received packet error.
    #[fail(display = "Get payload of received packet error")]
    GetPayload,
    /// Error indicates that onion response error.
    #[fail(display = "Onion response error")]
    OnionResponse,
    /// Error indicates that BootstrapInfo error.
    #[fail(display = "BootstrapInfo handling error")]
    BootstrapInfo,
    /// Error indicates that sending response packet error.
    #[fail(display = "Sending response error")]
    SendTo,
    /// Error indicates that received packet is not handled here.
    #[fail(display = "This packet kind is not handled here error")]
    NotHandled,
    /// Error indicates that received packet's ping_id is zero.
    #[fail(display = "Zero ping id error")]
    ZeroPingId,
    /// Error indicates that received packet's ping_id does not match.
    #[fail(display = "Ping id mismatch error")]
    PingIdMismatch,
    /// Error indicates that there is no friend.
    #[fail(display = "Friend does not exist error")]
    NoFriend,
    /// Error indicates that NetCrypto is not initialized.
    #[fail(display = "NetCrypto is not initialized error")]
    NetCrypto,
    /// Error indicates that handling NetCrypto packet made an error.
    #[fail(display = "Handling NetCrypto packet failed")]
    HandleNetCrypto,
    /// Error indicates that onion or net crypto processing fails.
    /// ## This enum entry is temporary for onion or net crypto module's transition to failure
    #[fail(display = "Onion or NetCrypto related error")]
    OnionOrNetCrypto,
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

impl From<OnionResponseError> for HandlePacketError {
    fn from(error: OnionResponseError) -> HandlePacketError {
        HandlePacketError {
            ctx: error.context(HandlePacketErrorKind::OnionResponse)
        }
    }
}

impl From<HandleBootstrapInfoError> for HandlePacketError {
    fn from(error: HandleBootstrapInfoError) -> HandlePacketError {
        HandlePacketError {
            ctx: error.context(HandlePacketErrorKind::BootstrapInfo)
        }
    }
}

impl From<NetCryptoHandlePacketError> for HandlePacketError {
    fn from(error: NetCryptoHandlePacketError) -> HandlePacketError {
        HandlePacketError {
            ctx: error.context(HandlePacketErrorKind::HandleNetCrypto)
        }
    }
}

impl From<IoError> for HandlePacketError {
    fn from(error: IoError) -> HandlePacketError {
        HandlePacketError {
            ctx: error.context(HandlePacketErrorKind::OnionOrNetCrypto)
        }
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

/// Error that can happen when calling `handle_bootstrap_info`.
#[derive(Debug)]
pub struct HandleBootstrapInfoError {
    ctx: Context<HandleBootstrapInfoErrorKind>,
}

impl HandleBootstrapInfoError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &HandleBootstrapInfoErrorKind {
        self.ctx.get_context()
    }
}

impl Fail for HandleBootstrapInfoError {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for HandleBootstrapInfoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Clone, Debug, Eq, PartialEq, Fail)]
pub enum HandleBootstrapInfoErrorKind {
    /// Error indicates that length of received BootstrapInfo packet error.
    #[fail(display = "Length of BootstrapInfo packet error")]
    Length,
    /// Error indicates that sending response packet error.
    #[fail(display = "Sending response error")]
    SendTo,
}

impl From<HandleBootstrapInfoErrorKind> for HandleBootstrapInfoError {
    fn from(kind: HandleBootstrapInfoErrorKind) -> HandleBootstrapInfoError {
        HandleBootstrapInfoError::from(Context::new(kind))
    }
}

impl From<Context<HandleBootstrapInfoErrorKind>> for HandleBootstrapInfoError {
    fn from(ctx: Context<HandleBootstrapInfoErrorKind>) -> HandleBootstrapInfoError {
        HandleBootstrapInfoError { ctx }
    }
}

impl From<TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> for HandleBootstrapInfoError {
    fn from(error: TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>) -> HandleBootstrapInfoError {
        HandleBootstrapInfoError {
            ctx: error.context(HandleBootstrapInfoErrorKind::SendTo)
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures::sink::Sink;
    use futures::future::Future;
    use std::io::ErrorKind;
    use std::time::Duration;
    use crate::toxcore::crypto_core::*;
    use crate::toxcore::io_tokio::*;

    #[test]
    fn handle_packet_error() {
        let error = HandlePacketError::from(HandlePacketErrorKind::ZeroPingId);
        assert!(error.cause().is_none());
        assert!(error.backtrace().is_some());
        assert_eq!(format!("{}", error), "Zero ping id error".to_owned());
    }

    #[test]
    fn handle_packet_send_error() {
        let (tx, rx) = mpsc::channel(32);

        let packet = Packet::BootstrapInfo(BootstrapInfo {
            version: 1717,
            motd: vec![1, 2, 3, 4],
        });
        let sock: SocketAddr = "127.0.0.1:33445".parse().unwrap();

        drop(rx);
        let res = send_to_bounded(&tx, (packet, sock), Duration::from_secs(1)).wait();
        assert!(res.is_err());
        let new_error = HandlePacketError::from(res.err().unwrap());
        assert_eq!(*new_error.kind(), HandlePacketErrorKind::SendTo);
    }

    #[test]
    fn handle_packet_io_error() {
        let e = IoError::new(ErrorKind::Other, "Test error");
        let new_error = HandlePacketError::from(e);
        assert_eq!(*new_error.kind(), HandlePacketErrorKind::OnionOrNetCrypto);
    }

    #[test]
    fn onion_response_send_error() {
        let (tx, rx) = mpsc::channel(32);

        let packet = Packet::BootstrapInfo(BootstrapInfo {
            version: 1717,
            motd: vec![1, 2, 3, 4],
        });
        let sock: SocketAddr = "127.0.0.1:33445".parse().unwrap();

        drop(rx);
        let res = tx.send((packet, sock)).wait();
        assert!(res.is_err());
        let new_error = OnionResponseError::from(res.err().unwrap());
        assert_eq!(*new_error.kind(), OnionResponseErrorKind::SendTo);
    }

    #[test]
    fn inner_onion_response_send_error() {
        let (tx, rx) = mpsc::channel(32);

        let packet = InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42; 123]
        });
        let sock: SocketAddr = "127.0.0.1:33445".parse().unwrap();

        drop(rx);
        let res = tx.send((packet, sock)).wait();
        assert!(res.is_err());
        let new_error = OnionResponseError::from(res.err().unwrap());
        assert_eq!(*new_error.kind(), OnionResponseErrorKind::Eof);
    }

    #[test]
    fn bootstrap_info_send_error() {
        let (tx, rx) = mpsc::channel(32);

        let packet = Packet::BootstrapInfo(BootstrapInfo {
            version: 1717,
            motd: vec![1, 2, 3, 4],
        });
        let sock: SocketAddr = "127.0.0.1:33445".parse().unwrap();

        drop(rx);
        let res = send_to_bounded(&tx, (packet, sock), Duration::from_secs(1)).wait();
        assert!(res.is_err());
        let new_error = HandleBootstrapInfoError::from(res.err().unwrap());
        assert_eq!(*new_error.kind(), HandleBootstrapInfoErrorKind::SendTo);
    }

    #[test]
    fn run_send_error() {
        let (tx, rx) = mpsc::channel(32);

        let packet = Packet::BootstrapInfo(BootstrapInfo {
            version: 1717,
            motd: vec![1, 2, 3, 4],
        });
        let sock: SocketAddr = "127.0.0.1:33445".parse().unwrap();

        drop(rx);
        let res = send_to_bounded(&tx, (packet, sock), Duration::from_secs(1)).wait();
        assert!(res.is_err());
        let new_error = RunError::from(res.err().unwrap());
        assert_eq!(*new_error.kind(), RunErrorKind::SendTo);
    }

    #[test]
    fn handle_packet_error_kind() {
        let get_payload = HandlePacketErrorKind::GetPayload;
        assert_eq!(format!("{}", get_payload), "Get payload of received packet error".to_owned());

        let onion_response = HandlePacketErrorKind::OnionResponse;
        assert_eq!(format!("{}", onion_response), "Onion response error".to_owned());

        let bootstrap_info = HandlePacketErrorKind::BootstrapInfo;
        assert_eq!(format!("{}", bootstrap_info), "BootstrapInfo handling error".to_owned());

        let send_to = HandlePacketErrorKind::SendTo;
        assert_eq!(format!("{}", send_to), "Sending response error".to_owned());

        let not_handled = HandlePacketErrorKind::NotHandled;
        assert_eq!(format!("{}", not_handled), "This packet kind is not handled here error".to_owned());

        let zero_ping_id = HandlePacketErrorKind::ZeroPingId;
        assert_eq!(format!("{}", zero_ping_id), "Zero ping id error".to_owned());

        let ping_id_mismatch = HandlePacketErrorKind::PingIdMismatch;
        assert_eq!(format!("{}", ping_id_mismatch), "Ping id mismatch error".to_owned());

        let no_friend = HandlePacketErrorKind::NoFriend;
        assert_eq!(format!("{}", no_friend), "Friend does not exist error".to_owned());

        let net_crypto = HandlePacketErrorKind::NetCrypto;
        assert_eq!(format!("{}", net_crypto), "NetCrypto is not initialized error".to_owned());

        let onion = HandlePacketErrorKind::OnionOrNetCrypto;
        assert_eq!(format!("{}", onion), "Onion or NetCrypto related error".to_owned());
    }

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
    fn bootstrap_info_error() {
        let error = HandleBootstrapInfoError::from(HandleBootstrapInfoErrorKind::Length);
        assert!(error.cause().is_none());
        assert!(error.backtrace().is_some());
        assert_eq!(format!("{}", error), "Length of BootstrapInfo packet error".to_owned());
    }

    #[test]
    fn bootstrap_info_error_kind() {
        let length = HandleBootstrapInfoErrorKind::Length;
        assert_eq!(format!("{}", length), "Length of BootstrapInfo packet error".to_owned());

        let send_to = HandleBootstrapInfoErrorKind::SendTo;
        assert_eq!(format!("{}", send_to), "Sending response error".to_owned());
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
}
