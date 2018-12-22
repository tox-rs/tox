/*! Errors enum for DHT server.
*/

use std::fmt;
use std::net::SocketAddr;
use futures::sync::mpsc;
use std::io::Error as IoError;
use tokio::timer::Error as TimerError;

use failure::{Backtrace, Context, Fail};
use crate::toxcore::dht::packet::*;
use crate::toxcore::onion::packet::*;

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
    #[fail(display = "Not handled error")]
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

impl From<mpsc::SendError<(Packet, SocketAddr)>> for HandlePacketError {
    fn from(error: mpsc::SendError<(Packet, SocketAddr)>) -> HandlePacketError {
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
    #[fail(display = "Sending response redirecting fails")]
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

impl From<mpsc::SendError<(Packet, SocketAddr)>> for HandleBootstrapInfoError {
    fn from(error: mpsc::SendError<(Packet, SocketAddr)>) -> HandleBootstrapInfoError {
        HandleBootstrapInfoError {
            ctx: error.context(HandleBootstrapInfoErrorKind::SendTo)
        }
    }
}

/// Error that can happen when calling `run_bootstrap_requests_sending`.
#[derive(Debug)]
pub struct BootstrapRequestsError {
    ctx: Context<BootstrapRequestsErrorKind>,
}

impl BootstrapRequestsError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &BootstrapRequestsErrorKind {
        self.ctx.get_context()
    }
}

impl Fail for BootstrapRequestsError {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for BootstrapRequestsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Clone, Debug, Eq, PartialEq, Fail)]
pub enum BootstrapRequestsErrorKind {
    /// Bootstrap request wakeup timer error
    #[fail(display = "Bootstrap wakeup timer error")]
    Wakeup,
    /// Send packet(s) error
    #[fail(display = "Send packet(s) error")]
    SendTo,
}

impl From<BootstrapRequestsErrorKind> for BootstrapRequestsError {
    fn from(kind: BootstrapRequestsErrorKind) -> BootstrapRequestsError {
        BootstrapRequestsError::from(Context::new(kind))
    }
}

impl From<Context<BootstrapRequestsErrorKind>> for BootstrapRequestsError {
    fn from(ctx: Context<BootstrapRequestsErrorKind>) -> BootstrapRequestsError {
        BootstrapRequestsError { ctx }
    }
}

impl From<TimerError> for BootstrapRequestsError {
    fn from(error: TimerError) -> BootstrapRequestsError {
        BootstrapRequestsError {
            ctx: error.context(BootstrapRequestsErrorKind::Wakeup)
        }
    }
}

impl From<mpsc::SendError<(Packet, SocketAddr)>> for BootstrapRequestsError {
    fn from(error: mpsc::SendError<(Packet, SocketAddr)>) -> BootstrapRequestsError {
        BootstrapRequestsError {
            ctx: error.context(BootstrapRequestsErrorKind::SendTo)
        }
    }
}

/// Error that can happen when calling `run_main_loop`.
#[derive(Debug)]
pub struct MainLoopError {
    ctx: Context<MainLoopErrorKind>,
}

impl MainLoopError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &MainLoopErrorKind {
        self.ctx.get_context()
    }
}

impl Fail for MainLoopError {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for MainLoopError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Clone, Debug, Eq, PartialEq, Fail)]
pub enum MainLoopErrorKind {
    /// Main loop wakeup timer error
    #[fail(display = "Main loop wakeup timer error")]
    Wakeup,
}

impl From<MainLoopErrorKind> for MainLoopError {
    fn from(kind: MainLoopErrorKind) -> MainLoopError {
        MainLoopError::from(Context::new(kind))
    }
}

impl From<Context<MainLoopErrorKind>> for MainLoopError {
    fn from(ctx: Context<MainLoopErrorKind>) -> MainLoopError {
        MainLoopError { ctx }
    }
}

impl From<TimerError> for MainLoopError {
    fn from(error: TimerError) -> MainLoopError {
        MainLoopError {
            ctx: error.context(MainLoopErrorKind::Wakeup)
        }
    }
}

/// Error that can happen when calling `dht_main_loop`.
#[derive(Debug)]
pub struct DhtLoopError {
    ctx: Context<DhtLoopErrorKind>,
}

impl DhtLoopError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &DhtLoopErrorKind {
        self.ctx.get_context()
    }
}

impl Fail for DhtLoopError {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for DhtLoopError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Clone, Debug, Eq, PartialEq, Fail)]
pub enum DhtLoopErrorKind {
    /// Main loop wakeup timer error
    #[fail(display = "Main loop wakeup timer error")]
    Wakeup,
    /// Send packet(s) error
    #[fail(display = "Send packet(s) error")]
    SendTo,
}

impl From<DhtLoopErrorKind> for DhtLoopError {
    fn from(kind: DhtLoopErrorKind) -> DhtLoopError {
        DhtLoopError::from(Context::new(kind))
    }
}

impl From<Context<DhtLoopErrorKind>> for DhtLoopError {
    fn from(ctx: Context<DhtLoopErrorKind>) -> DhtLoopError {
        DhtLoopError { ctx }
    }
}

impl From<TimerError> for DhtLoopError {
    fn from(error: TimerError) -> DhtLoopError {
        DhtLoopError {
            ctx: error.context(DhtLoopErrorKind::Wakeup)
        }
    }
}

impl From<mpsc::SendError<(Packet, SocketAddr)>> for DhtLoopError {
    fn from(error: mpsc::SendError<(Packet, SocketAddr)>) -> DhtLoopError {
        DhtLoopError {
            ctx: error.context(DhtLoopErrorKind::SendTo)
        }
    }
}

/// Error that can happen when calling `run_onion_key_refreshing`.
#[derive(Debug)]
pub struct OnionKeyRefreshingError {
    ctx: Context<OnionKeyRefreshingErrorKind>,
}

impl OnionKeyRefreshingError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &OnionKeyRefreshingErrorKind {
        self.ctx.get_context()
    }
}

impl Fail for OnionKeyRefreshingError {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for OnionKeyRefreshingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Clone, Debug, Eq, PartialEq, Fail)]
pub enum OnionKeyRefreshingErrorKind {
    /// Onion key refreshing wakeup timer error
    #[fail(display = "Onion key refreshing wakeup timer error")]
    Wakeup,
    /// Send packet(s) error
    #[fail(display = "Send packet(s) error")]
    SendTo,
}

impl From<OnionKeyRefreshingErrorKind> for OnionKeyRefreshingError {
    fn from(kind: OnionKeyRefreshingErrorKind) -> OnionKeyRefreshingError {
        OnionKeyRefreshingError::from(Context::new(kind))
    }
}

impl From<Context<OnionKeyRefreshingErrorKind>> for OnionKeyRefreshingError {
    fn from(ctx: Context<OnionKeyRefreshingErrorKind>) -> OnionKeyRefreshingError {
        OnionKeyRefreshingError { ctx }
    }
}

impl From<TimerError> for OnionKeyRefreshingError {
    fn from(error: TimerError) -> OnionKeyRefreshingError {
        OnionKeyRefreshingError {
            ctx: error.context(OnionKeyRefreshingErrorKind::Wakeup)
        }
    }
}

impl From<mpsc::SendError<(Packet, SocketAddr)>> for OnionKeyRefreshingError {
    fn from(error: mpsc::SendError<(Packet, SocketAddr)>) -> OnionKeyRefreshingError {
        OnionKeyRefreshingError {
            ctx: error.context(OnionKeyRefreshingErrorKind::SendTo)
        }
    }
}

/// Error that can happen when calling `run_pings_sending`.
#[derive(Debug)]
pub struct PingsSendingError {
    ctx: Context<PingsSendingErrorKind>,
}

impl PingsSendingError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &PingsSendingErrorKind {
        self.ctx.get_context()
    }
}

impl Fail for PingsSendingError {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for PingsSendingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Clone, Debug, Eq, PartialEq, Fail)]
pub enum PingsSendingErrorKind {
    /// Pings sending wakeup timer error
    #[fail(display = "Pings sending wakeup timer error")]
    Wakeup,
    /// Send packet(s) error
    #[fail(display = "Send packet(s) error")]
    SendTo,
}

impl From<PingsSendingErrorKind> for PingsSendingError {
    fn from(kind: PingsSendingErrorKind) -> PingsSendingError {
        PingsSendingError::from(Context::new(kind))
    }
}

impl From<Context<PingsSendingErrorKind>> for PingsSendingError {
    fn from(ctx: Context<PingsSendingErrorKind>) -> PingsSendingError {
        PingsSendingError { ctx }
    }
}

impl From<TimerError> for PingsSendingError {
    fn from(error: TimerError) -> PingsSendingError {
        PingsSendingError {
            ctx: error.context(PingsSendingErrorKind::Wakeup)
        }
    }
}

impl From<mpsc::SendError<(Packet, SocketAddr)>> for PingsSendingError {
    fn from(error: mpsc::SendError<(Packet, SocketAddr)>) -> PingsSendingError {
        PingsSendingError {
            ctx: error.context(PingsSendingErrorKind::SendTo)
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
    #[fail(display = "Sending pings error")]
    PingsSending,
    /// Refreshing onion key error
    #[fail(display = "Refreshing onion key error")]
    OnionKeyRefreshing,
    /// Main loop error
    #[fail(display = "Main loop error")]
    MainLoop,
    /// Sending bootstrap requests error
    #[fail(display = "Sending bootstrap requests error")]
    BootstrapRequests,
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

impl From<PingsSendingError> for RunError {
    fn from(error: PingsSendingError) -> RunError {
        RunError {
            ctx: error.context(RunErrorKind::PingsSending)
        }
    }
}

impl From<OnionKeyRefreshingError> for RunError {
    fn from(error: OnionKeyRefreshingError) -> RunError {
        RunError {
            ctx: error.context(RunErrorKind::OnionKeyRefreshing)
        }
    }
}

impl From<MainLoopError> for RunError {
    fn from(error: MainLoopError) -> RunError {
        RunError {
            ctx: error.context(RunErrorKind::MainLoop)
        }
    }
}

impl From<BootstrapRequestsError> for RunError {
    fn from(error: BootstrapRequestsError) -> RunError {
        RunError {
            ctx: error.context(RunErrorKind::BootstrapRequests)
        }
    }
}

