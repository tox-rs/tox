//! Errors for friend connections module.

use failure::Fail;

error_kind! {
    #[doc = "Error that can happen while removing a friend"]
    #[derive(Debug)]
    RemoveFriendError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Debug, Eq, PartialEq, Fail)]
    RemoveFriendErrorKind {
        #[doc = "Failed to kill net_crypto connection."]
        #[fail(display = "Failed to kill net_crypto connection")]
        KillConnection,
        #[doc = "There is no such friend."]
        #[fail(display = "There is no such friend")]
        NoFriend,
    }
}

error_kind! {
    #[doc = "Error that can happen while removing a frind"]
    #[derive(Debug)]
    RunError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Debug, Eq, PartialEq, Fail)]
    RunErrorKind {
        #[doc = "Wakeup timer error."]
        #[fail(display = "Wakeup timer error")]
        Wakeup,
        #[doc = "Timeout error."]
        #[fail(display = "Timeout error")]
        Timeout,
        #[doc = "Failed to kill net_crypto connection."]
        #[fail(display = "Failed to kill net_crypto connection")]
        KillConnection,
        #[doc = "Failed to send packet."]
        #[fail(display = "Failed to send packet")]
        SendTo,
        #[doc = "Failed to add TCP connection."]
        #[fail(display = "Failed to TCP connection")]
        AddTcpConnection,
        #[doc = "Failed to send connection status."]
        #[fail(display = "Failed to send connection status")]
        SendToConnectionStatus
    }
}

error_kind! {
    #[doc = "Error that can happen while handling `ShareRelays` packet."]
    #[derive(Debug)]
    HandleShareRelaysError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Debug, Eq, PartialEq, Fail)]
    HandleShareRelaysErrorKind {
        #[doc = "Failed to add TCP connection."]
        #[fail(display = "Failed to TCP connection")]
        AddTcpConnection
    }
}
