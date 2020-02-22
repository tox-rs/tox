/*! Errors enum for DHT server.
*/

use failure::Fail;

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
        #[doc = "Error indicates that next_onion_return is none."]
        #[fail(display = "Next onion return is none")]
        OnionResponseNext,
        #[doc = "Error indicates that sending response packet faces redirecting failure."]
        #[fail(display = "Sending response redirecting error")]
        OnionResponseRedirect,
        #[doc = "Error indicates that BootstrapInfo error."]
        #[fail(display = "BootstrapInfo handling error")]
        BootstrapInfoLength,
        #[doc = "Error indicates that sending response packet error."]
        #[fail(display = "Sending response error")]
        SendTo,
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
        #[doc = "Error indicates that OnionClient is not initialized."]
        #[fail(display = "OnionClient is not initialized error")]
        OnionClient,
        #[doc = "Error indicates that handling NetCrypto packet made an error."]
        #[fail(display = "Handling NetCrypto packet failed")]
        HandleNetCrypto,
        #[doc = "Error indicates that handling OnionClient packet made an error."]
        #[fail(display = "Handling OnionClient packet failed")]
        HandleOnionClient,
        #[doc = "Error indicates that onion or net crypto processing fails."]
        #[doc = "## This enum entry is temporary for onion or net crypto module's transition to failure"]
        #[fail(display = "Onion or NetCrypto related error")]
        OnionOrNetCrypto,
        #[doc = "Failed to send friend's IP address to the sink."]
        #[fail(display = "Failed to send friend's IP address to the sink")]
        FriendSaddr
    }
}

error_kind! {
    #[doc = "Error that can happen when calling `run_*`."]
    #[derive(Debug)]
    RunError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Clone, Debug, Eq, PartialEq, Fail)]
    RunErrorKind {
        #[doc = "Send packet(s) error."]
        #[fail(display = "Send packet(s) error")]
        SendTo,
    }
}

error_kind! {
    #[doc = "Error that can happen when calling `run_*`."]
    #[derive(Debug)]
    PingError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Clone, Debug, Eq, PartialEq, Fail)]
    PingErrorKind {
        #[doc = "Send packet(s) error."]
        #[fail(display = "Send packet(s) error")]
        SendTo,
    }
}
