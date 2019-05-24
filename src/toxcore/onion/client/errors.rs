error_kind! {
    #[doc = "Error that can happen when handling `OnionAnnounceResponse` packet."]
    #[derive(Debug)]
    HandleAnnounceResponseError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Clone, Debug, Eq, PartialEq, failure::Fail)]
    HandleAnnounceResponseErrorKind {
        #[doc = "Invalid request ID when handling OnionAnnounceResponse."]
        #[fail(display = "Invalid request ID when handling OnionAnnounceResponse")]
        InvalidRequestId,
        #[doc = "Invalid announce status in OnionAnnounceResponse."]
        #[fail(display = "Invalid announce status in OnionAnnounceResponse")]
        InvalidAnnounceStatus,
        #[doc = "No friend with PK specified in OnionAnnounceResponse."]
        #[fail(display = "No friend with PK specified in OnionAnnounceResponse")]
        NoFriendWithPk,
        #[doc = "Invalid payload."]
        #[fail(display = "Invalid payload")]
        InvalidPayload,
        #[doc = "Send packet(s) error."]
        #[fail(display = "Send packet(s) error")]
        SendTo,
    }
}

error_kind! {
    #[doc = "Error that can happen when handling `DhtPkAnnounce` packet."]
    #[derive(Debug)]
    HandleDhtPkAnnounceError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Clone, Debug, Eq, PartialEq, failure::Fail)]
    HandleDhtPkAnnounceErrorKind {
        #[doc = "No friend with PK specified in OnionAnnounceResponse."]
        #[fail(display = "No friend with PK specified in OnionAnnounceResponse")]
        NoFriendWithPk,
        #[doc = "Invalid no_reply."]
        #[fail(display = "Invalid no_reply")]
        InvalidNoReply,
        #[doc = "Failed to ping node."]
        #[fail(display = "Failed to ping node")]
        PingNode,
        #[doc = "Failed to add TCP relay."]
        #[fail(display = "Failed to add TCP relay")]
        AddRelay,
        #[doc = "Send packet(s) error."]
        #[fail(display = "Send packet(s) error")]
        SendTo,
    }
}

error_kind! {
    #[doc = "Error that can happen when handling `OnionDataResponse` packet."]
    #[derive(Debug)]
    HandleDataResponseError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Clone, Debug, Eq, PartialEq, failure::Fail)]
    HandleDataResponseErrorKind {
        #[doc = "Invalid payload."]
        #[fail(display = "Invalid payload")]
        InvalidPayload,
        #[doc = "Invalid inner payload."]
        #[fail(display = "Invalid inner payload")]
        InvalidInnerPayload,
        #[doc = "Failed to handle DHT `PublicKey` announce."]
        #[fail(display = "Failed to handle DHT PublicKey announce")]
        DhtPkAnnounce,
        #[doc = "Failed to send a friend request."]
        #[fail(display = "Failed to send a friend request")]
        FriendRequest,
    }
}

error_kind! {
    #[doc = "Error that can happen when calling `run_*`."]
    #[derive(Debug)]
    RunError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Clone, Debug, Eq, PartialEq, failure::Fail)]
    RunErrorKind {
        #[doc = "Timer error."]
        #[fail(display = "Timer error")]
        Wakeup,
        #[doc = "Send packet(s) error."]
        #[fail(display = "Send packet(s) error")]
        SendTo,
    }
}
