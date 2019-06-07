error_kind! {
    #[doc = "Error that can happen when handling `Tcp relay` packet."]
    #[derive(Debug)]
    HandlePacketError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Clone, Debug, Eq, PartialEq, failure::Fail)]
    HandlePacketErrorKind {
        #[doc = "Send packet(s) error."]
        #[fail(display = "Send packet(s) error")]
        SendTo,
        #[doc = "Server must not send this packet to client."]
        #[fail(display = "Server must not send this packet to client")]
        MustNotSend,
        #[doc = "Invalid connection ID when handling RouteResponse."]
        #[fail(display = "Invalid connection ID when handling RouteResponse")]
        InvalidConnectionId,
        #[doc = "Connection ID is already linked."]
        #[fail(display = "Connection ID is already linked")]
        AlreadyLinked,
        #[doc = "Unexpected route response packet is received."]
        #[fail(display = "Unexpected route response packet is received")]
        UnexpectedRouteResponse,
  }
}

error_kind! {
    #[doc = "Error that can happen when sending packet."]
    #[derive(Debug)]
    SendPacketError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Clone, Debug, Eq, PartialEq, failure::Fail)]
    SendPacketErrorKind {
        #[doc = "Send packet(s) error."]
        #[fail(display = "Send packet(s) error")]
        SendTo,
        #[doc = "Send packet(s) with wrong status."]
        #[fail(display = "Send packet(s) with wrong status")]
        WrongStatus,
        #[doc = "Send packet(s) with destination_pk is not online."]
        #[fail(display = "Send packet(s) with destination_pk is not online")]
        NotOnline,
        #[doc = "Send packet(s) with destination_pk is not linked."]
        #[fail(display = "Send packet(s) with destination_pk is not linked")]
        NotLinked,
        #[doc = "Send packet(s) to a connection but no such connection."]
        #[fail(display = "Send packet(s) to a connection but no such connection")]
        NoSuchConnection,
    }
}

error_kind! {
    #[doc = "Error that can happen when spawning a connection."]
    #[derive(Debug)]
    SpawnError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Clone, Debug, Eq, PartialEq, failure::Fail)]
    SpawnErrorKind {
        #[doc = "Read socket to receive packet error."]
        #[fail(display = "Read socket to receive packet error")]
        ReadSocket,
        #[doc = "Send packet(s) error."]
        #[fail(display = "Send packet(s) error")]
        SendTo,
        #[doc = "Handle packet(s) error."]
        #[fail(display = "Handle packet(s) error")]
        HandlePacket,
        #[doc = "Tcp client io error."]
        #[fail(display = "Tcp client io error")]
        Io,
        #[doc = "Tcp codec encode error."]
        #[fail(display = "Tcp codec encode error")]
        Encode,
    }
}

error_kind! {
    #[doc = "Error that can happen when handling a connection."]
    #[derive(Debug)]
    ConnectionError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Clone, Debug, Eq, PartialEq, failure::Fail)]
    ConnectionErrorKind {
        #[doc = "Spawing after adding global connection error."]
        #[fail(display = "Spawing after adding global connection error")]
        Spawn,
        #[doc = "Search relay by relay's PK, but no such relay."]
        #[fail(display = "Search relay by relay's PK, but no such relay")]
        NoSuchRelay,
        #[doc = "Send packet(s) error."]
        #[fail(display = "Send packet(s) error")]
        SendTo,
        #[doc = "No connection to the node."]
        #[fail(display = "No connection to the node")]
        NoConnection,
        #[doc = "Relay is not connected."]
        #[fail(display = "Relay is not connected")]
        NotConnected,
        #[doc = "Tcp Connections wakeup timer error."]
        #[fail(display = "Tcp Connections wakeup timer error")]
        Wakeup,
        #[doc = "Add connection to client error."]
        #[fail(display = "Add connection to client error")]
        AddConnection,
    }
}
