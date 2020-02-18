/*!
Module for errors of NetCrypto.
*/

use std::net::SocketAddr;

use failure::Fail;

use tox_crypto::*;

error_kind! {
    #[doc = "Error that can happen while processing packets array"]
    #[derive(Debug)]
    PacketsArrayError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Debug, Eq, PartialEq, Fail)]
    PacketsArrayErrorKind {
        #[doc = "Index is too big error."]
        #[fail(display = "The index {:?} is too big and can't be hold", index)]
        TooBig {
            #[doc = "The index that can't be hold."]
            index: u32,
        },
        #[doc = "Index already exists error."]
        #[fail(display = "The packet with index {:?} already exists", index)]
        AlreadyExist {
            #[doc = "The index that already exists."]
            index: u32,
        },
        #[doc = "Packets array is full."]
        #[fail(display = "Packets array is full")]
        ArrayFull,
        #[doc = "Index is lower than the end index."]
        #[fail(display = "Index {:?} is lower than the end index", index)]
        LowerIndex {
            #[doc = "The index that lower than end index."]
            index: u32,
        },
        #[doc = "Index is outside of buffer bounds."]
        #[fail(display = "Index {:?} is outside of buffer bounds", index)]
        OutsideIndex {
            #[doc = "The index that is outside of buffer bounds."]
            index: u32,
        },
    }
}

impl PacketsArrayError {
    pub(crate) fn too_big(index: u32) -> PacketsArrayError {
        PacketsArrayError::from(PacketsArrayErrorKind::TooBig { index })
    }

    pub(crate) fn already_exist(index: u32) -> PacketsArrayError {
        PacketsArrayError::from(PacketsArrayErrorKind::AlreadyExist { index })
    }

    pub(crate) fn lower_index(index: u32) -> PacketsArrayError {
        PacketsArrayError::from(PacketsArrayErrorKind::LowerIndex { index })
    }

    pub(crate) fn outside_index(index: u32) -> PacketsArrayError {
        PacketsArrayError::from(PacketsArrayErrorKind::OutsideIndex { index })
    }
}

error_kind! {
    #[doc = "Error that can happen when calling `handle_*` of packet."]
    #[derive(Debug)]
    HandlePacketError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Debug, Eq, PartialEq, Fail)]
    HandlePacketErrorKind {
        #[doc = "Error indicates that getting payload of received packet error."]
        #[fail(display = "Get payload of received packet error")]
        GetPayload,
        #[doc = "Error indicates that sending response packet error."]
        #[fail(display = "Sending response error")]
        SendTo,
        #[doc = "Error indicates that sending lossless response packet error."]
        #[fail(display = "Sending lossless response error")]
        SendToLossless,
        #[doc = "Error indicates that sending lossy response packet error."]
        #[fail(display = "Sending lossy response error")]
        SendToLossy,
        #[doc = "Error indicates that sending dhtpk packet error."]
        #[fail(display = "Sending dhtpk packet error")]
        SendToDhtpk,
        #[doc = "Error indicates that sending connection status error."]
        #[fail(display = "Sending connection status error")]
        SendToConnectionStatus,
        #[doc = "Error indicates that NetCrypto can't handle packet in current connection state."]
        #[fail(display = "Can't handle CookieResponse in current connection state")]
        InvalidState,
        #[doc = "Error indicates that NetCrypto can't handle crypto data packet in current connection state."]
        #[fail(display = "Can't handle CryptoData in current connection state")]
        CannotHandleCryptoData,
        #[doc = "Error indicates that invalid cookie request id."]
        #[fail(display = "Invalid cookie request id: expected {:?} but got {:?}", expect, got)]
        InvalidRequestId {
            #[doc = "Expected request id."]
            expect: u64,
            #[doc = "Gotten request id."]
            got: u64,
        },
        #[doc = "Error indicates that no crypto connection for address."]
        #[fail(display = "No crypto connection for address: {:?}", addr)]
        NoUdpConnection {
            #[doc = "The address for connection which don't exist."]
            addr: SocketAddr,
        },
        #[doc = "Error indicates that no crypto connection for address."]
        #[fail(display = "No crypto connection for DHT key: {:?}", pk)]
        NoTcpConnection {
            #[doc = "The DHT key for connection which don't exist."]
            pk: PublicKey,
        },
        #[doc = "Unexpected crypto handshake."]
        #[fail(display = "Unexpected crypto handshake")]
        UnexpectedCryptoHandshake,
        #[doc = "Error indicates that invalid SHA512 hash of cookie."]
        #[fail(display = "Invalid SHA512 hash of cookie")]
        BadSha512,
        #[doc = "Error indicates that cookie is timed out."]
        #[fail(display = "Cookie is timed out")]
        CookieTimedOut,
        #[doc = "Error indicates that cookie contains invalid real pk."]
        #[fail(display = "Cookie contains invalid real pk")]
        InvalidRealPk,
        #[doc = "Error indicates that cookie contains invalid dht pk."]
        #[fail(display = "Cookie contains invalid dht pk")]
        InvalidDhtPk,
        #[doc = "Error indicates that there is PacketsArrayError."]
        #[fail(display = "PacketsArrayError occurs")]
        PacketsArrayError,
        #[doc = "Error indicates that real data is empty."]
        #[fail(display = "Real data is empty")]
        DataEmpty,
        #[doc = "Error indicates that invalid packet id."]
        #[fail(display = "Invalid packet id: {:?}", id)]
        PacketId {
            #[doc = "The packet id that is invalid."]
            id: u8,
        },
    }
}

impl HandlePacketError {
    pub(crate) fn invalid_request_id(expect: u64, got: u64) -> HandlePacketError {
        HandlePacketError::from(HandlePacketErrorKind::InvalidRequestId {
            expect,
            got,
        })
    }

    pub(crate) fn no_udp_connection(addr: SocketAddr) -> HandlePacketError {
        HandlePacketError::from(HandlePacketErrorKind::NoUdpConnection {
            addr,
        })
    }

    pub(crate) fn no_tcp_connection(pk: PublicKey) -> HandlePacketError {
        HandlePacketError::from(HandlePacketErrorKind::NoTcpConnection {
            pk,
        })
    }

    pub(crate) fn packet_id(id: u8) -> HandlePacketError {
        HandlePacketError::from(HandlePacketErrorKind::PacketId {
            id,
        })
    }
}

error_kind! {
    #[doc = "Error that can happen while processing packets array."]
    #[derive(Debug)]
    SendDataError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Debug, Eq, PartialEq, Fail)]
    SendDataErrorKind {
        #[doc = "Connection is not established."]
        #[fail(display = "Connection is not established")]
        NoConnection,
        #[doc = "Error indicates that sending response packet error."]
        #[fail(display = "Sending response error")]
        SendTo,
        #[doc = "Error indicates that sending connection status error."]
        #[fail(display = "Sending connection status error")]
        SendToConnectionStatus,
    }
}

error_kind! {
    #[doc = "Error that can happen when calling `run`."]
    #[derive(Debug)]
    RunError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Clone, Debug, Eq, PartialEq, Fail)]
    RunErrorKind {
        #[doc = "Sending pings error."]
        #[fail(display = "Sending crypto data packet error")]
        SendData,
        #[doc = "NetCrypto periodical wakeup timer error."]
        #[fail(display = "Netcrypto periodical wakeup timer error")]
        Wakeup,
    }
}

error_kind! {
    #[doc = "Error that can happen during a lossless packet sending."]
    #[derive(Debug)]
    SendLosslessPacketError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Debug, Eq, PartialEq, Fail)]
    SendLosslessPacketErrorKind {
        #[doc = "Packet ID is outside lossless packets range."]
        #[fail(display = "Packet ID is outside lossless packets range")]
        InvalidPacketId,
        #[doc = "Connection to a friend is not established."]
        #[fail(display = "Connection to a friend is not established")]
        NoConnection,
        #[doc = "Packets send array is full."]
        #[fail(display = "Packets send array is full")]
        FullSendArray,
        #[doc = "Failed to send packet."]
        #[fail(display = "Failed to send packet")]
        SendTo,
    }
}

error_kind! {
    #[doc = "Error that can happen during a lossless packet sending."]
    #[derive(Debug)]
    KillConnectionError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Debug, Eq, PartialEq, Fail)]
    KillConnectionErrorKind {
        #[doc = "Connection to a friend is not established."]
        #[fail(display = "Connection to a friend is not established")]
        NoConnection,
        #[doc = "Failed to send kill packet."]
        #[fail(display = "Failed to send kill packet")]
        SendTo,
        #[doc = "Error indicates that sending connection status error."]
        #[fail(display = "Sending connection status error")]
        SendToConnectionStatus,
    }
}

error_kind! {
    #[doc = "Error that can happen during a packet sending."]
    #[derive(Debug)]
    SendPacketError,
    #[doc = "The specific kind of error that can occur."]
    #[derive(Debug, Eq, PartialEq, Fail)]
    SendPacketErrorKind {
        #[doc = "Failed to send TCP packet."]
        #[fail(display = "Failed to send TCP packet")]
        Tcp,
        #[doc = "Failed to send UDP packet."]
        #[fail(display = "Failed to send UDP packet")]
        Udp,
    }
}
