/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2017 Roman Proskuryakov <humbug@deeptown.org>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

/*! Top-level TCP Packets according
    to https://zetok.github.io/tox-spec/#encrypted-payload-types
*/

use toxcore::crypto_core::*;
use toxcore::tcp::binary_io::*;

use nom::{be_u8, be_u16, be_u64, rest};

/** Top-level TCP packet.

    According to https://zetok.github.io/tox-spec/#encrypted-payload-types.
*/
#[derive(Debug, PartialEq, Clone)]
pub enum Packet {
    /// [`RouteRequest`](./struct.RouteRequest.html) structure.
    RouteRequest(RouteRequest),
    /// [`RouteResponse`](./struct.RouteResponse.html) structure.
    RouteResponse(RouteResponse),
    /// [`ConnectNotification`](./struct.ConnectNotification.html) structure.
    ConnectNotification(ConnectNotification),
    /// [`DisconnectNotification`](./struct.DisconnectNotification.html) structure.
    DisconnectNotification(DisconnectNotification),
    /// [`PingRequest`](./struct.PingRequest.html) structure.
    PingRequest(PingRequest),
    /// [`PongResponse`](./struct.PongResponse.html) structure.
    PongResponse(PongResponse),
    /// [`OobSend`](./struct.OobSend.html) structure.
    OobSend(OobSend),
    /// [`OobReceive`](./struct.OobReceive.html) structure.
    OobReceive(OobReceive),
    /// TODO
    //OnionDataRequest,
    /// TODO
    //OnionDataResponse,
    /// [`Data`](./struct.Data.html) structure.
    Data(Data)
}

/// A serialized Packet should be not longer than 2032 bytes
pub const MAX_TCP_PACKET_SIZE: usize = 2032;

impl FromBytes for Packet {
    named!(from_bytes<Packet>, alt!(
        map!(RouteRequest::from_bytes, Packet::RouteRequest) |
        map!(RouteResponse::from_bytes, Packet::RouteResponse) |
        map!(ConnectNotification::from_bytes, Packet::ConnectNotification) |
        map!(DisconnectNotification::from_bytes, Packet::DisconnectNotification) |
        map!(PingRequest::from_bytes, Packet::PingRequest) |
        map!(PongResponse::from_bytes, Packet::PongResponse) |
        map!(OobSend::from_bytes, Packet::OobSend) |
        map!(OobReceive::from_bytes, Packet::OobReceive) |
        map!(Data::from_bytes, Packet::Data)
    ));
}

impl ToBytes for Packet {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            Packet::RouteRequest(ref p) => p.to_bytes(buf),
            Packet::RouteResponse(ref p) => p.to_bytes(buf),
            Packet::ConnectNotification(ref p) => p.to_bytes(buf),
            Packet::DisconnectNotification(ref p) => p.to_bytes(buf),
            Packet::PingRequest(ref p) => p.to_bytes(buf),
            Packet::PongResponse(ref p) => p.to_bytes(buf),
            Packet::OobSend(ref p) => p.to_bytes(buf),
            Packet::OobReceive(ref p) => p.to_bytes(buf),
            Packet::Data(ref p) => p.to_bytes(buf),
        }
    }
}

/** Packets are encrypted and sent in this form.

Serialized form:

Length     | Content
---------- | ------
`2`        | Length of encrypted payload in BigEndian
variable   | Encrypted payload

*/
pub struct EncryptedPacket {
    /// Encrypted payload
    pub payload: Vec<u8>
}

/// A serialized EncryptedPacket should be not longer than 2050 bytes
pub const MAX_TCP_ENC_PACKET_SIZE: usize = 2050;

impl FromBytes for EncryptedPacket {
    named!(from_bytes<EncryptedPacket>, do_parse!(
        length: be_u16 >>
        verify!(value!(length), |len| len > 0 /* TODO len < 2048... ? */ ) >>
        payload: take!(length) >>
        (EncryptedPacket { payload: payload.to_vec() })
    ));
}

impl ToBytes for EncryptedPacket {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u16!(self.payload.len()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

/** Sent by client to server.
Send a routing request to the server that we want to connect
to peer with public key where the public key is the public the peer
announced themselves as. The server must respond to this with a `RouteResponse`.

Packet type [`Kind::RouteRequest`](./enum.Kind.html).

Serialized form:

Length | Content
------ | ------
`1`    | 0x00
`32`   | DHT Public Key

*/
#[derive(Debug, PartialEq, Clone)]
pub struct RouteRequest {
    /// The requested PK
    pub pk: PublicKey,
}

impl FromBytes for RouteRequest {
    named!(from_bytes<RouteRequest>, do_parse!(
        tag!("\x00") >>
        pk: call!(PublicKey::from_bytes) >>
        (RouteRequest { pk: pk })
    ));
}

impl ToBytes for RouteRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x00) >>
            gen_slice!(self.pk.as_ref())
        )
    }
}

/** Sent by server to client.
The response to the routing request, tell the client if the
routing request succeeded (valid `connection_id`) and if it did,
tell them the id of the connection (`connection_id`). The public
key sent in the routing request is also sent in the response so
that the client can send many requests at the same time to the
server without having code to track which response belongs to which public key.

Packet type [`Kind::RouteResponse`](./enum.Kind.html).

Serialized form:

Length | Content
------ | ------
`1`    | 0x01
`1`    | connection_id
`32`   | DHT Public Key

*/
#[derive(Debug, PartialEq, Clone)]
pub struct RouteResponse {
    /// The id of the requested PK
    pub connection_id: u8,
    /// The requested PK
    pub pk: PublicKey,
}

impl FromBytes for RouteResponse {
    named!(from_bytes<RouteResponse>, do_parse!(
        tag!("\x01") >>
        connection_id: be_u8 >>
        pk: call!(PublicKey::from_bytes) >>
        (RouteResponse { connection_id: connection_id, pk: pk })
    ));
}

impl ToBytes for RouteResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x01) >>
            gen_be_u8!(self.connection_id) >>
            gen_slice!(self.pk.as_ref())
        )
    }
}

/** Sent by server to client.
Tell the client that connection_id is now connected meaning the other
is online and data can be sent using this `connection_id`.

Packet type [`Kind::ConnectNotification`](./enum.Kind.html).

Serialized form:

Length | Content
------ | ------
`1`    | 0x02
`1`    | connection_id

*/
#[derive(Debug, PartialEq, Clone)]
pub struct ConnectNotification {
    /// The id of the connected client
    pub connection_id: u8
}

impl FromBytes for ConnectNotification {
    named!(from_bytes<ConnectNotification>, do_parse!(
        tag!("\x02") >>
        connection_id: be_u8 >>
        (ConnectNotification { connection_id: connection_id })
    ));
}

impl ToBytes for ConnectNotification {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x02) >>
            gen_be_u8!(self.connection_id)
        )
    }
}

/** Sent by client to server.
Sent when client wants the server to forget about the connection related
to the connection_id in the notification. Server must remove this connection
and must be able to reuse the `connection_id` for another connection. If the
connection was connected the server must send a disconnect notification to the
other client. The other client must think that this client has simply
disconnected from the TCP server.

Sent by server to client.
Sent by the server to the client to tell them that the connection with
`connection_id` that was connected is now disconnected. It is sent either
when the other client of the connection disconnect or when they tell the
server to kill the connection (see above).

Packet type [`Kind::DisconnectNotification`](./enum.Kind.html).

Serialized form:

Length | Content
------ | ------
`1`    | 0x03
`1`    | connection_id

*/
#[derive(Debug, PartialEq, Clone)]
pub struct DisconnectNotification {
    /// The id of the disconnected client
    pub connection_id: u8
}

impl FromBytes for DisconnectNotification {
    named!(from_bytes<DisconnectNotification>, do_parse!(
        tag!("\x03") >>
        connection_id: be_u8 >>
        (DisconnectNotification { connection_id: connection_id })
    ));
}

impl ToBytes for DisconnectNotification {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x03) >>
            gen_be_u8!(self.connection_id)
        )
    }
}

/** Sent by both client and server, both will respond.
Ping packets are used to know if the other side of the connection is still
live. TCP when established doesn't have any sane timeouts (1 week isn't sane)
so we are obliged to have our own way to check if the other side is still live.
Ping ids can be anything except 0, this is because of how toxcore sets the
variable storing the `ping_id` that was sent to 0 when it receives a pong
response which means 0 is invalid.

The server should send ping packets every X seconds (toxcore `TCP_server` sends
them every 30 seconds and times out the peer if it doesn't get a response in 10).
The server should respond immediately to ping packets with pong packets.


Packet type [`Kind::PingRequest`](./enum.Kind.html).

Serialized form:

Length | Content
------ | ------
`1`    | 0x04
`8`    | ping_id in BigEndian

*/
#[derive(Debug, PartialEq, Clone)]
pub struct PingRequest {
    /// The id of ping
    pub ping_id: u64
}

impl FromBytes for PingRequest {
    named!(from_bytes<PingRequest>, do_parse!(
        tag!("\x04") >>
        ping_id: be_u64 >>
        (PingRequest { ping_id: ping_id })
    ));
}

impl ToBytes for PingRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x04) >>
            gen_be_u64!(self.ping_id)
        )
    }
}

/** Sent by both client and server, both will respond.
The server should respond to ping packets with pong packets with the same `ping_id`
as was in the ping packet. The server should check that each pong packet contains
the same `ping_id` as was in the ping, if not the pong packet must be ignored.

Packet type [`Kind::PongResponse`](./enum.Kind.html).

Serialized form:

Length | Content
------ | ------
`1`    | 0x05
`8`    | ping_id in BigEndian

*/
#[derive(Debug, PartialEq, Clone)]
pub struct PongResponse {
    /// The id of ping to respond
    pub ping_id: u64
}

impl FromBytes for PongResponse {
    named!(from_bytes<PongResponse>, do_parse!(
        tag!("\x05") >>
        ping_id: be_u64 >>
        (PongResponse { ping_id: ping_id })
    ));
}

impl ToBytes for PongResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x05) >>
            gen_be_u64!(self.ping_id)
        )
    }
}

/** Sent by client to server.
If a peer with private key equal to the key they announced themselves with is
connected, the data in the OOB send packet will be sent to that peer as an
OOB recv packet. If no such peer is connected, the packet is discarded. The
toxcore `TCP_server` implementation has a hard maximum OOB data length of 1024.
1024 was picked because it is big enough for the `net_crypto` packets related
to the handshake and is large enough that any changes to the protocol would not
require breaking `TCP server`. It is however not large enough for the bigges
`net_crypto` packets sent with an established `net_crypto` connection to
prevent sending those via OOB packets.

OOB packets can be used just like normal data packets however the extra size
makes sending data only through them less efficient than data packets.

Packet type [`Kind::OobSend`](./enum.Kind.html).

Serialized form:

Length   | Content
-------- | ------
`1`      | 0x06
`32`     | DHT Public Key
variable | Data

*/
#[derive(Debug, PartialEq, Clone)]
pub struct OobSend {
    /// Public Key of the receiver
    pub destination_pk: PublicKey,
    /// OOB data packet
    pub data: Vec<u8>
}

impl FromBytes for OobSend {
    named!(from_bytes<OobSend>, do_parse!(
        tag!("\x06") >>
        destination_pk: call!(PublicKey::from_bytes) >>
        data: rest >>
        (OobSend { destination_pk: destination_pk, data: data.to_vec() })
    ));
}

impl ToBytes for OobSend {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x06) >>
            gen_slice!(self.destination_pk.as_ref()) >>
            gen_slice!(self.data)
        )
    }
}

/** Sent by server to client.
OOB recv are sent with the announced public key of the peer that sent the
OOB send packet and the exact data.

Packet type [`Kind::OobSend`](./enum.Kind.html).

Serialized form:

Length   | Content
-------- | ------
`1`      | 0x07
`32`     | DHT Public Key
variable | Data

*/
#[derive(Debug, PartialEq, Clone)]
pub struct OobReceive {
    /// Public Key of the sender
    pub sender_pk: PublicKey,
    /// OOB data packet
    pub data: Vec<u8>
}

impl FromBytes for OobReceive {
    named!(from_bytes<OobReceive>, do_parse!(
        tag!("\x07") >>
        sender_pk: call!(PublicKey::from_bytes) >>
        data: rest >>
        (OobReceive { sender_pk: sender_pk, data: data.to_vec() })
    ));
}

impl ToBytes for OobReceive {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x07) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.data)
        )
    }
}

/** Sent by client to server.
The client sends data with `connection_id` and the server
relays it to the given connection

Packet type [`Kind::Data`](./enum.Kind.html).

Serialized form:

Length   | Content
-------- | ------
`1`      | connection_id [ 0x10 .. 0xF0 )
variable | Data

*/
#[derive(Debug, PartialEq, Clone)]
pub struct Data {
    /// The id of the connection of the client
    pub connection_id: u8,
    /// Data packet
    pub data: Vec<u8>
}

impl FromBytes for Data {
    named!(from_bytes<Data>, do_parse!(
        connection_id: be_u8 >>
        verify!(value!(connection_id), |id| id >= 0x10 && id < 0xF0) >>
        data: rest >>
        (Data { connection_id: connection_id, data: data.to_vec() })
    ));
}

impl ToBytes for Data {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(self.connection_id) >>
            gen_slice!(self.data)
        )
    }
}
