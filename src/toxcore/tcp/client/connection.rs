/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2018 Roman Proskuryakov <humbug@deeptown.org>

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

/*! The implementation of TCP Relay client connection
*/


use toxcore::tcp::packet::*;

use futures::prelude::*;
use futures::sync::mpsc;
use futures::future;

use tokio_io::IoFuture;

use std::io::{Error, ErrorKind};

/** A packet received from server.
    May be handled by user in callbacks
*/
#[derive(Debug, PartialEq, Clone)]
pub enum IncomingPacket {
    /// response to RouteRequest
    RouteResponse(RouteResponse),
    /// notification from server when both clients sent RouteRequest
    ConnectNotification(ConnectNotification),
    /// when other client was disconnected
    DisconnectNotification(DisconnectNotification),
    /// oob from other client with sender pk
    OobReceive(OobReceive),
    /// data from connected client
    Data(Data)
}

/** A packet should be sent to server.
    Used by user to send packet to server
*/
#[derive(Debug, PartialEq, Clone)]
pub enum OutgoingPacket {
    /// ask server to connect to other client
    RouteRequest(RouteRequest),
    /// force server to drop the connection by id
    DisconnectNotification(DisconnectNotification),
    /// send oob by pk
    OobSend(OobSend),
    /// send data to connected client by id
    Data(Data)
}

/** Connection between server and client
*/
#[derive(Debug, Clone)]
pub struct Connection {
    /// The channel side to send packets to server
    server_tx: mpsc::UnboundedSender<Packet>,
    /// The channel side to send packets to client to handle them in callbacks
    callback_tx: mpsc::UnboundedSender<IncomingPacket>,
}

impl Connection {
    /** Create a new connection
        Client-side code must call this function to send the packet to server
    */
    pub fn new(server_tx: mpsc::UnboundedSender<Packet>,
            callback_tx: mpsc::UnboundedSender<IncomingPacket>) -> Connection {
        Connection { server_tx, callback_tx }
    }
    pub(super) fn handle_from_server(&self, packet: Packet) -> IoFuture<()> {
        match packet {
            Packet::RouteRequest(_packet) => {
                Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "Server must not send RouteRequest to client"
                )))
            },
            Packet::RouteResponse(packet) => {
                self.send_to_client( IncomingPacket::RouteResponse(packet) )
            },
            Packet::ConnectNotification(packet) => {
                self.send_to_client( IncomingPacket::ConnectNotification(packet) )
            },
            Packet::DisconnectNotification(packet) => {
                self.send_to_client( IncomingPacket::DisconnectNotification(packet) )
            },
            Packet::OobReceive(packet) => {
                self.send_to_client( IncomingPacket::OobReceive(packet) )
            },
            Packet::OobSend(_packet) => {
                Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "Server must not send OobSend to client"
                )))
            },
            Packet::Data(packet) => {
                self.send_to_client( IncomingPacket::Data(packet) )
            },
            Packet::PingRequest(packet) => {
                self.send_to_server(Packet::PongResponse(
                    PongResponse { ping_id: packet.ping_id }
                ))
            },
            Packet::PongResponse(_packet) => {
                // TODO check ping_id
                Box::new( future::ok(()) )
            },
            _ => unimplemented!() // TODO onion
        }
    }
    /** Handle packet from client
        Client-side code must call this function to send the packet to server
    */
    pub(super) fn handle_from_client(&self, packet: OutgoingPacket) -> IoFuture<()> {
        match packet {
            OutgoingPacket::RouteRequest(packet) => {
                self.send_to_server( Packet::RouteRequest(packet) )
            },
            OutgoingPacket::DisconnectNotification(packet) => {
                self.send_to_server( Packet::DisconnectNotification(packet) )
            },
            OutgoingPacket::OobSend(packet) => {
                self.send_to_server( Packet::OobSend(packet) )
            },
            OutgoingPacket::Data(packet) => {
                self.send_to_server( Packet::Data(packet) )
            },
        }
    }
    /// Send packet to server
    pub(super) fn send_to_server(&self, packet: Packet) -> IoFuture<()> {
        Box::new(self.server_tx.clone() // clone tx sender for 1 send only
            .send(packet)
            .map(|_tx| ()) // ignore tx because it was cloned
            .map_err(|_| {
                // This may only happen if rx is gone
                // So cast SendError<T> to a corresponding std::io::Error
                Error::from(ErrorKind::UnexpectedEof)
            })
        )
    }
    /// Send packet back to client (to be handled as a callback)
    pub(super) fn send_to_client(&self, packet: IncomingPacket) -> IoFuture<()> {
        Box::new(self.callback_tx.clone() // clone tx sender for 1 send only
            .send(packet)
            .map(|_tx| ()) // ignore tx because it was cloned
            .map_err(|_| {
                // This may only happen if rx is gone
                // So cast SendError<T> to a corresponding std::io::Error
                Error::from(ErrorKind::UnexpectedEof)
            })
        )
    }
}
