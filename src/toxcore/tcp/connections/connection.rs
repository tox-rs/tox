/*! The implementation of TCP connections
*/

use toxcore::tcp::packet::*;
use toxcore::io_tokio::*;
use toxcore::crypto_core::PublicKey;

use futures::sync::mpsc;
use futures::future;

use std::io::{Error, ErrorKind};

/** A packet received from client.
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

/** Connection between server and net_crypto
*/
#[derive(Debug, Clone)]
pub struct Connection {
    /// The channel side to send packets to server
    to_server_tx: mpsc::UnboundedSender<(Packet, PublicKey)>,
    /// The channel side to send packets to net_crypto to handle them in callbacks
    callback_tx: mpsc::UnboundedSender<(IncomingPacket, PublicKey)>,
}

impl Connection {
    /** Create a new connection
        Client-side code must call this function to send the packet to server
    */
    pub fn new(to_server_tx: mpsc::UnboundedSender<(Packet, PublicKey)>,
               callback_tx: mpsc::UnboundedSender<(IncomingPacket, PublicKey)>) -> Connection {
        Connection { to_server_tx, callback_tx }
    }

    pub(super) fn handle_from_server(&self, packet: Packet, connection_id: PublicKey) -> IoFuture<()> {
        match packet {
            Packet::RouteRequest(_packet) => {
                Box::new( future::err(
                    Error::new(ErrorKind::Other,
                               "Server must not send RouteRequest to client"
                    )))
            },
            Packet::RouteResponse(packet) => {
                self.send_to_net_crypto( IncomingPacket::RouteResponse(packet), connection_id )
            },
            Packet::ConnectNotification(packet) => {
                self.send_to_net_crypto( IncomingPacket::ConnectNotification(packet), connection_id )
            },
            Packet::DisconnectNotification(packet) => {
                self.send_to_net_crypto( IncomingPacket::DisconnectNotification(packet), connection_id )
            },
            Packet::PingRequest(packet) => {
                self.send_to_server(Packet::PongResponse(
                    PongResponse { ping_id: packet.ping_id }
                ), connection_id)
            },
            Packet::PongResponse(_packet) => {
                // TODO check ping_id
                Box::new( future::ok(()) )
            },
            Packet::OobSend(_packet) => {
                Box::new( future::err(
                    Error::new(ErrorKind::Other,
                               "Server must not send OobSend to client"
                    )))
            },
            Packet::OobReceive(packet) => {
                self.send_to_net_crypto( IncomingPacket::OobReceive(packet), connection_id )
            },
            Packet::Data(packet) => {
                self.send_to_net_crypto( IncomingPacket::Data(packet), connection_id )
            },
            _ => unimplemented!() // TODO onion
        }
    }
    /** Handle packet from client
        Client-side code must call this function to send the packet to server
    */
    pub(super) fn handle_from_net_crypto(&self, packet: OutgoingPacket, connection_id: PublicKey) -> IoFuture<()> {
        match packet {
            OutgoingPacket::RouteRequest(packet) => {
                self.send_to_server( Packet::RouteRequest(packet), connection_id )
            },
            OutgoingPacket::DisconnectNotification(packet) => {
                self.send_to_server( Packet::DisconnectNotification(packet), connection_id )
            },
            OutgoingPacket::OobSend(packet) => {
                self.send_to_server( Packet::OobSend(packet), connection_id )
            },
            OutgoingPacket::Data(packet) => {
                self.send_to_server( Packet::Data(packet), connection_id )
            },
        }
    }
    /// Send packet to server
    fn send_to_server(&self, packet: Packet, connection_id: PublicKey) -> IoFuture<()> {
        send_to(&self.to_server_tx, (packet, connection_id) )
    }
    /// Send packet back to client (to be handled as a callback)
    fn send_to_net_crypto(&self, packet: IncomingPacket, connection_id: PublicKey) -> IoFuture<()> {
        send_to(&self.callback_tx, (packet, connection_id))
    }
}
