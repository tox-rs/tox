/*! The implementation of TCP Relay client connection
*/

use toxcore::tcp::packet::*;
use toxcore::io_tokio::*;

use futures::sync::mpsc;
use futures::future;

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
            Packet::PingRequest(packet) => {
                self.send_to_server(Packet::PongResponse(
                    PongResponse { ping_id: packet.ping_id }
                ))
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
                self.send_to_client( IncomingPacket::OobReceive(packet) )
            },
            Packet::Data(packet) => {
                self.send_to_client( IncomingPacket::Data(packet) )
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
    fn send_to_server(&self, packet: Packet) -> IoFuture<()> {
        send_to(&self.server_tx, packet)
    }
    /// Send packet back to client (to be handled as a callback)
    fn send_to_client(&self, packet: IncomingPacket) -> IoFuture<()> {
        send_to(&self.callback_tx, packet)
    }
}

#[cfg(test)]
mod tests {
    use toxcore::crypto_core::*;
    use toxcore::tcp::client::connection::*;
    use futures::prelude::*;
    use futures::sync::mpsc;

    fn create_connection_channels()
        -> (Connection, mpsc::UnboundedReceiver<Packet>, mpsc::UnboundedReceiver<IncomingPacket>) {
        let (server_tx, server_rx) = mpsc::unbounded();
        let (callback_tx, callback_rx) = mpsc::unbounded();
        let connection = Connection::new(server_tx, callback_tx);
        (connection.clone(), server_rx, callback_rx)
    }

    // client tests
    #[test]
    fn client_route_request() {
        let (connection, server_rx, _callback_rx) = create_connection_channels();

        let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
                                192, 117, 0, 225, 119, 43, 48, 117,
                                84, 109, 112, 57, 243, 216, 4, 171,
                                185, 111, 33, 146, 221, 31, 77, 118]);

        let outgoing_packet = OutgoingPacket::RouteRequest(
            RouteRequest { pk: friend_pk }
        );
        connection.handle_from_client(outgoing_packet.clone()).wait().unwrap();

        let (incoming_packet, _tail) = server_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), Packet::RouteRequest(RouteRequest {
            pk: friend_pk
        }));
    }
    #[test]
    fn client_disconnect_notification() {
        let (connection, server_rx, _callback_rx) = create_connection_channels();

        let outgoing_packet = OutgoingPacket::DisconnectNotification(
            DisconnectNotification { connection_id: 42 }
        );
        connection.handle_from_client(outgoing_packet.clone()).wait().unwrap();

        let (incoming_packet, _tail) = server_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), Packet::DisconnectNotification(
            DisconnectNotification { connection_id: 42 }
        ));
    }
    #[test]
    fn client_oob_send() {
        let (connection, server_rx, _callback_rx) = create_connection_channels();

        let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
                                192, 117, 0, 225, 119, 43, 48, 117,
                                84, 109, 112, 57, 243, 216, 4, 171,
                                185, 111, 33, 146, 221, 31, 77, 118]);

        let outgoing_packet = OutgoingPacket::OobSend(
            OobSend { destination_pk: friend_pk, data: vec![13; 42] }
        );
        connection.handle_from_client(outgoing_packet.clone()).wait().unwrap();

        let (incoming_packet, _tail) = server_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), Packet::OobSend(
            OobSend { destination_pk: friend_pk, data: vec![13; 42] }
        ));
    }
    #[test]
    fn client_data() {
        let (connection, server_rx, _callback_rx) = create_connection_channels();

        let outgoing_packet = OutgoingPacket::Data(
            Data { connection_id: 42, data: vec![13; 42] }
        );
        connection.handle_from_client(outgoing_packet.clone()).wait().unwrap();

        let (incoming_packet, _tail) = server_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), Packet::Data(
            Data { connection_id: 42, data: vec![13; 42] }
        ));
    }

    // server tests
    #[test]
    fn server_route_request() {
        let (connection, _server_rx, _callback_rx) = create_connection_channels();

        let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
                                192, 117, 0, 225, 119, 43, 48, 117,
                                84, 109, 112, 57, 243, 216, 4, 171,
                                185, 111, 33, 146, 221, 31, 77, 118]);

        let packet = Packet::RouteRequest(
            RouteRequest { pk: friend_pk }
        );
        let handle_res = connection.handle_from_server(packet).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn server_route_response() {
        let (connection, _server_rx, callback_rx) = create_connection_channels();

        let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
                                192, 117, 0, 225, 119, 43, 48, 117,
                                84, 109, 112, 57, 243, 216, 4, 171,
                                185, 111, 33, 146, 221, 31, 77, 118]);

        let packet = Packet::RouteResponse(
            RouteResponse { pk: friend_pk, connection_id: 42 }
        );
        connection.handle_from_server(packet).wait().unwrap();
        let (incoming_packet, _tail) = callback_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), IncomingPacket::RouteResponse(
            RouteResponse { pk: friend_pk, connection_id: 42 }
        ));
    }
    #[test]
    fn server_connect_notification() {
        let (connection, _server_rx, callback_rx) = create_connection_channels();

        let packet = Packet::ConnectNotification(
            ConnectNotification { connection_id: 42 }
        );
        connection.handle_from_server(packet).wait().unwrap();
        let (incoming_packet, _tail) = callback_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), IncomingPacket::ConnectNotification(
            ConnectNotification { connection_id: 42 }
        ));
    }
    #[test]
    fn server_disconnect_notification() {
        let (connection, _server_rx, callback_rx) = create_connection_channels();

        let packet = Packet::DisconnectNotification(
            DisconnectNotification { connection_id: 42 }
        );
        connection.handle_from_server(packet).wait().unwrap();
        let (incoming_packet, _tail) = callback_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), IncomingPacket::DisconnectNotification(
            DisconnectNotification { connection_id: 42 }
        ));
    }
    #[test]
    fn server_ping_request() {
        let (connection, server_rx, _callback_rx) = create_connection_channels();

        let packet = Packet::PingRequest(
            PingRequest { ping_id: 42 }
        );
        connection.handle_from_server(packet).wait().unwrap();
        let (incoming_packet, _tail) = server_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), Packet::PongResponse(
            PongResponse { ping_id: 42 }
        ));
    }
    #[test]
    fn server_oob_send() {
        let (connection, _server_rx, _callback_rx) = create_connection_channels();

        let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
                                192, 117, 0, 225, 119, 43, 48, 117,
                                84, 109, 112, 57, 243, 216, 4, 171,
                                185, 111, 33, 146, 221, 31, 77, 118]);

        let packet = Packet::OobSend(
            OobSend { destination_pk: friend_pk, data: vec![13; 42] }
        );
        let handle_res = connection.handle_from_server(packet).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn server_oob_receive() {
        let (connection, _server_rx, callback_rx) = create_connection_channels();

        let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
                                192, 117, 0, 225, 119, 43, 48, 117,
                                84, 109, 112, 57, 243, 216, 4, 171,
                                185, 111, 33, 146, 221, 31, 77, 118]);

        let packet = Packet::OobReceive(
            OobReceive { sender_pk: friend_pk, data: vec![13; 42] }
        );
        connection.handle_from_server(packet).wait().unwrap();
        let (incoming_packet, _tail) = callback_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), IncomingPacket::OobReceive(
            OobReceive { sender_pk: friend_pk, data: vec![13; 42] }
        ));
    }
    #[test]
    fn server_data() {
        let (connection, _server_rx, callback_rx) = create_connection_channels();

        let packet = Packet::Data(
            Data { connection_id: 42, data: vec![13; 42] }
        );
        connection.handle_from_server(packet).wait().unwrap();
        let (incoming_packet, _tail) = callback_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), IncomingPacket::Data(
            Data { connection_id: 42, data: vec![13; 42] }
        ));
    }

    // test lost rx parts
    #[test]
    fn server_disconnected() {
        let (connection, server_rx, _callback_rx) = create_connection_channels();
        drop(server_rx);

        let packet = OutgoingPacket::DisconnectNotification(
            DisconnectNotification { connection_id: 42 }
        );
        let handle_res = connection.handle_from_client(packet).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn client_disconnected() {
        let (connection, _server_rx, callback_rx) = create_connection_channels();
        drop(callback_rx);

        let packet = Packet::DisconnectNotification(
            DisconnectNotification { connection_id: 42 }
        );
        let handle_res = connection.handle_from_server(packet).wait();
        assert!(handle_res.is_err());
    }
}
