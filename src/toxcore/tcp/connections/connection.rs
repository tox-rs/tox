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
    /** Handle packet from net_crypto
        NetCrypto-side code must call this function to send the packet to server
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

#[cfg(test)]
mod tests {
    use super::*;
    use toxcore::crypto_core::*;
    use futures::prelude::*;

    fn create_connection_channels()
        -> (Connection, mpsc::UnboundedReceiver<(Packet, PublicKey)>, mpsc::UnboundedReceiver<(IncomingPacket, PublicKey)>) {
        let (server_tx, server_rx) = mpsc::unbounded();
        let (callback_tx, callback_rx) = mpsc::unbounded();
        let connection = Connection::new(server_tx, callback_tx);
        (connection.clone(), server_rx, callback_rx)
    }

    // client tests
    #[test]
    fn net_crypto_route_request() {
        let (connection, server_rx, _callback_rx) = create_connection_channels();

        let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
            192, 117, 0, 225, 119, 43, 48, 117,
            84, 109, 112, 57, 243, 216, 4, 171,
            185, 111, 33, 146, 221, 31, 77, 118]);

        let outgoing_packet = OutgoingPacket::RouteRequest(
            RouteRequest { pk: friend_pk }
        );

        let connection_id = gen_keypair().0;

        connection.handle_from_net_crypto(outgoing_packet.clone(), connection_id.clone()).wait().unwrap();

        let (incoming_packet, _tail) = server_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), (Packet::RouteRequest(RouteRequest {
            pk: friend_pk
        }), connection_id));
    }

    #[test]
    fn net_crypto_disconnect_notification() {
        let (connection, server_rx, _callback_rx) = create_connection_channels();

        let outgoing_packet = OutgoingPacket::DisconnectNotification(
            DisconnectNotification { connection_id: 42 }
        );

        let connection_id = gen_keypair().0;

        connection.handle_from_net_crypto(outgoing_packet.clone(), connection_id.clone()).wait().unwrap();

        let (incoming_packet, _tail) = server_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), (Packet::DisconnectNotification(
            DisconnectNotification { connection_id: 42 }
        ), connection_id));
    }

    #[test]
    fn net_crypto_oob_send() {
        let (connection, server_rx, _callback_rx) = create_connection_channels();

        let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
            192, 117, 0, 225, 119, 43, 48, 117,
            84, 109, 112, 57, 243, 216, 4, 171,
            185, 111, 33, 146, 221, 31, 77, 118]);

        let outgoing_packet = OutgoingPacket::OobSend(
            OobSend { destination_pk: friend_pk, data: vec![13; 42] }
        );

        let connection_id = gen_keypair().0;

        connection.handle_from_net_crypto(outgoing_packet.clone(), connection_id.clone()).wait().unwrap();

        let (incoming_packet, _tail) = server_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), (Packet::OobSend(
            OobSend { destination_pk: friend_pk, data: vec![13; 42] }
        ), connection_id));
    }

    #[test]
    fn net_crypto_data() {
        let (connection, server_rx, _callback_rx) = create_connection_channels();

        let outgoing_packet = OutgoingPacket::Data(
            Data { connection_id: 42, data: vec![13; 42] }
        );

        let connection_id = gen_keypair().0;

        connection.handle_from_net_crypto(outgoing_packet.clone(), connection_id.clone()).wait().unwrap();

        let (incoming_packet, _tail) = server_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), (Packet::Data(
            Data { connection_id: 42, data: vec![13; 42] }
        ), connection_id));
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

        let connection_id = gen_keypair().0;

        let handle_res = connection.handle_from_server(packet, connection_id).wait();
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

        let connection_id = gen_keypair().0;

        connection.handle_from_server(packet, connection_id.clone()).wait().unwrap();
        let (incoming_packet, _tail) = callback_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), (IncomingPacket::RouteResponse(
            RouteResponse { pk: friend_pk, connection_id: 42 }
        ), connection_id));
    }

    #[test]
    fn server_connect_notification() {
        let (connection, _server_rx, callback_rx) = create_connection_channels();

        let packet = Packet::ConnectNotification(
            ConnectNotification { connection_id: 42 }
        );

        let connection_id = gen_keypair().0;

        connection.handle_from_server(packet, connection_id.clone()).wait().unwrap();
        let (incoming_packet, _tail) = callback_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), (IncomingPacket::ConnectNotification(
            ConnectNotification { connection_id: 42 }
        ), connection_id));
    }

    #[test]
    fn server_disconnect_notification() {
        let (connection, _server_rx, callback_rx) = create_connection_channels();

        let packet = Packet::DisconnectNotification(
            DisconnectNotification { connection_id: 42 }
        );

        let connection_id = gen_keypair().0;

        connection.handle_from_server(packet, connection_id.clone()).wait().unwrap();
        let (incoming_packet, _tail) = callback_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), (IncomingPacket::DisconnectNotification(
            DisconnectNotification { connection_id: 42 }
        ), connection_id));
    }

    #[test]
    fn server_ping_request() {
        let (connection, server_rx, _callback_rx) = create_connection_channels();

        let packet = Packet::PingRequest(
            PingRequest { ping_id: 42 }
        );

        let connection_id = gen_keypair().0;

        connection.handle_from_server(packet, connection_id.clone()).wait().unwrap();
        let (incoming_packet, _tail) = server_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), (Packet::PongResponse(
            PongResponse { ping_id: 42 }
        ), connection_id));
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

        let connection_id = gen_keypair().0;

        let handle_res = connection.handle_from_server(packet, connection_id).wait();
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

        let connection_id = gen_keypair().0;

        connection.handle_from_server(packet, connection_id.clone()).wait().unwrap();
        let (incoming_packet, _tail) = callback_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), (IncomingPacket::OobReceive(
            OobReceive { sender_pk: friend_pk, data: vec![13; 42] }
        ), connection_id));
    }
    #[test]
    fn server_data() {
        let (connection, _server_rx, callback_rx) = create_connection_channels();

        let packet = Packet::Data(
            Data { connection_id: 42, data: vec![13; 42] }
        );

        let connection_id = gen_keypair().0;

        connection.handle_from_server(packet, connection_id.clone()).wait().unwrap();
        let (incoming_packet, _tail) = callback_rx.into_future().wait().unwrap();
        assert_eq!(incoming_packet.unwrap(), (IncomingPacket::Data(
            Data { connection_id: 42, data: vec![13; 42] }
        ), connection_id));
    }

    // test lost rx parts
    #[test]
    fn server_disconnected() {
        let (connection, server_rx, _callback_rx) = create_connection_channels();
        drop(server_rx);

        let packet = OutgoingPacket::DisconnectNotification(
            DisconnectNotification { connection_id: 42 }
        );

        let connection_id = gen_keypair().0;

        let handle_res = connection.handle_from_net_crypto(packet, connection_id).wait();
        assert!(handle_res.is_err());
    }

    #[test]
    fn net_crypto_disconnected() {
        let (connection, _server_rx, callback_rx) = create_connection_channels();
        drop(callback_rx);

        let packet = Packet::DisconnectNotification(
            DisconnectNotification { connection_id: 42 }
        );

        let connection_id = gen_keypair().0;

        let handle_res = connection.handle_from_server(packet, connection_id).wait();
        assert!(handle_res.is_err());
    }
}
