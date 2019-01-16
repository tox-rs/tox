use std::collections::HashSet;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use failure::Fail;
use futures::{future, Future, Stream};
use futures::future::Either;
use futures::sync::mpsc;
use parking_lot::RwLock;
use tokio_codec::Framed;
use tokio;
use tokio::net::TcpStream;

use crate::toxcore::crypto_core::*;
use crate::toxcore::io_tokio::*;
use crate::toxcore::onion::packet::InnerOnionResponse;
use crate::toxcore::stats::Stats;
use crate::toxcore::tcp::codec::{Codec, EncodeError};
use crate::toxcore::tcp::connection_id::ConnectionId;
use crate::toxcore::tcp::handshake::make_client_handshake;
use crate::toxcore::tcp::links::*;
use crate::toxcore::tcp::packet::*;
use crate::toxcore::time::*;

/// Buffer size (in packets) for outgoing packets. This number shouldn't be high
/// to minimize latency. If some relay can't take more packets we can use
/// another relay. So it doesn't make much sense to buffer packets and wait for
/// the relay to send them.
const CLIENT_CHANNEL_SIZE: usize = 2;

/// Packet that can be received from a TCP relay and should be handled outside
/// of connections module.
#[derive(Debug, PartialEq, Clone)]
pub enum IncomingPacket {
    /// Data packet with sender's `PublicKey`.
    Data(PublicKey, Vec<u8>),
    /// Oob packet with sender's `PublicKey`.
    Oob(PublicKey, Vec<u8>),
    /// Onion response packet.
    Onion(InnerOnionResponse),
}

/// TCP relay connection status.
#[derive(Debug, Clone)]
enum ClientStatus {
    /// In this status we are not connected to the relay. This is initial
    /// status. Also we can end up in this status if connection was lost due to
    /// errors.
    Disconnected,
    /// This status means that we are trying to connect to the relay i.e.
    /// establish TCP connection and make a handshake.
    Connecting,
    /// In this status we have established connection to the relay. Note that
    /// when the inner sender is dropped the connection to the relay will be
    /// closed. Also this means that the sender object should not be copied
    /// anywhere else unless you want to keep the connection.
    Connected(mpsc::Sender<Packet>),
    /// This status means that we are not connected to the relay but can
    /// reconnect later. Connection becomes sleeping when all friends that might
    /// use it are connected directly via UDP.
    Sleeping,
}

/// Client connection to a TCP relay.
#[derive(Clone)]
pub struct Client {
    /// `PublicKey` of the TCP relay.
    pub pk: PublicKey,
    /// IP address of the TCP relay.
    pub addr: SocketAddr,
    /// Sink for packets that should be handled somewhere else. `PublicKey` here
    /// belongs to TCP relay.
    incoming_tx: mpsc::UnboundedSender<(PublicKey, IncomingPacket)>,
    /// Status of the relay.
    status: Arc<RwLock<ClientStatus>>,
    /// Time when a connection to the relay was established.
    connected_time: Arc<RwLock<Option<Instant>>>,
    /// Number of unsuccessful attempts to establish connection to the relay.
    /// This is used to decide what to do after the connection terminates.
    connection_attempts: Arc<RwLock<u32>>,
    links: Arc<RwLock<Links>>,
    /// List of nodes we want to be connected to. When the connection to the
    /// relay establishes we send `RouteRequest` packets with these `PublicKey`s.
    connections: Arc<RwLock<HashSet<PublicKey>>>,
}

impl Client {
    /// Create new `Client` object.
    pub fn new(pk: PublicKey, addr: SocketAddr, incoming_tx: mpsc::UnboundedSender<(PublicKey, IncomingPacket)>) -> Client {
        Client {
            pk,
            addr,
            incoming_tx,
            status: Arc::new(RwLock::new(ClientStatus::Disconnected)),
            connected_time: Arc::new(RwLock::new(None)),
            connection_attempts: Arc::new(RwLock::new(0)),
            links: Arc::new(RwLock::new(Links::new())),
            connections: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Handle packet received from TCP relay.
    pub fn handle_packet(&self, packet: Packet) -> impl Future<Item = (), Error = Error> + Send {
        // TODO: use anonymous sum types when rust has them
        // https://github.com/rust-lang/rfcs/issues/294
        match packet {
            Packet::RouteRequest(packet) => Box::new(self.handle_route_request(&packet)) as Box<dyn Future<Item = _, Error = _> + Send>,
            Packet::RouteResponse(packet) => Box::new(self.handle_route_response(&packet)),
            Packet::ConnectNotification(packet) => Box::new(self.handle_connect_notification(&packet)),
            Packet::DisconnectNotification(packet) => Box::new(self.handle_disconnect_notification(&packet)),
            Packet::PingRequest(packet) => Box::new(self.handle_ping_request(&packet)),
            Packet::PongResponse(packet) => Box::new(self.handle_pong_response(&packet)),
            Packet::OobSend(packet) => Box::new(self.handle_oob_send(&packet)),
            Packet::OobReceive(packet) => Box::new(self.handle_oob_receive(packet)),
            Packet::Data(packet) => Box::new(self.handle_data(packet)),
            Packet::OnionRequest(packet) => Box::new(self.handle_onion_request(&packet)),
            Packet::OnionResponse(packet) => Box::new(self.handle_onion_response(packet)),
        }
    }

    /// Send packet to this relay. If we are not connected to the relay an error
    /// will be returned.
    fn send_packet(&self, packet: Packet) -> impl Future<Item = (), Error = Error> + Send {
        if let ClientStatus::Connected(ref tx) = *self.status.read() {
            Either::A(send_to(tx, packet).map_err(|e|
                Error::new(ErrorKind::Other,
                    format!("Failed to send packet: {:?}", e)
            )))
        } else {
            // Attempt to send packet to TCP relay with wrong status. For
            // instance it can happen when we received ping request from the
            // relay and right after that relay became sleeping so we are not
            // able to respond anymore.
            Either::B( future::err(
                Error::new(ErrorKind::Other,
                    format!("Attempt to send packet to TCP relay with wrong status: {:?}", packet)
            )))
        }
    }

    fn handle_route_request(&self, _packet: &RouteRequest) -> impl Future<Item = (), Error = Error> + Send {
        future::err(
            Error::new(ErrorKind::Other,
                "Server must not send RouteRequest to client"
        ))
    }

    fn handle_route_response(&self, packet: &RouteResponse) -> impl Future<Item = (), Error = Error> + Send {
        let index = if let Some(index) = packet.connection_id.index() {
            index
        } else {
            return future::err(
                Error::new(ErrorKind::Other,
                    "RouteResponse: connection id is zero"
            ))
        };

        if self.connections.read().contains(&packet.pk) {
            if self.links.write().insert_by_id(&packet.pk, index) {
                future::ok(())
            } else {
                future::err(
                    Error::new(ErrorKind::Other,
                        "handle_route_response: connection_id is already linked"
                ))
            }
        } else {
            // in theory this can happen if we added connection and right
            // after that removed it
            // TODO: should it be handled better?
            future::err(
                Error::new(ErrorKind::Other,
                    "handle_route_response: unexpected route response"
            ))
        }
    }

    fn handle_connect_notification(&self, packet: &ConnectNotification) -> impl Future<Item = (), Error = Error> + Send {
        let index = if let Some(index) = packet.connection_id.index() {
            index
        } else {
            return future::err(
                Error::new(ErrorKind::Other,
                    "ConnectNotification: connection id is zero"
            ))
        };

        if self.links.write().upgrade(index) {
            future::ok(())
        } else {
            future::err(
                Error::new(ErrorKind::Other,
                    "handle_connect_notification: connection_id is not linked"
            ))
        }
    }

    fn handle_disconnect_notification(&self, packet: &DisconnectNotification) -> impl Future<Item = (), Error = Error> + Send {
        let index = if let Some(index) = packet.connection_id.index() {
            index
        } else {
            return future::err(
                Error::new(ErrorKind::Other,
                    "DisconnectNotification: connection id is zero"
            ))
        };

        if self.links.write().downgrade(index) {
            future::ok(())
        } else {
            future::err(
                Error::new(ErrorKind::Other,
                    "handle_disconnect_notification: connection_id is not linked"
            ))
        }
    }

    fn handle_ping_request(&self, packet: &PingRequest) -> impl Future<Item = (), Error = Error> + Send {
        self.send_packet(Packet::PongResponse(
            PongResponse { ping_id: packet.ping_id }
        ))
    }

    fn handle_pong_response(&self, _packet: &PongResponse) -> impl Future<Item = (), Error = Error> + Send {
        // TODO check ping_id
        future::ok(())
    }

    fn handle_oob_send(&self, _packet: &OobSend) -> impl Future<Item = (), Error = Error> + Send {
        future::err(
            Error::new(ErrorKind::Other,
                "Server must not send OobSend to client"
        ))
    }

    fn handle_oob_receive(&self, packet: OobReceive) -> impl Future<Item = (), Error = Error> + Send {
        send_to(&self.incoming_tx, (self.pk, IncomingPacket::Oob(packet.sender_pk, packet.data))).map_err(|e|
            Error::new(ErrorKind::Other,
                format!("Failed to send packet: {:?}", e)
        ))
    }

    fn handle_data(&self, packet: Data) -> impl Future<Item = (), Error = Error> + Send {
        let index = if let Some(index) = packet.connection_id.index() {
            index
        } else {
            return Either::A( future::err(
                Error::new(ErrorKind::Other,
                    "Data: connection id is zero"
            )))
        };

        let links = self.links.read();
        if let Some(link) = links.by_id(index) {
            Either::B(send_to(&self.incoming_tx, (self.pk, IncomingPacket::Data(link.pk, packet.data))).map_err(|e|
                Error::new(ErrorKind::Other,
                    format!("Failed to send packet: {:?}", e)
            )))
        } else {
            Either::A( future::err(
                Error::new(ErrorKind::Other,
                    "Data.connection_id is not linked"
            )))
        }
    }

    fn handle_onion_request(&self, _packet: &OnionRequest) -> impl Future<Item = (), Error = Error> + Send {
        future::err(
            Error::new(ErrorKind::Other,
                "Server must not send OnionRequest to client"
        ))
    }

    fn handle_onion_response(&self, packet: OnionResponse) -> impl Future<Item = (), Error = Error> + Send {
        send_to(&self.incoming_tx, (self.pk, IncomingPacket::Onion(packet.payload))).map_err(|e|
            Error::new(ErrorKind::Other,
                format!("Failed to send packet: {:?}", e)
        ))
    }

    /// Spawn a connection to this TCP relay if it is not connected already. The
    /// connection is spawned via `tokio::spawn` so the result future will be
    /// completed after first poll.
    pub fn spawn(self, dht_sk: SecretKey, dht_pk: PublicKey) -> impl Future<Item = (), Error = Error> + Send { // TODO: send pings periodically
        future::lazy(move || {
            let relay_pk = self.pk;
            let self_c = self.clone();

            match *self.status.write() {
                ref mut status @ ClientStatus::Disconnected
                | ref mut status @ ClientStatus::Sleeping => *status = ClientStatus::Connecting,
                _ => return future::ok(()),
            }

            let future = TcpStream::connect(&self.addr)
                .and_then(move |socket| make_client_handshake(socket, &dht_pk, &dht_sk, &relay_pk)) // TODO: timeout
                .and_then(move |(socket, channel)| {
                    let stats = Stats::new();
                    let secure_socket = Framed::new(socket, Codec::new(channel, stats));
                    let (to_server, from_server) = secure_socket.split();
                    let (to_server_tx, to_server_rx) = mpsc::channel(CLIENT_CHANNEL_SIZE);

                    match *self.status.write() {
                        ref mut status @ ClientStatus::Connecting => *status = ClientStatus::Connected(to_server_tx),
                        _ => return Either::A(future::ok(())),
                    }

                    *self.connection_attempts.write() = 0;

                    *self.connected_time.write() = Some(clock_now());

                    let route_requests = self.send_route_requests();

                    let writer = to_server_rx
                        .map_err(|()| -> EncodeError { unreachable!("rx can't fail") })
                        .forward(to_server)
                        .map_err(|e| Error::new(ErrorKind::Other, e.compat()))
                        .map(|_| ());

                    let reader = from_server
                        .map_err(|e| Error::new(ErrorKind::Other, e.compat()))
                        .for_each(move |packet| self.handle_packet(packet));

                    Either::B(writer
                        .select(reader)
                        .map_err(|(e, _)| e)
                        .join(route_requests)
                        .map(|_| ()))
                })
                .then(move |res| {
                    match *self_c.status.write() {
                        ClientStatus::Sleeping => { },
                        ref mut status => *status = ClientStatus::Disconnected,
                    }
                    if res.is_err() {
                        self_c.connection_attempts.write().saturating_add(1);
                    }
                    *self_c.connected_time.write() = None;
                    self_c.links.write().clear();
                    future::result(res)
                })
                .map_err(|e|
                    error!("TCP relay connection error: {}", e)
                );

            tokio::spawn(future);

            future::ok(())
        })
    }

    /// Send `RouteRequest` packet with specified `PublicKey`.
    fn send_route_request(&self, pk: PublicKey) -> impl Future<Item = (), Error = Error> + Send {
        self.send_packet(Packet::RouteRequest(RouteRequest {
            pk
        }))
    }

    /// Send `RouteRequest` packets for all nodes we should be connected to via
    /// the relay. It should be done for every fresh connection to the relay.
    fn send_route_requests(&self) -> impl Future<Item = (), Error = Error> + Send {
        let connections = self.connections.read();
        let futures = connections.iter()
            .map(|&pk| self.send_route_request(pk))
            .collect::<Vec<_>>();
        future::join_all(futures).map(|_| ())
    }

    /// Send `Data` packet to a node via relay.
    pub fn send_data(&self, destination_pk: PublicKey, data: Vec<u8>) -> impl Future<Item = (), Error = Error> + Send {
        // it is important that the result future succeeds only if packet is
        // sent since we take only one successful future from several relays
        // when send data packet
        let links = self.links.read();
        if let Some(index) = links.id_by_pk(&destination_pk) {
            if links.by_id(index).map(|link| link.status) == Some(LinkStatus::Online) {
                Either::A(self.send_packet(Packet::Data(Data {
                    connection_id: ConnectionId::from_index(index),
                    data,
                })))
            } else {
                Either::B( future::err(
                    Error::new(ErrorKind::Other,
                        "send_data: destination_pk is not online"
                )))
            }
        } else {
            Either::B( future::err(
                Error::new(ErrorKind::Other,
                    "send_data: destination_pk is not linked"
            )))
        }
    }

    /// Send `OobSend` packet to a node via relay.
    pub fn send_oob(&self, destination_pk: PublicKey, data: Vec<u8>) -> impl Future<Item = (), Error = Error> + Send {
        self.send_packet(Packet::OobSend(OobSend {
            destination_pk,
            data,
        }))
    }

    /// Send `OnionRequest` packet to the relay.
    pub fn send_onion(&self, onion_request: OnionRequest) -> impl Future<Item = (), Error = Error> + Send {
        self.send_packet(Packet::OnionRequest(onion_request))
    }

    /// Add connection to a friend via this relay. If we are connected to the
    /// relay `RouteRequest` packet will be sent. Also this packet will be sent
    /// when fresh connection is established.
    pub fn add_connection(&self, pk: PublicKey) -> impl Future<Item = (), Error = Error> + Send {
        if self.connections.write().insert(pk) {
            // ignore sending errors if we are not connected to the relay
            // in this case RouteRequest will be sent after connection
            Either::A(self.send_route_request(pk).then(|_| Ok(())))
        } else {
            Either::B(future::ok(()))
        }
    }

    /// Remove connection to a friend via this relay. If we are connected to the
    /// relay and linked to the friend `DisconnectNotification` packet will be
    /// sent.
    pub fn remove_connection(&self, pk: PublicKey) -> impl Future<Item = (), Error = Error> + Send {
        if self.connections.write().remove(&pk) {
            let mut links = self.links.write();
            if let Some(index) = links.id_by_pk(&pk) {
                links.take(index);
                Either::A(self.send_packet(Packet::DisconnectNotification(DisconnectNotification {
                    connection_id: ConnectionId::from_index(index),
                })).then(|_| Ok(())))
            } else {
                // the link may not exist if we delete the connection before we
                // receive RouteResponse packet
                // TODO: should it be handled better?
                Either::B(future::ok(()))
            }
        } else {
            Either::B( future::err(
                Error::new(ErrorKind::Other,
                    "remove_connection: no such connection"
            )))
        }
    }

    /// Drop connection to the TCP relay if it's connected.
    pub fn disconnect(&self) {
        // just drop the sink to stop the connection
        *self.status.write() = ClientStatus::Disconnected;
    }

    /// Drop connection to the TCP relay if it's connected changing status to
    /// `Sleeping`.
    pub fn sleep(&self) {
        // just drop the sink to stop the connection
        *self.status.write() = ClientStatus::Sleeping;
    }

    /// Check if TCP connection to the relay is established.
    pub fn is_connected(&self) -> bool {
        match *self.status.read() {
            ClientStatus::Connected(_) => true,
            _ => false,
        }
    }

    /// Check if TCP connection to the relay is not established.
    pub fn is_disconnected(&self) -> bool {
        match *self.status.read() {
            ClientStatus::Disconnected => true,
            _ => false,
        }
    }

    /// Check if TCP connection to the relay is sleeping.
    pub fn is_sleeping(&self) -> bool {
        match *self.status.read() {
            ClientStatus::Sleeping => true,
            _ => false,
        }
    }

    /// Number of unsuccessful attempts to establish connection to the relay.
    /// This value is always 0 for successfully connected relays.
    pub fn connection_attempts(&self) -> u32 {
        *self.connection_attempts.read()
    }

    /// Time when a connection to the relay was established. Only connected
    /// relays have this value.
    pub fn connected_time(&self) -> Option<Instant> {
        *self.connected_time.read()
    }

    /// Number of nodes we want to be connected to via this relay.
    pub fn connections_count(&self) -> usize {
        self.connections.read().len()
    }

    /// Check if connection to the node with specified `PublicKey` exists.
    pub fn has_connection(&self, pk: PublicKey) -> bool {
        self.connections.read().contains(&pk)
    }

    /// Check if connection to the node with specified `PublicKey` is online.
    pub fn is_connection_online(&self, pk: PublicKey) -> bool {
        let links = self.links.read();
        if let Some(index) = links.id_by_pk(&pk) {
            if let Some(link) = links.by_id(index) {
                link.status == LinkStatus::Online
            } else {
                false
            }
        } else {
            false
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use std::time::{Duration, Instant};

    use tokio::net::TcpListener;
    use tokio::timer::Interval;

    use crate::toxcore::onion::packet::*;
    use crate::toxcore::tcp::server::{Server, ServerExt};

    pub fn create_client() -> (mpsc::UnboundedReceiver<(PublicKey, IncomingPacket)>, mpsc::Receiver<Packet>, Client) {
        crypto_init().unwrap();
        let relay_addr = "127.0.0.1:12345".parse().unwrap();
        let (relay_pk, _relay_sk) = gen_keypair();
        let (incoming_tx, incoming_rx) = mpsc::unbounded();
        let (outgoing_tx, outgoing_rx) = mpsc::channel(CLIENT_CHANNEL_SIZE);
        let client = Client::new(relay_pk, relay_addr, incoming_tx);
        *client.status.write() = ClientStatus::Connected(outgoing_tx);
        *client.connected_time.write() = Some(Instant::now());
        (incoming_rx, outgoing_rx, client)
    }

    pub fn set_connection_attempts(client: &Client, attempts: u32) {
        *client.connection_attempts.write() = attempts;
    }

    #[test]
    fn handle_route_request() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let route_request = Packet::RouteRequest(RouteRequest {
            pk: gen_keypair().0,
        });

        assert!(client.handle_packet(route_request).wait().is_err());
    }

    #[test]
    fn handle_route_response() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let (new_pk, _new_sk) = gen_keypair();
        let index = 42;

        client.connections.write().insert(new_pk);

        let route_response = Packet::RouteResponse(RouteResponse {
            connection_id: ConnectionId::from_index(index),
            pk: new_pk,
        });

        client.handle_packet(route_response).wait().unwrap();

        let link = client.links.read().by_id(index).cloned().unwrap();

        assert_eq!(link.pk, new_pk);
        assert_eq!(link.status, LinkStatus::Registered);
    }

    #[test]
    fn handle_route_response_occupied() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let (existing_pk, _existing_sk) = gen_keypair();
        let (new_pk, _new_sk) = gen_keypair();
        let index = 42;

        client.connections.write().insert(new_pk);
        client.links.write().insert_by_id(&existing_pk, index);

        let route_response = Packet::RouteResponse(RouteResponse {
            connection_id: ConnectionId::from_index(index),
            pk: new_pk,
        });

        assert!(client.handle_packet(route_response).wait().is_err());

        let link = client.links.read().by_id(index).cloned().unwrap();

        assert_eq!(link.pk, existing_pk);
        assert_eq!(link.status, LinkStatus::Registered);
    }

    #[test]
    fn handle_route_response_unexpected() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let index = 42;
        let route_response = Packet::RouteResponse(RouteResponse {
            connection_id: ConnectionId::from_index(index),
            pk: gen_keypair().0,
        });

        assert!(client.handle_packet(route_response).wait().is_err());

        assert!(client.links.read().by_id(index).is_none());
    }

    #[test]
    fn handle_route_response_0() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let route_response = Packet::RouteResponse(RouteResponse {
            connection_id: ConnectionId::zero(),
            pk: gen_keypair().0,
        });

        assert!(client.handle_packet(route_response).wait().is_err());
    }

    #[test]
    fn handle_connect_notification() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let (existing_pk, _existing_sk) = gen_keypair();
        let index = 42;

        client.links.write().insert_by_id(&existing_pk, index);

        let connect_notification = Packet::ConnectNotification(ConnectNotification {
            connection_id: ConnectionId::from_index(index),
        });

        client.handle_packet(connect_notification).wait().unwrap();

        let link = client.links.read().by_id(index).cloned().unwrap();

        assert_eq!(link.pk, existing_pk);
        assert_eq!(link.status, LinkStatus::Online);
    }

    #[test]
    fn handle_connect_notification_unexpected() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let index = 42;
        let connect_notification = Packet::ConnectNotification(ConnectNotification {
            connection_id: ConnectionId::from_index(index),
        });

        assert!(client.handle_packet(connect_notification).wait().is_err());

        assert!(client.links.read().by_id(index).is_none());
    }

    #[test]
    fn handle_connect_notification_0() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let connect_notification = Packet::ConnectNotification(ConnectNotification {
            connection_id: ConnectionId::zero(),
        });

        assert!(client.handle_packet(connect_notification).wait().is_err());
    }

    #[test]
    fn handle_disconnect_notification() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let (existing_pk, _existing_sk) = gen_keypair();
        let index = 42;

        client.links.write().insert_by_id(&existing_pk, index);
        client.links.write().upgrade(index);

        let disconnect_notification = Packet::DisconnectNotification(DisconnectNotification {
            connection_id: ConnectionId::from_index(index),
        });

        client.handle_packet(disconnect_notification).wait().unwrap();

        let link = client.links.read().by_id(index).cloned().unwrap();

        assert_eq!(link.pk, existing_pk);
        assert_eq!(link.status, LinkStatus::Registered);
    }

    #[test]
    fn handle_disconnect_notification_unexpected() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let index = 42;
        let disconnect_notification = Packet::DisconnectNotification(DisconnectNotification {
            connection_id: ConnectionId::from_index(index),
        });

        assert!(client.handle_packet(disconnect_notification).wait().is_err());

        assert!(client.links.read().by_id(index).is_none());
    }

    #[test]
    fn handle_disconnect_notification_0() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let disconnect_notification = Packet::DisconnectNotification(DisconnectNotification {
            connection_id: ConnectionId::zero(),
        });

        assert!(client.handle_packet(disconnect_notification).wait().is_err());
    }

    #[test]
    fn handle_ping_request() {
        let (_incoming_rx, outgoing_rx, client) = create_client();

        let ping_id = 42;
        let ping_request = Packet::PingRequest(PingRequest {
            ping_id
        });

        client.handle_packet(ping_request).wait().unwrap();

        let packet = unpack!(outgoing_rx.into_future().wait().unwrap().0.unwrap(), Packet::PongResponse);

        assert_eq!(packet.ping_id, ping_id);
    }

    #[test]
    fn handle_pong_response() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let ping_id = 42;
        let pong_response = Packet::PongResponse(PongResponse {
            ping_id
        });

        client.handle_packet(pong_response).wait().unwrap();
    }

    #[test]
    fn handle_oob_send() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let oob_send = Packet::OobSend(OobSend {
            destination_pk: gen_keypair().0,
            data: vec![42; 123],
        });

        assert!(client.handle_packet(oob_send).wait().is_err());
    }

    #[test]
    fn handle_oob_receive() {
        let (incoming_rx, _outgoing_rx, client) = create_client();

        let sender_pk = gen_keypair().0;
        let data = vec![42; 123];
        let oob_receive = Packet::OobReceive(OobReceive {
            sender_pk,
            data: data.clone(),
        });

        client.handle_packet(oob_receive).wait().unwrap();

        let (relay_pk, packet) = incoming_rx.into_future().wait().unwrap().0.unwrap();
        let (received_pk, received_data) = unpack!(packet, IncomingPacket::Oob[pk, data]);

        assert_eq!(relay_pk, client.pk);
        assert_eq!(received_pk, sender_pk);
        assert_eq!(received_data, data);
    }

    #[test]
    fn handle_data() {
        let (incoming_rx, _outgoing_rx, client) = create_client();

        let (sender_pk, _sender_sk) = gen_keypair();
        let index = 42;

        client.links.write().insert_by_id(&sender_pk, index);
        client.links.write().upgrade(index);

        let data = vec![42; 123];
        let data_packet = Packet::Data(Data {
            connection_id: ConnectionId::from_index(index),
            data: data.clone(),
        });

        client.handle_packet(data_packet).wait().unwrap();

        let (relay_pk, packet) = incoming_rx.into_future().wait().unwrap().0.unwrap();
        let (received_pk, received_data) = unpack!(packet, IncomingPacket::Data[pk, data]);

        assert_eq!(relay_pk, client.pk);
        assert_eq!(received_pk, sender_pk);
        assert_eq!(received_data, data);
    }

    #[test]
    fn handle_data_unexpected() {
        let (incoming_rx, _outgoing_rx, client) = create_client();

        let data_packet = Packet::Data(Data {
            connection_id: ConnectionId::from_index(42),
            data: vec![42; 123],
        });

        assert!(client.handle_packet(data_packet).wait().is_err());

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(incoming_rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn handle_data_0() {
        let (incoming_rx, _outgoing_rx, client) = create_client();

        let data_packet = Packet::Data(Data {
            connection_id: ConnectionId::zero(),
            data: vec![42; 123],
        });

        assert!(client.handle_packet(data_packet).wait().is_err());

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(incoming_rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn handle_onion_request() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let onion_request = Packet::OnionRequest(OnionRequest {
            nonce: gen_nonce(),
            ip_port: IpPort {
                protocol: ProtocolType::TCP,
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345,
            },
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123],
        });

        assert!(client.handle_packet(onion_request).wait().is_err());
    }

    #[test]
    fn handle_onion_response() {
        let (incoming_rx, _outgoing_rx, client) = create_client();

        let payload = InnerOnionResponse::OnionDataResponse(OnionDataResponse {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123]
        });
        let onion_response = Packet::OnionResponse(OnionResponse {
            payload: payload.clone(),
        });

        client.handle_packet(onion_response).wait().unwrap();

        let (relay_pk, packet) = incoming_rx.into_future().wait().unwrap().0.unwrap();
        let received_payload = unpack!(packet, IncomingPacket::Onion);

        assert_eq!(relay_pk, client.pk);
        assert_eq!(received_payload, payload);
    }

    #[test]
    fn send_data() {
        let (_incoming_rx, outgoing_rx, client) = create_client();

        let (destination_pk, _destination_sk) = gen_keypair();
        let data = vec![42; 123];

        let index = 42;
        client.links.write().insert_by_id(&destination_pk, index);
        client.links.write().upgrade(index);

        client.send_data(destination_pk, data.clone()).wait().unwrap();

        let packet = unpack!(outgoing_rx.into_future().wait().unwrap().0.unwrap(), Packet::Data);

        assert_eq!(packet.connection_id, ConnectionId::from_index(index));
        assert_eq!(packet.data, data);
    }

    #[test]
    fn send_data_not_linked() {
        let (_incoming_rx, outgoing_rx, client) = create_client();

        let (destination_pk, _destination_sk) = gen_keypair();
        let data = vec![42; 123];

        assert!(client.send_data(destination_pk, data.clone()).wait().is_err());

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(outgoing_rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn send_data_not_online() {
        let (_incoming_rx, outgoing_rx, client) = create_client();

        let (destination_pk, _destination_sk) = gen_keypair();
        let data = vec![42; 123];

        let connection_id = 42;
        client.links.write().insert_by_id(&destination_pk, connection_id - 16);

        assert!(client.send_data(destination_pk, data.clone()).wait().is_err());

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(outgoing_rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn send_oob() {
        let (_incoming_rx, outgoing_rx, client) = create_client();

        let (destination_pk, _destination_sk) = gen_keypair();
        let data = vec![42; 123];

        client.send_oob(destination_pk, data.clone()).wait().unwrap();

        let packet = unpack!(outgoing_rx.into_future().wait().unwrap().0.unwrap(), Packet::OobSend);

        assert_eq!(packet.destination_pk, destination_pk);
        assert_eq!(packet.data, data);
    }

    #[test]
    fn send_onion() {
        let (_incoming_rx, outgoing_rx, client) = create_client();

        let onion_request = OnionRequest {
            nonce: gen_nonce(),
            ip_port: IpPort {
                protocol: ProtocolType::TCP,
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345,
            },
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123],
        };

        client.send_onion(onion_request.clone()).wait().unwrap();

        let packet = unpack!(outgoing_rx.into_future().wait().unwrap().0.unwrap(), Packet::OnionRequest);

        assert_eq!(packet, onion_request);
    }

    #[test]
    fn add_connection() {
        let (_incoming_rx, outgoing_rx, client) = create_client();

        let (connection_pk, _connection_sk) = gen_keypair();

        client.add_connection(connection_pk).wait().unwrap();

        let (packet, outgoing_rx) = outgoing_rx.into_future().wait().unwrap();
        let packet = unpack!(packet.unwrap(), Packet::RouteRequest);

        assert_eq!(packet.pk, connection_pk);

        // RouteRequest shouldn't be sent again after we add the same connection
        client.add_connection(connection_pk).wait().unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(outgoing_rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn remove_connection() {
        let (_incoming_rx, outgoing_rx, client) = create_client();

        let (connection_pk, _connection_sk) = gen_keypair();
        let index = 42;

        client.connections.write().insert(connection_pk);
        client.links.write().insert_by_id(&connection_pk, index);

        client.remove_connection(connection_pk).wait().unwrap();

        let packet = unpack!(outgoing_rx.into_future().wait().unwrap().0.unwrap(), Packet::DisconnectNotification);

        assert_eq!(packet.connection_id, ConnectionId::from_index(index));
    }

    #[test]
    fn remove_connection_no_connection() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let (connection_pk, _connection_sk) = gen_keypair();

        assert!(client.remove_connection(connection_pk).wait().is_err());
    }

    #[test]
    fn remove_connection_no_link() {
        let (_incoming_rx, outgoing_rx, client) = create_client();

        let (connection_pk, _connection_sk) = gen_keypair();

        client.connections.write().insert(connection_pk);

        client.remove_connection(connection_pk).wait().unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(outgoing_rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn disconnect() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        assert!(client.is_connected());
        assert!(!client.is_disconnected());
        assert!(!client.is_sleeping());

        client.disconnect();

        assert!(!client.is_connected());
        assert!(client.is_disconnected());
        assert!(!client.is_sleeping());
    }

    #[test]
    fn sleep() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        assert!(client.is_connected());
        assert!(!client.is_disconnected());
        assert!(!client.is_sleeping());

        client.sleep();

        assert!(!client.is_connected());
        assert!(!client.is_disconnected());
        assert!(client.is_sleeping());
    }

    #[test]
    fn is_connection_online() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let (connection_pk, _connection_sk) = gen_keypair();
        let connection_id = 42;

        client.links.write().insert_by_id(&connection_pk, connection_id - 16);

        assert!(!client.is_connection_online(connection_pk));

        client.links.write().upgrade(connection_id - 16);

        assert!(client.is_connection_online(connection_pk));
    }

    #[test]
    fn connections_count() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        assert_eq!(client.connections_count(), 0);

        let (connection_pk, _connection_sk) = gen_keypair();

        client.connections.write().insert(connection_pk);

        assert_eq!(client.connections_count(), 1);
    }

    #[test]
    fn is_connection_online_no_connection() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let (connection_pk, _connection_sk) = gen_keypair();

        assert!(!client.is_connection_online(connection_pk));
    }

    #[test]
    fn spawn() {
        // waits until the relay becomes connected
        fn on_connected(client: Client) -> impl Future<Item = (), Error = Error> + Send {
            Interval::new(Instant::now(), Duration::from_millis(10))
                .map_err(|e| Error::new(ErrorKind::Other, e))
                .skip_while(move |_| match *client.status.read() {
                    ClientStatus::Connecting => future::ok(true),
                    ClientStatus::Connected(_) => future::ok(false),
                    ref other => future::err(Error::new(ErrorKind::Other, format!("Invalid status: {:?}", other))),
                })
                .into_future()
                .map(|_| ())
                .map_err(|(e, _)| e)
        }

        // waits until link with PublicKey becomes online
        fn on_online(client: Client, pk: PublicKey) -> impl Future<Item = (), Error = Error> + Send {
            Interval::new(Instant::now(), Duration::from_millis(10))
                .map_err(|e| Error::new(ErrorKind::Other, e))
                .skip_while(move |_| {
                    let links = client.links.read();
                    if let Some(index) = links.id_by_pk(&pk) {
                        future::ok(links.by_id(index).map(|link| link.status) != Some(LinkStatus::Online))
                    } else {
                        future::ok(true)
                    }
                })
                .into_future()
                .map(|_| ())
                .map_err(|(e, _)| e)
        }

        crypto_init().unwrap();
        // run server
        let (server_pk, server_sk) = gen_keypair();

        let addr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(&addr).unwrap();
        let addr = listener.local_addr().unwrap();

        let server = Server::new();
        let stats = Stats::new();
        let server_future = server.run(listener, server_sk, stats, 2)
            .map_err(|e| Error::new(ErrorKind::Other, e.compat()));

        // run first client
        let (client_pk_1, client_sk_1) = gen_keypair();
        let (incoming_tx_1, incoming_rx_1) = mpsc::unbounded();
        let client_1 = Client::new(server_pk, addr, incoming_tx_1);
        // connection attempts should be set to 0 after successful connection
        set_connection_attempts(&client_1, 3);
        let client_future_1 = client_1.clone().spawn(client_sk_1, client_pk_1);

        // run second client
        let (client_pk_2, client_sk_2) = gen_keypair();
        let (incoming_tx_2, incoming_rx_2) = mpsc::unbounded();
        let client_2 = Client::new(server_pk, addr, incoming_tx_2);
        // connection attempts should be set to 0 after successful connection
        set_connection_attempts(&client_2, 3);
        let client_future_2 = client_2.clone().spawn(client_sk_2, client_pk_2);

        // add connection immediately
        let connection_future = client_2.add_connection(client_pk_1);

        // wait until connections are established
        let client_1_c = client_1.clone();
        let client_2_c = client_2.clone();
        let on_connected_future = on_connected(client_1.clone()).join(on_connected(client_2.clone())).and_then(move |_| {
            assert!(client_1_c.connected_time().is_some());
            assert!(client_2_c.connected_time().is_some());
            assert_eq!(client_1_c.connection_attempts(), 0);
            assert_eq!(client_2_c.connection_attempts(), 0);
            // add connection when relay is connected
            client_1_c.add_connection(client_pk_2)
        });

        let data_1 = vec![42; 123];
        let data_2 = vec![43; 123];

        // wait until links become online
        let client_1_c = client_1.clone();
        let client_2_c = client_2.clone();
        let data_1_c = data_1.clone();
        let data_2_c = data_2.clone();
        let on_online_future = on_online(client_1.clone(), client_pk_2).join(on_online(client_2.clone(), client_pk_1))
            // and then send data packets to each other
            .and_then(move |_| client_1_c.send_data(client_pk_2, data_1_c))
            .and_then(move |_| client_2_c.send_data(client_pk_1, data_2_c))
            // and then get them
            .and_then(move |_| incoming_rx_1.map_err(|()| unreachable!("rx can't fail")).into_future().map(move |(packet, _)| {
                let (relay_pk, packet) = packet.unwrap();
                let (received_pk, received_data) = unpack!(packet, IncomingPacket::Data[pk, data]);
                assert_eq!(relay_pk, server_pk);
                assert_eq!(received_pk, client_pk_2);
                assert_eq!(received_data, data_2);
            }).map_err(|(e, _)| e))
            .and_then(move |_| incoming_rx_2.map_err(|()| unreachable!("rx can't fail")).into_future().map(move |(packet, _)| {
                let (relay_pk, packet) = packet.unwrap();
                let (received_pk, received_data) = unpack!(packet, IncomingPacket::Data[pk, data]);
                assert_eq!(relay_pk, server_pk);
                assert_eq!(received_pk, client_pk_1);
                assert_eq!(received_data, data_1);
            }).map_err(|(e, _)| e))
            .map(move |_| {
                // tokio runtime won't become idle until we drop the connections
                client_1.disconnect();
                client_2.disconnect();
            });

        let future = client_future_1
            .join5(client_future_2, connection_future, on_connected_future, on_online_future)
            .map(|_| ());
        let future = server_future
            .select(future)
            .then(|r| {
                assert!(r.is_ok());
                r
            })
            .map(|_| ())
            .map_err(|_| ());

        tokio::run(future);
    }
}
