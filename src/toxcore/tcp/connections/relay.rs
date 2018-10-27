use std::collections::{HashMap, HashSet};
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

use toxcore::crypto_core::*;
use toxcore::io_tokio::*;
use toxcore::onion::packet::InnerOnionResponse;
use toxcore::stats::Stats;
use toxcore::tcp::codec::{Codec, EncodeError};
use toxcore::tcp::handshake::make_client_handshake;
use toxcore::tcp::packet::*;
use toxcore::time::*;

/// Buffer size (in packets) for outgoing packets. This number shouldn't be high
/// to minimize latency. If some relay can't take more packets we can use
/// another relay. So it doesn't make much sense to buffer packets and wait for
/// the relay to send them.
const RELAY_CHANNEL_SIZE: usize = 2;

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
enum RelayStatus {
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

/// Link status.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum LinkStatus {
    /// We received `RouteResponse` packet with connection id but can't use it
    /// until we get `ConnectNotification` packet.
    Registered,
    /// We received `ConnectNotification` packet so connection can be used to
    /// send packets.
    Online,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct Link {
    status: LinkStatus,
    pk: PublicKey,
}

impl Link {
    fn new(pk: PublicKey) -> Link {
        Link {
            status: LinkStatus::Registered,
            pk,
        }
    }
}

/// Client connection to a TCP relay.
#[derive(Clone)]
pub struct Relay {
    /// `PublicKey` of the TCP relay.
    pub pk: PublicKey,
    /// IP address of the TCP relay.
    pub addr: SocketAddr,
    /// Sink for packets that should be handled somewhere else. `PublicKey` here
    /// belongs to TCP relay.
    incoming_tx: mpsc::UnboundedSender<(PublicKey, IncomingPacket)>,
    /// Status of the relay.
    status: Arc<RwLock<RelayStatus>>,
    /// Time when a connection to the relay was established.
    connected_time: Arc<RwLock<Option<Instant>>>,
    /// Number of unsuccessful attempts to establish connection to the relay.
    /// This is used to decide what to do after the connection terminates.
    connection_attempts: Arc<RwLock<u32>>,
    links: Arc<RwLock<[Option<Link>; 240]>>,
    pk_to_id: Arc<RwLock<HashMap<PublicKey, u8>>>,
    /// List of nodes we want to be connected to. When the connection to the
    /// relay establishes we send `RouteRequest` packets with these `PublicKey`s.
    connections: Arc<RwLock<HashSet<PublicKey>>>,
}

impl Relay {
    /// Create new `Relay` object.
    pub fn new(pk: PublicKey, addr: SocketAddr, incoming_tx: mpsc::UnboundedSender<(PublicKey, IncomingPacket)>) -> Relay {
        Relay {
            pk,
            addr,
            incoming_tx,
            status: Arc::new(RwLock::new(RelayStatus::Disconnected)),
            connected_time: Arc::new(RwLock::new(None)),
            connection_attempts: Arc::new(RwLock::new(0)),
            links: Arc::new(RwLock::new([None; 240])),
            pk_to_id: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Handle packet received from TCP relay.
    pub fn handle_packet(&self, packet: Packet) -> IoFuture<()> {
        match packet {
            Packet::RouteRequest(packet) => self.handle_route_request(packet),
            Packet::RouteResponse(packet) => self.handle_route_response(packet),
            Packet::ConnectNotification(packet) => self.handle_connect_notification(packet),
            Packet::DisconnectNotification(packet) => self.handle_disconnect_notification(packet),
            Packet::PingRequest(packet) => self.handle_ping_request(packet),
            Packet::PongResponse(packet) => self.handle_pong_response(packet),
            Packet::OobSend(packet) => self.handle_oob_send(packet),
            Packet::OobReceive(packet) => self.handle_oob_receive(packet),
            Packet::Data(packet) => self.handle_data(packet),
            Packet::OnionRequest(packet) => self.handle_onion_request(packet),
            Packet::OnionResponse(packet) => self.handle_onion_response(packet),
        }
    }

    /// Send packet to this relay. If we are not connected to the relay an error
    /// will be returned.
    fn send_packet(&self, packet: Packet) -> IoFuture<()> {
        if let RelayStatus::Connected(ref tx) = *self.status.read() {
            send_to(tx, packet)
        } else {
            // Attempt to send packet to TCP relay with wrong status. For
            // instance it can happen when we received ping request from the
            // relay and right after that relay became sleeping so we are not
            // able to respond anymore.
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    format!("Attempt to send packet to TCP relay with wrong status: {:?}", packet)
            )))
        }
    }

    fn handle_route_request(&self, _packet: RouteRequest) -> IoFuture<()> {
        Box::new( future::err(
            Error::new(ErrorKind::Other,
                "Server must not send RouteRequest to client"
        )))
    }

    fn handle_route_response(&self, packet: RouteResponse) -> IoFuture<()> {
        let mut links = self.links.write();
        let link = &mut links[packet.connection_id as usize - 16];
        if link.is_none() {
            if self.connections.read().contains(&packet.pk) {
                *link = Some(Link::new(packet.pk));
                self.pk_to_id.write().insert(packet.pk, packet.connection_id);
                Box::new(future::ok(()))
            } else {
                // in theory this can happen if we added connection and right
                // after that removed it
                // TODO: should it be handled better?
                Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "handle_route_response: unexpected route response"
                )))
            }
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "handle_route_response: connection_id is already linked"
            )))
        }
    }

    fn handle_connect_notification(&self, packet: ConnectNotification) -> IoFuture<()> {
        let mut links = self.links.write();
        if let Some(ref mut link) = links[packet.connection_id as usize - 16] {
            link.status = LinkStatus::Online;
            Box::new(future::ok(()))
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "handle_connect_notification: connection_id is not linked"
            )))
        }
    }

    fn handle_disconnect_notification(&self, packet: DisconnectNotification) -> IoFuture<()> {
        let mut links = self.links.write();
        if let Some(ref mut link) = links[packet.connection_id as usize - 16] {
            link.status = LinkStatus::Registered;
            Box::new(future::ok(()))
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "handle_disconnect_notification: connection_id is not linked"
            )))
        }
    }

    fn handle_ping_request(&self, packet: PingRequest) -> IoFuture<()> {
        self.send_packet(Packet::PongResponse(
            PongResponse { ping_id: packet.ping_id }
        ))
    }

    fn handle_pong_response(&self, _packet: PongResponse) -> IoFuture<()> {
        // TODO check ping_id
        Box::new(future::ok(()))
    }

    fn handle_oob_send(&self, _packet: OobSend) -> IoFuture<()> {
        Box::new( future::err(
            Error::new(ErrorKind::Other,
                "Server must not send OobSend to client"
        )))
    }

    fn handle_oob_receive(&self, packet: OobReceive) -> IoFuture<()> {
        send_to(&self.incoming_tx, (self.pk, IncomingPacket::Oob(packet.sender_pk, packet.data)))
    }

    fn handle_data(&self, packet: Data) -> IoFuture<()> {
        let links = self.links.read();
        if let Some(link) = links[packet.connection_id as usize - 16] {
            send_to(&self.incoming_tx, (self.pk, IncomingPacket::Data(link.pk, packet.data)))
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "Data.connection_id is not linked"
            )))
        }
    }

    fn handle_onion_request(&self, _packet: OnionRequest) -> IoFuture<()> {
        Box::new( future::err(
            Error::new(ErrorKind::Other,
                "Server must not send OnionRequest to client"
        )))
    }

    fn handle_onion_response(&self, packet: OnionResponse) -> IoFuture<()> {
        send_to(&self.incoming_tx, (self.pk, IncomingPacket::Onion(packet.payload)))
    }

    /// Spawn a connection to this TCP relay if it is not connected already. The
    /// connection is spawned via `tokio::spawn` so the result future will be
    /// completed after first poll.
    pub fn spawn(self, dht_sk: SecretKey, dht_pk: PublicKey) -> IoFuture<()> { // TODO: send pings periodically
        Box::new(future::lazy(move || {
            let relay_pk = self.pk;
            let self_c = self.clone();

            match *self.status.write() {
                ref mut status @ RelayStatus::Disconnected
                | ref mut status @ RelayStatus::Sleeping => *status = RelayStatus::Connecting,
                _ => return future::ok(()),
            }

            let future = TcpStream::connect(&self.addr)
                .and_then(move |socket| make_client_handshake(socket, &dht_pk, &dht_sk, &relay_pk)) // TODO: timeout
                .and_then(move |(socket, channel)| {
                    let stats = Stats::new();
                    let secure_socket = Framed::new(socket, Codec::new(channel, stats));
                    let (to_server, from_server) = secure_socket.split();
                    let (to_server_tx, to_server_rx) = mpsc::channel(RELAY_CHANNEL_SIZE);

                    match *self.status.write() {
                        ref mut status @ RelayStatus::Connecting => *status = RelayStatus::Connected(to_server_tx),
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
                        RelayStatus::Sleeping => { },
                        ref mut status => *status = RelayStatus::Disconnected,
                    }
                    if res.is_err() {
                        self_c.connection_attempts.write().saturating_add(1);
                    }
                    *self_c.connected_time.write() = None;
                    self_c.clear_links();
                    future::result(res)
                })
                .map_err(|e| {
                    error!("TCP relay connection error: {}", e);
                    ()
                });

            tokio::spawn(future);

            future::ok(())
        }))
    }

    /// Send `RouteRequest` packet with specified `PublicKey`.
    fn send_route_request(&self, pk: PublicKey) -> IoFuture<()> {
        self.send_packet(Packet::RouteRequest(RouteRequest {
            pk
        }))
    }

    /// Send `RouteRequest` packets for all nodes we should be connected to via
    /// the relay. It should be done for every fresh connection to the relay.
    fn send_route_requests(&self) -> IoFuture<()> {
        let connections = self.connections.read();
        let futures = connections.iter()
            .map(|&pk| self.send_route_request(pk))
            .collect::<Vec<_>>();
        Box::new(future::join_all(futures).map(|_| ()))
    }

    /// When the connection to a TCP relay closed links are no longer valid.
    /// After new connection establishes new links will be created.
    fn clear_links(&self) {
        *self.links.write() = [None; 240];
        self.pk_to_id.write().clear();
    }

    /// Send `Data` packet to a node via relay.
    pub fn send_data(&self, destination_pk: PublicKey, data: Vec<u8>) -> IoFuture<()> {
        // it is important that the result future succeeds only if packet is
        // sent since we take only one successful future from several relays
        // when send data packet
        let pk_to_id = self.pk_to_id.read();
        if let Some(&connection_id) = pk_to_id.get(&destination_pk) {
            let links = self.links.read();
            if links[connection_id as usize - 16].map(|link| link.status) == Some(LinkStatus::Online) {
                self.send_packet(Packet::Data(Data {
                    connection_id,
                    data,
                }))
            } else {
                Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "send_data: destination_pk is not online"
                )))
            }
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "send_data: destination_pk is not linked"
            )))
        }
    }

    /// Send `OobSend` packet to a node via relay.
    pub fn send_oob(&self, destination_pk: PublicKey, data: Vec<u8>) -> IoFuture<()> {
        self.send_packet(Packet::OobSend(OobSend {
            destination_pk,
            data,
        }))
    }

    /// Send `OnionRequest` packet to the relay.
    pub fn send_onion(&self, onion_request: OnionRequest) -> IoFuture<()> {
        self.send_packet(Packet::OnionRequest(onion_request))
    }

    /// Add connection to a friend via this relay. If we are connected to the
    /// relay `RouteRequest` packet will be sent. Also this packet will be sent
    /// when fresh connection is established.
    pub fn add_connection(&self, pk: PublicKey) -> IoFuture<()> {
        if self.connections.write().insert(pk) {
            // ignore sending errors if we are not connected to the relay
            // in this case RouteRequest will be sent after connection
            Box::new(self.send_route_request(pk).then(|_| Ok(())))
        } else {
            Box::new(future::ok(()))
        }
    }

    /// Remove connection to a friend via this relay. If we are connected to the
    /// relay and linked to the friend `DisconnectNotification` packet will be
    /// sent.
    pub fn remove_connection(&self, pk: PublicKey) -> IoFuture<()> {
        if self.connections.write().remove(&pk) {
            let mut pk_to_id = self.pk_to_id.write();
            if let Some(connection_id) = pk_to_id.remove(&pk) {
                self.links.write()[connection_id as usize - 16] = None;
                Box::new(self.send_packet(Packet::DisconnectNotification(DisconnectNotification {
                    connection_id
                })).then(|_| Ok(())))
            } else {
                // the link may not exist if we delete the connection before we
                // receive RouteResponse packet
                // TODO: should it be handled better?
                Box::new(future::ok(()))
            }
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "remove_connection: no such connection"
            )))
        }
    }

    /// Drop connection to the TCP relay if it's connected.
    pub fn disconnect(&self) {
        // just drop the sink to stop the connection
        *self.status.write() = RelayStatus::Disconnected;
    }

    /// Drop connection to the TCP relay if it's connected changing status to
    /// `Sleeping`.
    pub fn sleep(&self) {
        // just drop the sink to stop the connection
        *self.status.write() = RelayStatus::Sleeping;
    }

    /// Check if TCP connection to the relay is established.
    pub fn is_connected(&self) -> bool {
        match *self.status.read() {
            RelayStatus::Connected(_) => true,
            _ => false,
        }
    }

    /// Check if TCP connection to the relay is not established.
    pub fn is_disconnected(&self) -> bool {
        match *self.status.read() {
            RelayStatus::Disconnected => true,
            _ => false,
        }
    }

    /// Check if TCP connection to the relay is sleeping.
    pub fn is_sleeping(&self) -> bool {
        match *self.status.read() {
            RelayStatus::Sleeping => true,
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
        if let Some(&connection_id) = self.pk_to_id.read().get(&pk) {
            if let Some(link) = self.links.read()[connection_id as usize - 16] {
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

    use toxcore::onion::packet::*;
    use toxcore::tcp::server::*;

    pub fn create_relay() -> (mpsc::UnboundedReceiver<(PublicKey, IncomingPacket)>, mpsc::Receiver<Packet>, Relay) {
        let relay_addr = "127.0.0.1:12345".parse().unwrap();
        let (relay_pk, _relay_sk) = gen_keypair();
        let (incoming_tx, incoming_rx) = mpsc::unbounded();
        let (outgoing_tx, outgoing_rx) = mpsc::channel(RELAY_CHANNEL_SIZE);
        let relay = Relay::new(relay_pk, relay_addr, incoming_tx);
        *relay.status.write() = RelayStatus::Connected(outgoing_tx);
        *relay.connected_time.write() = Some(Instant::now());
        (incoming_rx, outgoing_rx, relay)
    }

    pub fn set_connection_attempts(relay: &Relay, attempts: u32) {
        *relay.connection_attempts.write() = attempts;
    }

    #[test]
    fn handle_route_request() {
        let (_incoming_rx, _outgoing_rx, relay) = create_relay();

        let route_request = Packet::RouteRequest(RouteRequest {
            pk: gen_keypair().0,
        });

        assert!(relay.handle_packet(route_request).wait().is_err());
    }

    #[test]
    fn handle_route_response() {
        let (_incoming_rx, _outgoing_rx, relay) = create_relay();

        let (new_pk, _new_sk) = gen_keypair();
        let connection_id = 42;

        relay.connections.write().insert(new_pk);

        let route_response = Packet::RouteResponse(RouteResponse {
            connection_id,
            pk: new_pk,
        });

        relay.handle_packet(route_response).wait().unwrap();

        let link = relay.links.read()[connection_id as usize - 16].unwrap();

        assert_eq!(link.pk, new_pk);
        assert_eq!(link.status, LinkStatus::Registered);
    }

    #[test]
    fn handle_route_response_occupied() {
        let (_incoming_rx, _outgoing_rx, relay) = create_relay();

        let (existing_pk, _existing_sk) = gen_keypair();
        let (new_pk, _new_sk) = gen_keypair();
        let connection_id = 42;

        relay.connections.write().insert(new_pk);
        relay.links.write()[connection_id as usize - 16] = Some(Link::new(existing_pk));

        let route_response = Packet::RouteResponse(RouteResponse {
            connection_id,
            pk: new_pk,
        });

        assert!(relay.handle_packet(route_response).wait().is_err());

        let link = relay.links.read()[connection_id as usize - 16].unwrap();

        assert_eq!(link.pk, existing_pk);
        assert_eq!(link.status, LinkStatus::Registered);
    }

    #[test]
    fn handle_route_response_unexpected() {
        let (_incoming_rx, _outgoing_rx, relay) = create_relay();

        let connection_id = 42;
        let route_response = Packet::RouteResponse(RouteResponse {
            connection_id,
            pk: gen_keypair().0,
        });

        assert!(relay.handle_packet(route_response).wait().is_err());

        assert!(relay.links.read()[connection_id as usize - 16].is_none());
    }

    #[test]
    fn handle_connect_notification() {
        let (_incoming_rx, _outgoing_rx, relay) = create_relay();

        let (existing_pk, _existing_sk) = gen_keypair();
        let connection_id = 42;

        relay.links.write()[connection_id as usize - 16] = Some(Link::new(existing_pk));

        let connect_notification = Packet::ConnectNotification(ConnectNotification {
            connection_id,
        });

        relay.handle_packet(connect_notification).wait().unwrap();

        let link = relay.links.read()[connection_id as usize - 16].unwrap();

        assert_eq!(link.pk, existing_pk);
        assert_eq!(link.status, LinkStatus::Online);
    }

    #[test]
    fn handle_connect_notification_unexpected() {
        let (_incoming_rx, _outgoing_rx, relay) = create_relay();

        let connection_id = 42;
        let connect_notification = Packet::ConnectNotification(ConnectNotification {
            connection_id,
        });

        assert!(relay.handle_packet(connect_notification).wait().is_err());

        assert!(relay.links.read()[connection_id as usize - 16].is_none());
    }

    #[test]
    fn handle_disconnect_notification() {
        let (_incoming_rx, _outgoing_rx, relay) = create_relay();

        let (existing_pk, _existing_sk) = gen_keypair();
        let connection_id = 42;

        relay.links.write()[connection_id as usize - 16] = Some(Link {
            pk: existing_pk,
            status: LinkStatus::Online,
        });

        let disconnect_notification = Packet::DisconnectNotification(DisconnectNotification {
            connection_id,
        });

        relay.handle_packet(disconnect_notification).wait().unwrap();

        let link = relay.links.read()[connection_id as usize - 16].unwrap();

        assert_eq!(link.pk, existing_pk);
        assert_eq!(link.status, LinkStatus::Registered);
    }

    #[test]
    fn handle_disconnect_notification_unexpected() {
        let (_incoming_rx, _outgoing_rx, relay) = create_relay();

        let connection_id = 42;
        let disconnect_notification = Packet::DisconnectNotification(DisconnectNotification {
            connection_id,
        });

        assert!(relay.handle_packet(disconnect_notification).wait().is_err());

        assert!(relay.links.read()[connection_id as usize - 16].is_none());
    }

    #[test]
    fn handle_ping_request() {
        let (_incoming_rx, outgoing_rx, relay) = create_relay();

        let ping_id = 42;
        let ping_request = Packet::PingRequest(PingRequest {
            ping_id
        });

        relay.handle_packet(ping_request).wait().unwrap();

        let packet = unpack!(outgoing_rx.into_future().wait().unwrap().0.unwrap(), Packet::PongResponse);

        assert_eq!(packet.ping_id, ping_id);
    }

    #[test]
    fn handle_pong_response() {
        let (_incoming_rx, _outgoing_rx, relay) = create_relay();

        let ping_id = 42;
        let pong_response = Packet::PongResponse(PongResponse {
            ping_id
        });

        relay.handle_packet(pong_response).wait().unwrap();
    }

    #[test]
    fn handle_oob_send() {
        let (_incoming_rx, _outgoing_rx, relay) = create_relay();

        let oob_send = Packet::OobSend(OobSend {
            destination_pk: gen_keypair().0,
            data: vec![42; 123],
        });

        assert!(relay.handle_packet(oob_send).wait().is_err());
    }

    #[test]
    fn handle_oob_receive() {
        let (incoming_rx, _outgoing_rx, relay) = create_relay();

        let sender_pk = gen_keypair().0;
        let data = vec![42; 123];
        let oob_receive = Packet::OobReceive(OobReceive {
            sender_pk,
            data: data.clone(),
        });

        relay.handle_packet(oob_receive).wait().unwrap();

        let (relay_pk, packet) = incoming_rx.into_future().wait().unwrap().0.unwrap();
        let (received_pk, received_data) = unpack!(packet, IncomingPacket::Oob[pk, data]);

        assert_eq!(relay_pk, relay.pk);
        assert_eq!(received_pk, sender_pk);
        assert_eq!(received_data, data);
    }

    #[test]
    fn handle_data() {
        let (incoming_rx, _outgoing_rx, relay) = create_relay();

        let (sender_pk, _sender_sk) = gen_keypair();
        let connection_id = 42;

        relay.links.write()[connection_id as usize - 16] = Some(Link {
            pk: sender_pk,
            status: LinkStatus::Online,
        });

        let data = vec![42; 123];
        let data_packet = Packet::Data(Data {
            connection_id,
            data: data.clone(),
        });

        relay.handle_packet(data_packet).wait().unwrap();

        let (relay_pk, packet) = incoming_rx.into_future().wait().unwrap().0.unwrap();
        let (received_pk, received_data) = unpack!(packet, IncomingPacket::Data[pk, data]);

        assert_eq!(relay_pk, relay.pk);
        assert_eq!(received_pk, sender_pk);
        assert_eq!(received_data, data);
    }

    #[test]
    fn handle_data_unexpected() {
        let (incoming_rx, _outgoing_rx, relay) = create_relay();

        let data_packet = Packet::Data(Data {
            connection_id: 42,
            data: vec![42; 123],
        });

        assert!(relay.handle_packet(data_packet).wait().is_err());

        // Necessary to drop tx so that rx.collect() can be finished
        drop(relay);

        assert!(incoming_rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn handle_onion_request() {
        let (_incoming_rx, _outgoing_rx, relay) = create_relay();

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

        assert!(relay.handle_packet(onion_request).wait().is_err());
    }

    #[test]
    fn handle_onion_response() {
        let (incoming_rx, _outgoing_rx, relay) = create_relay();

        let payload = InnerOnionResponse::OnionDataResponse(OnionDataResponse {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123]
        });
        let onion_response = Packet::OnionResponse(OnionResponse {
            payload: payload.clone(),
        });

        relay.handle_packet(onion_response).wait().unwrap();

        let (relay_pk, packet) = incoming_rx.into_future().wait().unwrap().0.unwrap();
        let received_payload = unpack!(packet, IncomingPacket::Onion);

        assert_eq!(relay_pk, relay.pk);
        assert_eq!(received_payload, payload);
    }

    #[test]
    fn send_data() {
        let (_incoming_rx, outgoing_rx, relay) = create_relay();

        let (destination_pk, _destination_sk) = gen_keypair();
        let data = vec![42; 123];

        let connection_id = 42;
        relay.pk_to_id.write().insert(destination_pk, connection_id);
        relay.links.write()[connection_id as usize - 16] = Some(Link {
            pk: destination_pk,
            status: LinkStatus::Online,
        });

        relay.send_data(destination_pk, data.clone()).wait().unwrap();

        let packet = unpack!(outgoing_rx.into_future().wait().unwrap().0.unwrap(), Packet::Data);

        assert_eq!(packet.connection_id, connection_id);
        assert_eq!(packet.data, data);
    }

    #[test]
    fn send_data_not_linked() {
        let (_incoming_rx, outgoing_rx, relay) = create_relay();

        let (destination_pk, _destination_sk) = gen_keypair();
        let data = vec![42; 123];

        assert!(relay.send_data(destination_pk, data.clone()).wait().is_err());

        // Necessary to drop tx so that rx.collect() can be finished
        drop(relay);

        assert!(outgoing_rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn send_data_not_online() {
        let (_incoming_rx, outgoing_rx, relay) = create_relay();

        let (destination_pk, _destination_sk) = gen_keypair();
        let data = vec![42; 123];

        let connection_id = 42;
        relay.pk_to_id.write().insert(destination_pk, connection_id);
        relay.links.write()[connection_id as usize - 16] = Some(Link::new(destination_pk));

        assert!(relay.send_data(destination_pk, data.clone()).wait().is_err());

        // Necessary to drop tx so that rx.collect() can be finished
        drop(relay);

        assert!(outgoing_rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn send_oob() {
        let (_incoming_rx, outgoing_rx, relay) = create_relay();

        let (destination_pk, _destination_sk) = gen_keypair();
        let data = vec![42; 123];

        relay.send_oob(destination_pk, data.clone()).wait().unwrap();

        let packet = unpack!(outgoing_rx.into_future().wait().unwrap().0.unwrap(), Packet::OobSend);

        assert_eq!(packet.destination_pk, destination_pk);
        assert_eq!(packet.data, data);
    }

    #[test]
    fn send_onion() {
        let (_incoming_rx, outgoing_rx, relay) = create_relay();

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

        relay.send_onion(onion_request.clone()).wait().unwrap();

        let packet = unpack!(outgoing_rx.into_future().wait().unwrap().0.unwrap(), Packet::OnionRequest);

        assert_eq!(packet, onion_request);
    }

    #[test]
    fn add_connection() {
        let (_incoming_rx, outgoing_rx, relay) = create_relay();

        let (connection_pk, _connection_sk) = gen_keypair();

        relay.add_connection(connection_pk).wait().unwrap();

        let (packet, outgoing_rx) = outgoing_rx.into_future().wait().unwrap();
        let packet = unpack!(packet.unwrap(), Packet::RouteRequest);

        assert_eq!(packet.pk, connection_pk);

        // RouteRequest shouldn't be sent again after we add the same connection
        relay.add_connection(connection_pk).wait().unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(relay);

        assert!(outgoing_rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn remove_connection() {
        let (_incoming_rx, outgoing_rx, relay) = create_relay();

        let (connection_pk, _connection_sk) = gen_keypair();
        let connection_id = 42;

        relay.connections.write().insert(connection_pk);
        relay.links.write()[connection_id as usize - 16] = Some(Link::new(connection_pk));
        relay.pk_to_id.write().insert(connection_pk, connection_id);

        relay.remove_connection(connection_pk).wait().unwrap();

        let packet = unpack!(outgoing_rx.into_future().wait().unwrap().0.unwrap(), Packet::DisconnectNotification);

        assert_eq!(packet.connection_id, connection_id);
    }

    #[test]
    fn remove_connection_no_connection() {
        let (_incoming_rx, _outgoing_rx, relay) = create_relay();

        let (connection_pk, _connection_sk) = gen_keypair();

        assert!(relay.remove_connection(connection_pk).wait().is_err());
    }

    #[test]
    fn remove_connection_no_link() {
        let (_incoming_rx, outgoing_rx, relay) = create_relay();

        let (connection_pk, _connection_sk) = gen_keypair();

        relay.connections.write().insert(connection_pk);

        relay.remove_connection(connection_pk).wait().unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(relay);

        assert!(outgoing_rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn disconnect() {
        let (_incoming_rx, _outgoing_rx, relay) = create_relay();

        assert!(relay.is_connected());
        assert!(!relay.is_disconnected());
        assert!(!relay.is_sleeping());

        relay.disconnect();

        assert!(!relay.is_connected());
        assert!(relay.is_disconnected());
        assert!(!relay.is_sleeping());
    }

    #[test]
    fn sleep() {
        let (_incoming_rx, _outgoing_rx, relay) = create_relay();

        assert!(relay.is_connected());
        assert!(!relay.is_disconnected());
        assert!(!relay.is_sleeping());

        relay.sleep();

        assert!(!relay.is_connected());
        assert!(!relay.is_disconnected());
        assert!(relay.is_sleeping());
    }

    #[test]
    fn is_connection_online() {
        let (_incoming_rx, _outgoing_rx, relay) = create_relay();

        let (connection_pk, _connection_sk) = gen_keypair();
        let connection_id = 42;

        relay.links.write()[connection_id as usize - 16] = Some(Link::new(connection_pk));
        relay.pk_to_id.write().insert(connection_pk, connection_id);

        assert!(!relay.is_connection_online(connection_pk));

        relay.links.write()[connection_id as usize - 16] = Some(Link {
            pk: connection_pk,
            status: LinkStatus::Online,
        });

        assert!(relay.is_connection_online(connection_pk));
    }

    #[test]
    fn connections_count() {
        let (_incoming_rx, _outgoing_rx, relay) = create_relay();

        assert_eq!(relay.connections_count(), 0);

        let (connection_pk, _connection_sk) = gen_keypair();

        relay.connections.write().insert(connection_pk);

        assert_eq!(relay.connections_count(), 1);
    }

    #[test]
    fn is_connection_online_no_connection() {
        let (_incoming_rx, _outgoing_rx, relay) = create_relay();

        let (connection_pk, _connection_sk) = gen_keypair();

        assert!(!relay.is_connection_online(connection_pk));
    }

    #[test]
    fn spawn() {
        // waits until the relay becomes connected
        fn on_connected(relay: Relay) -> IoFuture<()> {
            let future = Interval::new(Instant::now(), Duration::from_millis(10))
                .map_err(|e| Error::new(ErrorKind::Other, e))
                .skip_while(move |_| match *relay.status.read() {
                    RelayStatus::Connecting => future::ok(true),
                    RelayStatus::Connected(_) => future::ok(false),
                    ref other => future::err(Error::new(ErrorKind::Other, format!("Invalid status: {:?}", other))),
                })
                .into_future()
                .map(|_| ())
                .map_err(|(e, _)| e);
            Box::new(future)
        }

        // waits until link with PublicKey becomes online
        fn on_online(relay: Relay, pk: PublicKey) -> IoFuture<()> {
            let future = Interval::new(Instant::now(), Duration::from_millis(10))
                .map_err(|e| Error::new(ErrorKind::Other, e))
                .skip_while(move |_|
                    if let Some(&connection_id) = relay.pk_to_id.read().get(&pk) {
                        let link = relay.links.read()[connection_id as usize - 16];
                        future::ok(link.map(|link| link.status) != Some(LinkStatus::Online))
                    } else {
                        future::ok(true)
                    }
                )
                .into_future()
                .map(|_| ())
                .map_err(|(e, _)| e);
            Box::new(future)
        }

        // run server
        let (server_pk, server_sk) = gen_keypair();
        let addr = "0.0.0.0:12347".parse().unwrap();
        let listener = TcpListener::bind(&addr).unwrap();
        let server = Server::new();
        let stats = Stats::new();
        let server_future = server.run(listener, server_sk, stats)
            .map_err(|e| Error::new(ErrorKind::Other, e.compat()));

        // run first client
        let (client_pk_1, client_sk_1) = gen_keypair();
        let (incoming_tx_1, incoming_rx_1) = mpsc::unbounded();
        let relay_1 = Relay::new(server_pk, addr, incoming_tx_1);
        // connection attempts should be set to 0 after successful connection
        set_connection_attempts(&relay_1, 3);
        let relay_future_1 = relay_1.clone().spawn(client_sk_1, client_pk_1);

        // run second client
        let (client_pk_2, client_sk_2) = gen_keypair();
        let (incoming_tx_2, incoming_rx_2) = mpsc::unbounded();
        let relay_2 = Relay::new(server_pk, addr, incoming_tx_2);
        // connection attempts should be set to 0 after successful connection
        set_connection_attempts(&relay_2, 3);
        let relay_future_2 = relay_2.clone().spawn(client_sk_2, client_pk_2);

        // add connection immediately
        let connection_future = relay_2.add_connection(client_pk_1);

        // wait until connections are established
        let relay_1_c = relay_1.clone();
        let relay_2_c = relay_2.clone();
        let on_connected_future = on_connected(relay_1.clone()).join(on_connected(relay_2.clone())).and_then(move |_| {
            assert!(relay_1_c.connected_time().is_some());
            assert!(relay_2_c.connected_time().is_some());
            assert_eq!(relay_1_c.connection_attempts(), 0);
            assert_eq!(relay_2_c.connection_attempts(), 0);
            // add connection when relay is connected
            relay_1_c.add_connection(client_pk_2)
        });

        let data_1 = vec![42; 123];
        let data_2 = vec![43; 123];

        // wait until links become online
        let relay_1_c = relay_1.clone();
        let relay_2_c = relay_2.clone();
        let data_1_c = data_1.clone();
        let data_2_c = data_2.clone();
        let on_online_future = on_online(relay_1.clone(), client_pk_2).join(on_online(relay_2.clone(), client_pk_1))
            // and then send data packets to each other
            .and_then(move |_| relay_1_c.send_data(client_pk_2, data_1_c))
            .and_then(move |_| relay_2_c.send_data(client_pk_1, data_2_c))
            // and then get them
            .and_then(move |_| incoming_rx_1.map_err(|()| unreachable!("rx can't fail")).into_future().map(move |(packet, _)| {
                let (relay_pk, packet) = packet.unwrap();
                let (received_pk, received_data) = unpack!(packet, IncomingPacket::Data[pk, data]);
                assert_eq!(relay_pk, server_pk);
                assert_eq!(received_pk, client_pk_2);
                assert_eq!(received_data, data_2);
                ()
            }).map_err(|(e, _)| e))
            .and_then(move |_| incoming_rx_2.map_err(|()| unreachable!("rx can't fail")).into_future().map(move |(packet, _)| {
                let (relay_pk, packet) = packet.unwrap();
                let (received_pk, received_data) = unpack!(packet, IncomingPacket::Data[pk, data]);
                assert_eq!(relay_pk, server_pk);
                assert_eq!(received_pk, client_pk_1);
                assert_eq!(received_data, data_1);
                ()
            }).map_err(|(e, _)| e))
            .map(move |_| {
                // tokio runtime won't become idle until we drop the connections
                relay_1.disconnect();
                relay_2.disconnect();
                ()
            });

        let future = relay_future_1
            .join5(relay_future_2, connection_future, on_connected_future, on_online_future)
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
