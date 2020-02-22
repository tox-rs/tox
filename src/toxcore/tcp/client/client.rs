use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use failure::Fail;
use futures::{future, Future, FutureExt, TryFutureExt, StreamExt, SinkExt};
use futures::future::Either;
use futures::channel::mpsc;
use parking_lot::RwLock;
use tokio_util::codec::Framed;
use tokio::net::TcpStream;

use crate::toxcore::crypto_core::*;
use crate::toxcore::onion::packet::InnerOnionResponse;
use crate::toxcore::stats::Stats;
use crate::toxcore::tcp::codec::{Codec};
use crate::toxcore::tcp::connection_id::ConnectionId;
use crate::toxcore::tcp::handshake::make_client_handshake;
use crate::toxcore::tcp::links::*;
use crate::toxcore::tcp::packet::*;
use crate::toxcore::time::*;
use crate::toxcore::tcp::client::errors::*;

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
    Data(PublicKey, DataPayload),
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
    pub async fn handle_packet(&self, packet: Packet) -> Result<(), HandlePacketError> {
        match packet {
            Packet::RouteRequest(packet) => self.handle_route_request(&packet).await,
            Packet::RouteResponse(packet) => self.handle_route_response(&packet).await,
            Packet::ConnectNotification(packet) => self.handle_connect_notification(&packet).await,
            Packet::DisconnectNotification(packet) => self.handle_disconnect_notification(&packet).await,
            Packet::PingRequest(packet) => self.handle_ping_request(&packet).await,
            Packet::PongResponse(packet) => self.handle_pong_response(&packet).await,
            Packet::OobSend(packet) => self.handle_oob_send(&packet).await,
            Packet::OobReceive(packet) => self.handle_oob_receive(packet).await,
            Packet::Data(packet) => self.handle_data(packet).await,
            Packet::OnionRequest(packet) => self.handle_onion_request(&packet).await,
            Packet::OnionResponse(packet) => self.handle_onion_response(packet).await,
        }
    }

    /// Send packet to this relay. If we are not connected to the relay an error
    /// will be returned.
    fn send_packet(&self, packet: Packet) -> impl Future<Output = Result<(), SendPacketError>> + Send {
        if let ClientStatus::Connected(ref tx) = *self.status.read() {
            let mut tx = tx.clone();
            Either::Left(async move {
                tx.send(packet).await
                    .map_err(|e| e.context(SendPacketErrorKind::SendTo).into())
            })
        } else {
            // Attempt to send packet to TCP relay with wrong status. For
            // instance it can happen when we received ping request from the
            // relay and right after that relay became sleeping so we are not
            // able to respond anymore.
            Either::Right(future::err(
                SendPacketErrorKind::WrongStatus.into()
            ))
        }
    }

    fn handle_route_request(&self, _packet: &RouteRequest) -> impl Future<Output = Result<(), HandlePacketError>> + Send {
        future::err(
            HandlePacketErrorKind::MustNotSend.into()
        )
    }

    fn handle_route_response(&self, packet: &RouteResponse) -> impl Future<Output = Result<(), HandlePacketError>> + Send {
        let index = if let Some(index) = packet.connection_id.index() {
            index
        } else {
            return future::err(
                HandlePacketErrorKind::InvalidConnectionId.into()
            )
        };

        if self.connections.read().contains(&packet.pk) {
            if self.links.write().insert_by_id(&packet.pk, index) {
                future::ok(())
            } else {
                future::err(
                    HandlePacketErrorKind::AlreadyLinked.into()
                )
            }
        } else {
            // in theory this can happen if we added connection and right
            // after that removed it
            // TODO: should it be handled better?
            future::err(
                HandlePacketErrorKind::UnexpectedRouteResponse.into()
            )
        }
    }

    fn handle_connect_notification(&self, packet: &ConnectNotification) -> impl Future<Output = Result<(), HandlePacketError>> + Send {
        let index = if let Some(index) = packet.connection_id.index() {
            index
        } else {
            return future::err(
                HandlePacketErrorKind::InvalidConnectionId.into()
            )
        };

        if self.links.write().upgrade(index) {
            future::ok(())
        } else {
            future::err(
                HandlePacketErrorKind::AlreadyLinked.into()
            )
        }
    }

    fn handle_disconnect_notification(&self, packet: &DisconnectNotification) -> impl Future<Output = Result<(), HandlePacketError>> + Send {
        let index = if let Some(index) = packet.connection_id.index() {
            index
        } else {
            return future::err(
                HandlePacketErrorKind::InvalidConnectionId.into()
            )
        };

        if self.links.write().downgrade(index) {
            future::ok(())
        } else {
            future::err(
                HandlePacketErrorKind::AlreadyLinked.into()
            )
        }
    }

    fn handle_ping_request(&self, packet: &PingRequest) -> impl Future<Output = Result<(), HandlePacketError>> + Send {
        self.send_packet(Packet::PongResponse(
            PongResponse { ping_id: packet.ping_id }
        )).map_err(|e| e.context(HandlePacketErrorKind::SendTo).into())
    }

    fn handle_pong_response(&self, _packet: &PongResponse) -> impl Future<Output = Result<(), HandlePacketError>> + Send {
        // TODO check ping_id
        future::ok(())
    }

    fn handle_oob_send(&self, _packet: &OobSend) -> impl Future<Output = Result<(), HandlePacketError>> + Send {
        future::err(
            HandlePacketErrorKind::MustNotSend.into()
        )
    }

    fn handle_oob_receive(&self, packet: OobReceive) -> impl Future<Output = Result<(), HandlePacketError>> + Send {
        let mut tx = self.incoming_tx.clone();
        let msg = (
            self.pk,
            IncomingPacket::Oob(packet.sender_pk, packet.data)
        );

        async move {
            tx.send(msg).await
                .map_err(|e| e.context(HandlePacketErrorKind::SendTo).into())
        }
    }

    fn handle_data(&self, packet: Data) -> impl Future<Output = Result<(), HandlePacketError>> + Send {
        let index = if let Some(index) = packet.connection_id.index() {
            index
        } else {
            return Either::Left( future::err(
                HandlePacketErrorKind::InvalidConnectionId.into()
            ))
        };

        let links = self.links.read();
        if let Some(link) = links.by_id(index) {
            let mut tx = self.incoming_tx.clone();
            let msg = (
                self.pk,
                IncomingPacket::Data(link.pk, packet.data)
            );

            Either::Right(async move {
                tx.send(msg).await
                    .map_err(|e| e.context(HandlePacketErrorKind::SendTo).into())
            })
        } else {
            Either::Left( future::err(
                HandlePacketErrorKind::AlreadyLinked.into()
            ))
        }
    }

    fn handle_onion_request(&self, _packet: &OnionRequest) -> impl Future<Output = Result<(), HandlePacketError>> + Send {
        future::err(
            HandlePacketErrorKind::MustNotSend.into()
        )
    }

    fn handle_onion_response(&self, packet: OnionResponse) -> impl Future<Output = Result<(), HandlePacketError>> + Send {
        let mut tx = self.incoming_tx.clone();
        let msg = (
            self.pk,
            IncomingPacket::Onion(packet.payload)
        );

        async move {
            tx.send(msg).await
                .map_err(|e| e.context(HandlePacketErrorKind::SendTo).into())
        }
    }

    /// Spawn a connection to this TCP relay if it is not connected already. The
    /// connection is spawned via `tokio::spawn` so the result future will be
    /// completed after first poll.
    async fn spawn_inner(self, dht_sk: SecretKey, dht_pk: PublicKey) -> Result<(), SpawnError> { // TODO: send pings periodically
        let relay_pk = self.pk;
        match *self.status.write() {
            ref mut status @ ClientStatus::Disconnected
            | ref mut status @ ClientStatus::Sleeping =>
                *status = ClientStatus::Connecting,
            _ => return Ok(()),
        }

        let socket = TcpStream::connect(&self.addr).await
            .map_err(|e| SpawnError::from(e.context(SpawnErrorKind::Io)))?;

        let (socket, channel) =
            make_client_handshake(socket, &dht_pk, &dht_sk, &relay_pk).await
                .map_err(|e| SpawnError::from(e.context(SpawnErrorKind::Io)))?;

        let stats = Stats::new();
        let secure_socket =
            Framed::new(socket, Codec::new(channel, stats));
        let (mut to_server, mut from_server) =
            secure_socket.split();
        let (to_server_tx, to_server_rx) =
            mpsc::channel(CLIENT_CHANNEL_SIZE);

        match *self.status.write() {
            ref mut status @ ClientStatus::Connecting =>
                *status = ClientStatus::Connected(to_server_tx),
            _ => return Ok(()),
        }

        *self.connection_attempts.write() = 0;
        *self.connected_time.write() = Some(clock_now());

        let route_requests = async {
            self.send_route_requests().await
                .map_err(|e|
                    SpawnError::from(e.context(SpawnErrorKind::SendTo))
                )
        };

        let mut to_server_rx = to_server_rx.map(Ok);
        let writer = to_server
            .send_all(&mut to_server_rx)
            .map_err(|e|
                SpawnError::from(e.context(SpawnErrorKind::Encode))
            );

        let reader = async {
            while let Some(packet) = from_server.next().await {
                let packet = packet
                    .map_err(|e|
                        SpawnError::from(e.context(SpawnErrorKind::ReadSocket))
                    )?;
                self.handle_packet(packet).await
                    .map_err(|e|
                        SpawnError::from(e.context(SpawnErrorKind::HandlePacket))
                    )?
            }

            Result::<(), SpawnError>::Ok(())
        };

        let rw = async move {
            futures::select! {
                res = reader.fuse() => res,
                res = writer.fuse() => res,
            }
        };

        futures::try_join!(rw, route_requests).map(drop)
    }

    async fn run(self, dht_sk: SecretKey, dht_pk: PublicKey) -> Result<(), SpawnError> {
        let self_c = self.clone();
        let future = self.spawn_inner(dht_sk, dht_pk);

        future
            .then(move |res| {
                match *self_c.status.write() {
                    ClientStatus::Sleeping => { },
                    ref mut status => *status = ClientStatus::Disconnected,
                }
                if res.is_err() {
                    let mut connection_attempts = self_c.connection_attempts.write();
                    *connection_attempts = connection_attempts.saturating_add(1);
                }
                *self_c.connected_time.write() = None;
                self_c.links.write().clear();
                future::ready(res)
            })
            .map_err(|e| {
                error!("TCP relay connection error: {}", e);
                e
            })
            .await
    }

    /// Spawn a connection to this TCP relay if it is not connected already. The
    /// connection is spawned via `tokio::spawn` so the result future will be
    /// completed after first poll.
    pub async fn spawn(self, dht_sk: SecretKey, dht_pk: PublicKey) -> Result<(), SpawnError> { // TODO: send pings periodically
        tokio::spawn(self.run(dht_sk, dht_pk));
        Ok(())
    }

    /// Send `RouteRequest` packet with specified `PublicKey`.
    fn send_route_request(&self, pk: PublicKey) -> impl Future<Output = Result<(), SendPacketError>> + Send {
        self.send_packet(Packet::RouteRequest(RouteRequest {
            pk
        }))
    }

    /// Send `RouteRequest` packets for all nodes we should be connected to via
    /// the relay. It should be done for every fresh connection to the relay.
    fn send_route_requests(&self) -> impl Future<Output = Result<(), SendPacketError>> + Send {
        let connections = self.connections.read();
        let futures = connections.iter()
            .map(|&pk| self.send_route_request(pk))
            .collect::<Vec<_>>();
        future::try_join_all(futures).map_ok(drop)
    }

    /// Send `Data` packet to a node via relay.
    pub fn send_data(&self, destination_pk: PublicKey, data: DataPayload) -> impl Future<Output = Result<(), SendPacketError>> + Send {
        // it is important that the result future succeeds only if packet is
        // sent since we take only one successful future from several relays
        // when send data packet
        let links = self.links.read();
        if let Some(index) = links.id_by_pk(&destination_pk) {
            if links.by_id(index).map(|link| link.status) == Some(LinkStatus::Online) {
                Either::Left(self.send_packet(Packet::Data(Data {
                    connection_id: ConnectionId::from_index(index),
                    data,
                })))
            } else {
                Either::Right( future::err(
                    SendPacketErrorKind::NotOnline.into()
                ))
            }
        } else {
            Either::Right( future::err(
                SendPacketErrorKind::NotLinked.into()
            ))
        }
    }

    /// Send `OobSend` packet to a node via relay.
    pub fn send_oob(&self, destination_pk: PublicKey, data: Vec<u8>) -> impl Future<Output = Result<(), SendPacketError>> + Send {
        self.send_packet(Packet::OobSend(OobSend {
            destination_pk,
            data,
        }))
    }

    /// Send `OnionRequest` packet to the relay.
    pub fn send_onion(&self, onion_request: OnionRequest) -> impl Future<Output = Result<(), SendPacketError>> + Send {
        self.send_packet(Packet::OnionRequest(onion_request))
    }

    /// Add connection to a friend via this relay. If we are connected to the
    /// relay `RouteRequest` packet will be sent. Also this packet will be sent
    /// when fresh connection is established.
    pub fn add_connection(&self, pk: PublicKey) -> impl Future<Output = Result<(), SendPacketError>> + Send {
        if self.connections.write().insert(pk) {
            // ignore sending errors if we are not connected to the relay
            // in this case RouteRequest will be sent after connection
            Either::Left(self.send_route_request(pk).then(|_| future::ok(())))
        } else {
            Either::Right(future::ok(()))
        }
    }

    /// Remove connection to a friend via this relay. If we are connected to the
    /// relay and linked to the friend `DisconnectNotification` packet will be
    /// sent.
    pub fn remove_connection(&self, pk: PublicKey) -> impl Future<Output = Result<(), SendPacketError>> + Send {
        if self.connections.write().remove(&pk) {
            let mut links = self.links.write();
            if let Some(index) = links.id_by_pk(&pk) {
                links.take(index);
                Either::Left(self.send_packet(Packet::DisconnectNotification(DisconnectNotification {
                    connection_id: ConnectionId::from_index(index),
                })).then(|_| future::ok(())))
            } else {
                // the link may not exist if we delete the connection before we
                // receive RouteResponse packet
                // TODO: should it be handled better?
                Either::Right(future::ok(()))
            }
        } else {
            Either::Right( future::err(
                SendPacketErrorKind::NoSuchConnection.into()
            ))
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
    use failure::Error;
    use std::io::{Error as IoError, ErrorKind as IoErrorKind};

    use tokio::net::TcpListener;

    use crate::toxcore::dht::packet::CryptoData;
    use crate::toxcore::ip_port::*;
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

    #[tokio::test]
    async fn handle_route_request() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let route_request = Packet::RouteRequest(RouteRequest {
            pk: gen_keypair().0,
        });

        let error = client.handle_packet(route_request).await.err().unwrap();
        assert_eq!(*error.kind(), HandlePacketErrorKind::MustNotSend);
    }

    #[tokio::test]
    async fn handle_route_response() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let (new_pk, _new_sk) = gen_keypair();
        let index = 42;

        client.connections.write().insert(new_pk);

        let route_response = Packet::RouteResponse(RouteResponse {
            connection_id: ConnectionId::from_index(index),
            pk: new_pk,
        });

        client.handle_packet(route_response).await.unwrap();

        let link = client.links.read().by_id(index).cloned().unwrap();

        assert_eq!(link.pk, new_pk);
        assert_eq!(link.status, LinkStatus::Registered);
    }

    #[tokio::test]
    async fn handle_route_response_occupied() {
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

        assert!(client.handle_packet(route_response).await.is_err());

        let link = client.links.read().by_id(index).cloned().unwrap();

        assert_eq!(link.pk, existing_pk);
        assert_eq!(link.status, LinkStatus::Registered);
    }

    #[tokio::test]
    async fn handle_route_response_unexpected() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let index = 42;
        let route_response = Packet::RouteResponse(RouteResponse {
            connection_id: ConnectionId::from_index(index),
            pk: gen_keypair().0,
        });

        let error = client.handle_packet(route_response).await.err().unwrap();
        assert_eq!(*error.kind(), HandlePacketErrorKind::UnexpectedRouteResponse);

        assert!(client.links.read().by_id(index).is_none());
    }

    #[tokio::test]
    async fn handle_route_response_0() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let route_response = Packet::RouteResponse(RouteResponse {
            connection_id: ConnectionId::zero(),
            pk: gen_keypair().0,
        });

        let error = client.handle_packet(route_response).await.err().unwrap();
        assert_eq!(*error.kind(), HandlePacketErrorKind::InvalidConnectionId);
    }

    #[tokio::test]
    async fn handle_connect_notification() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let (existing_pk, _existing_sk) = gen_keypair();
        let index = 42;

        client.links.write().insert_by_id(&existing_pk, index);

        let connect_notification = Packet::ConnectNotification(ConnectNotification {
            connection_id: ConnectionId::from_index(index),
        });

        client.handle_packet(connect_notification).await.unwrap();

        let link = client.links.read().by_id(index).cloned().unwrap();

        assert_eq!(link.pk, existing_pk);
        assert_eq!(link.status, LinkStatus::Online);
    }

    #[tokio::test]
    async fn handle_connect_notification_unexpected() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let index = 42;
        let connect_notification = Packet::ConnectNotification(ConnectNotification {
            connection_id: ConnectionId::from_index(index),
        });

        let error = client.handle_packet(connect_notification).await.err().unwrap();
        assert_eq!(*error.kind(), HandlePacketErrorKind::AlreadyLinked);

        assert!(client.links.read().by_id(index).is_none());
    }

    #[tokio::test]
    async fn handle_connect_notification_0() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let connect_notification = Packet::ConnectNotification(ConnectNotification {
            connection_id: ConnectionId::zero(),
        });

        let error = client.handle_packet(connect_notification).await.err().unwrap();
        assert_eq!(*error.kind(), HandlePacketErrorKind::InvalidConnectionId);
    }

    #[tokio::test]
    async fn handle_disconnect_notification() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let (existing_pk, _existing_sk) = gen_keypair();
        let index = 42;

        client.links.write().insert_by_id(&existing_pk, index);
        client.links.write().upgrade(index);

        let disconnect_notification = Packet::DisconnectNotification(DisconnectNotification {
            connection_id: ConnectionId::from_index(index),
        });

        client.handle_packet(disconnect_notification).await.unwrap();

        let link = client.links.read().by_id(index).cloned().unwrap();

        assert_eq!(link.pk, existing_pk);
        assert_eq!(link.status, LinkStatus::Registered);
    }

    #[tokio::test]
    async fn handle_disconnect_notification_unexpected() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let index = 42;
        let disconnect_notification = Packet::DisconnectNotification(DisconnectNotification {
            connection_id: ConnectionId::from_index(index),
        });

        let error = client.handle_packet(disconnect_notification).await.err().unwrap();
        assert_eq!(*error.kind(), HandlePacketErrorKind::AlreadyLinked);

        assert!(client.links.read().by_id(index).is_none());
    }

    #[tokio::test]
    async fn handle_disconnect_notification_0() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let disconnect_notification = Packet::DisconnectNotification(DisconnectNotification {
            connection_id: ConnectionId::zero(),
        });

        let error = client.handle_packet(disconnect_notification).await.err().unwrap();
        assert_eq!(*error.kind(), HandlePacketErrorKind::InvalidConnectionId);
    }

    #[tokio::test]
    async fn handle_ping_request() {
        let (_incoming_rx, outgoing_rx, client) = create_client();

        let ping_id = 42;
        let ping_request = Packet::PingRequest(PingRequest {
            ping_id
        });

        client.handle_packet(ping_request).await.unwrap();

        let packet = unpack!(outgoing_rx.into_future().await.0.unwrap(), Packet::PongResponse);

        assert_eq!(packet.ping_id, ping_id);
    }

    #[tokio::test]
    async fn handle_pong_response() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let ping_id = 42;
        let pong_response = Packet::PongResponse(PongResponse {
            ping_id
        });

        client.handle_packet(pong_response).await.unwrap();
    }

    #[tokio::test]
    async fn handle_oob_send() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let oob_send = Packet::OobSend(OobSend {
            destination_pk: gen_keypair().0,
            data: vec![42; 123],
        });

        let error = client.handle_packet(oob_send).await.err().unwrap();
        assert_eq!(*error.kind(), HandlePacketErrorKind::MustNotSend);
    }

    #[tokio::test]
    async fn handle_oob_receive() {
        let (incoming_rx, _outgoing_rx, client) = create_client();

        let sender_pk = gen_keypair().0;
        let data = vec![42; 123];
        let oob_receive = Packet::OobReceive(OobReceive {
            sender_pk,
            data: data.clone(),
        });

        client.handle_packet(oob_receive).await.unwrap();

        let (relay_pk, packet) = incoming_rx.into_future().await.0.unwrap();
        let (received_pk, received_data) = unpack!(packet, IncomingPacket::Oob[pk, data]);

        assert_eq!(relay_pk, client.pk);
        assert_eq!(received_pk, sender_pk);
        assert_eq!(received_data, data);
    }

    #[tokio::test]
    async fn handle_data() {
        let (incoming_rx, _outgoing_rx, client) = create_client();

        let (sender_pk, _sender_sk) = gen_keypair();
        let index = 42;

        client.links.write().insert_by_id(&sender_pk, index);
        client.links.write().upgrade(index);

        let data = DataPayload::CryptoData(CryptoData {
            nonce_last_bytes: 42,
            payload: vec![42; 123],
        });
        let data_packet = Packet::Data(Data {
            connection_id: ConnectionId::from_index(index),
            data: data.clone(),
        });

        client.handle_packet(data_packet).await.unwrap();

        let (relay_pk, packet) = incoming_rx.into_future().await.0.unwrap();
        let (received_pk, received_data) = unpack!(packet, IncomingPacket::Data[pk, data]);

        assert_eq!(relay_pk, client.pk);
        assert_eq!(received_pk, sender_pk);
        assert_eq!(received_data, data);
    }

    #[tokio::test]
    async fn handle_data_unexpected() {
        let (incoming_rx, _outgoing_rx, client) = create_client();

        let data_packet = Packet::Data(Data {
            connection_id: ConnectionId::from_index(42),
            data: DataPayload::CryptoData(CryptoData {
                nonce_last_bytes: 42,
                payload: vec![42; 123],
            }),
        });

        let error = client.handle_packet(data_packet).await.err().unwrap();
        assert_eq!(*error.kind(), HandlePacketErrorKind::AlreadyLinked);

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(incoming_rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn handle_data_0() {
        let (incoming_rx, _outgoing_rx, client) = create_client();

        let data_packet = Packet::Data(Data {
            connection_id: ConnectionId::zero(),
            data: DataPayload::CryptoData(CryptoData {
                nonce_last_bytes: 42,
                payload: vec![42; 123],
            }),
        });

        let error = client.handle_packet(data_packet).await.err().unwrap();
        assert_eq!(*error.kind(), HandlePacketErrorKind::InvalidConnectionId);

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(incoming_rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn handle_onion_request() {
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

        let error = client.handle_packet(onion_request).await.err().unwrap();
        assert_eq!(*error.kind(), HandlePacketErrorKind::MustNotSend);
    }

    #[tokio::test]
    async fn handle_onion_response() {
        let (incoming_rx, _outgoing_rx, client) = create_client();

        let payload = InnerOnionResponse::OnionDataResponse(OnionDataResponse {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123]
        });
        let onion_response = Packet::OnionResponse(OnionResponse {
            payload: payload.clone(),
        });

        client.handle_packet(onion_response).await.unwrap();

        let (relay_pk, packet) = incoming_rx.into_future().await.0.unwrap();
        let received_payload = unpack!(packet, IncomingPacket::Onion);

        assert_eq!(relay_pk, client.pk);
        assert_eq!(received_payload, payload);
    }

    #[tokio::test]
    async fn send_data() {
        let (_incoming_rx, outgoing_rx, client) = create_client();

        let (destination_pk, _destination_sk) = gen_keypair();
        let data = DataPayload::CryptoData(CryptoData {
            nonce_last_bytes: 42,
            payload: vec![42; 123],
        });

        let index = 42;
        client.links.write().insert_by_id(&destination_pk, index);
        client.links.write().upgrade(index);

        client.send_data(destination_pk, data.clone()).await.unwrap();

        let packet = unpack!(outgoing_rx.into_future().await.0.unwrap(), Packet::Data);

        assert_eq!(packet.connection_id, ConnectionId::from_index(index));
        assert_eq!(packet.data, data);
    }

    #[tokio::test]
    async fn send_data_not_linked() {
        let (_incoming_rx, outgoing_rx, client) = create_client();

        let (destination_pk, _destination_sk) = gen_keypair();
        let data = DataPayload::CryptoData(CryptoData {
            nonce_last_bytes: 42,
            payload: vec![42; 123],
        });

        let error = client.send_data(destination_pk, data.clone()).await.err().unwrap();
        assert_eq!(*error.kind(), SendPacketErrorKind::NotLinked);

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(outgoing_rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn send_data_not_online() {
        let (_incoming_rx, outgoing_rx, client) = create_client();

        let (destination_pk, _destination_sk) = gen_keypair();
        let data = DataPayload::CryptoData(CryptoData {
            nonce_last_bytes: 42,
            payload: vec![42; 123],
        });

        let connection_id = 42;
        client.links.write().insert_by_id(&destination_pk, connection_id - 16);

        let error = client.send_data(destination_pk, data.clone()).await.err().unwrap();
        assert_eq!(*error.kind(), SendPacketErrorKind::NotOnline);

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(outgoing_rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn send_oob() {
        let (_incoming_rx, outgoing_rx, client) = create_client();

        let (destination_pk, _destination_sk) = gen_keypair();
        let data = vec![42; 123];

        client.send_oob(destination_pk, data.clone()).await.unwrap();

        let packet = unpack!(outgoing_rx.into_future().await.0.unwrap(), Packet::OobSend);

        assert_eq!(packet.destination_pk, destination_pk);
        assert_eq!(packet.data, data);
    }

    #[tokio::test]
    async fn send_onion() {
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

        client.send_onion(onion_request.clone()).await.unwrap();

        let packet = unpack!(outgoing_rx.into_future().await.0.unwrap(), Packet::OnionRequest);

        assert_eq!(packet, onion_request);
    }

    #[tokio::test]
    async fn add_connection() {
        let (_incoming_rx, outgoing_rx, client) = create_client();

        let (connection_pk, _connection_sk) = gen_keypair();

        client.add_connection(connection_pk).await.unwrap();

        let (packet, outgoing_rx) = outgoing_rx.into_future().await;
        let packet = unpack!(packet.unwrap(), Packet::RouteRequest);

        assert_eq!(packet.pk, connection_pk);

        // RouteRequest shouldn't be sent again after we add the same connection
        client.add_connection(connection_pk).await.unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(outgoing_rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn remove_connection() {
        let (_incoming_rx, outgoing_rx, client) = create_client();

        let (connection_pk, _connection_sk) = gen_keypair();
        let index = 42;

        client.connections.write().insert(connection_pk);
        client.links.write().insert_by_id(&connection_pk, index);

        client.remove_connection(connection_pk).await.unwrap();

        let packet = unpack!(outgoing_rx.into_future().await.0.unwrap(), Packet::DisconnectNotification);

        assert_eq!(packet.connection_id, ConnectionId::from_index(index));
    }

    #[tokio::test]
    async fn remove_connection_no_connection() {
        let (_incoming_rx, _outgoing_rx, client) = create_client();

        let (connection_pk, _connection_sk) = gen_keypair();

        let error = client.remove_connection(connection_pk).await.err().unwrap();
        assert_eq!(*error.kind(), SendPacketErrorKind::NoSuchConnection);
    }

    #[tokio::test]
    async fn remove_connection_no_link() {
        let (_incoming_rx, outgoing_rx, client) = create_client();

        let (connection_pk, _connection_sk) = gen_keypair();

        client.connections.write().insert(connection_pk);

        client.remove_connection(connection_pk).await.unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(outgoing_rx.collect::<Vec<_>>().await.is_empty());
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

    #[tokio::test]
    async fn spawn() {
        // waits until the relay becomes connected
        async fn on_connected(client: Client) -> Result<(), Error> {
            let mut interval = tokio::time::interval(Duration::from_millis(10));

            while let Some(_) = interval.next().await {
                match *client.status.read() {
                    ClientStatus::Connecting => continue,
                    ClientStatus::Connected(_) => return Ok(()),
                    ref other => return Err(Error::from(IoError::new(IoErrorKind::Other, format!("Invalid status: {:?}", other)))),
                }
            }

            Ok(())
        }

        // waits until link with PublicKey becomes online
        async fn on_online(client: Client, pk: PublicKey) -> Result<(), Error> {
            let mut interval = tokio::time::interval(Duration::from_millis(10));

            while let Some(_) = interval.next().await {
                let links = client.links.read();
                if let Some(index) = links.id_by_pk(&pk) {
                    let status = links.by_id(index).map(|link| link.status);
                    if status == Some(LinkStatus::Online) { return Ok(()) }
                }
            }

            Ok(())
        }

        crypto_init().unwrap();
        // run server
        let (server_pk, server_sk) = gen_keypair();

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(&addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = Server::new();
        let stats = Stats::new();
        let server_future = server.run(listener, server_sk, stats, 2)
            .map_err(Error::from);
        tokio::spawn(server_future);

        // run first client
        let (client_pk_1, client_sk_1) = gen_keypair();
        let (incoming_tx_1, mut incoming_rx_1) = mpsc::unbounded();
        let client_1 = Client::new(server_pk, addr, incoming_tx_1);
        // connection attempts should be set to 0 after successful connection
        set_connection_attempts(&client_1, 3);
        client_1.clone().spawn(client_sk_1, client_pk_1).await.unwrap();

        // run second client
        let (client_pk_2, client_sk_2) = gen_keypair();
        let (incoming_tx_2, mut incoming_rx_2) = mpsc::unbounded();
        let client_2 = Client::new(server_pk, addr, incoming_tx_2);
        // connection attempts should be set to 0 after successful connection
        set_connection_attempts(&client_2, 3);
        client_2.clone().spawn(client_sk_2, client_pk_2).await.unwrap();

        // wait until connections are established
        on_connected(client_1.clone()).await.unwrap();
        on_connected(client_2.clone()).await.unwrap();

        assert!(client_1.connected_time().is_some());
        assert!(client_2.connected_time().is_some());
        assert_eq!(client_1.connection_attempts(), 0);
        assert_eq!(client_2.connection_attempts(), 0);

        // add connections when relay is connected
        client_1.add_connection(client_pk_2).await.unwrap();
        client_2.add_connection(client_pk_1).await.unwrap();

        // wait until links become online
        on_online(client_1.clone(), client_pk_2).await.unwrap();
        on_online(client_2.clone(), client_pk_1).await.unwrap();

        let data_1 = DataPayload::CryptoData(CryptoData {
            nonce_last_bytes: 42,
            payload: vec![42; 123],
        });
        let data_2 = DataPayload::CryptoData(CryptoData {
            nonce_last_bytes: 42,
            payload: vec![43; 123],
        });
        client_1.send_data(client_pk_2, data_1.clone()).await.unwrap();
        client_2.send_data(client_pk_1, data_2.clone()).await.unwrap();

        let packet1 = incoming_rx_1.next().await;
        let (relay_pk, packet) = packet1.unwrap();
        {
            let (received_pk, received_data) = unpack!(packet, IncomingPacket::Data[pk, data]);

            assert_eq!(relay_pk, server_pk);
            assert_eq!(received_pk, client_pk_2);
            assert_eq!(received_data, data_2);
        }

        let packet2 = incoming_rx_2.next().await;
        let (relay_pk, packet) = packet2.unwrap();
        {
            let (received_pk, received_data) = unpack!(packet, IncomingPacket::Data[pk, data]);

            assert_eq!(relay_pk, server_pk);
            assert_eq!(received_pk, client_pk_1);
            assert_eq!(received_data, data_1);
        }
    }

    #[tokio::test]
    async fn run_unsuccessful() {
        // run server
        let (_server_pk, server_sk) = gen_keypair();

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut listener = TcpListener::bind(&addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = Server::new();
        let stats = Stats::new();
        let server_future = async {
            let connection = listener.incoming().next().await.unwrap().unwrap();
            server.run_connection(connection, server_sk, stats)
                .map_err(Error::from).await
        };

        // run a client with invalid server's pk
        let (client_pk_1, client_sk_1) = gen_keypair();
        let (invalid_server_pk, _invalid_server_sk) = gen_keypair();
        let (incoming_tx_1, _incoming_rx_1) = mpsc::unbounded();
        let client = Client::new(invalid_server_pk, addr, incoming_tx_1);
        let client_future = client.clone().run(client_sk_1, client_pk_1)
            .map_err(Error::from);

        let (server_res, client_res) = future::join(server_future.boxed(), client_future.boxed()).await;
        assert!(server_res.is_err()); // fail to process handshake
        assert!(client_res.is_err()); // fail to process handshake

        // connection_attempts should be increased
        assert_eq!(*client.connection_attempts.read(), 1);
    }
}
