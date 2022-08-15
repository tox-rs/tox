use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use futures::{FutureExt, TryFutureExt, StreamExt, SinkExt};
use futures::channel::mpsc;
use tokio_util::codec::Framed;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use tox_crypto::*;
use tox_packet::onion::InnerOnionResponse;
use crate::stats::Stats;
use crate::relay::codec::Codec;
use tox_packet::relay::connection_id::ConnectionId;
use crate::relay::handshake::make_client_handshake;
use crate::relay::links::*;
use tox_packet::relay::*;
use crate::time::*;
use crate::relay::client::errors::*;

/// Buffer size (in packets) for outgoing packets. This number shouldn't be high
/// to minimize latency. If some relay can't take more packets we can use
/// another relay. So it doesn't make much sense to buffer packets and wait for
/// the relay to send them.
const CLIENT_CHANNEL_SIZE: usize = 2;

/// Packet that can be received from a TCP relay and should be handled outside
/// of connections module.
#[derive(Debug, PartialEq, Eq, Clone)]
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
    async fn send_packet(&self, packet: Packet) -> Result<(), SendPacketError> {
        if let ClientStatus::Connected(ref tx) = *self.status.read().await {
            let mut tx = tx.clone();
            tx.send(packet).await
                .map_err(SendPacketError::SendTo)
        } else {
            // Attempt to send packet to TCP relay with wrong status. For
            // instance it can happen when we received ping request from the
            // relay and right after that relay became sleeping so we are not
            // able to respond anymore.
            Err(SendPacketError::WrongStatus)
        }
    }

    async fn handle_route_request(&self, _packet: &RouteRequest) -> Result<(), HandlePacketError> {
        Err(HandlePacketError::MustNotSend)
    }

    async fn handle_route_response(&self, packet: &RouteResponse) -> Result<(), HandlePacketError> {
        let index = if let Some(index) = packet.connection_id.index() {
            index
        } else {
            return Err(HandlePacketError::InvalidConnectionId)
        };

        if self.connections.read().await.contains(&packet.pk) {
            if self.links.write().await.insert_by_id(packet.pk.clone(), index) {
                Ok(())
            } else {
                Err(HandlePacketError::AlreadyLinked)
            }
        } else {
            // in theory this can happen if we added connection and right
            // after that removed it
            // TODO: should it be handled better?
            Err(HandlePacketError::UnexpectedRouteResponse)
        }
    }

    async fn handle_connect_notification(&self, packet: &ConnectNotification) -> Result<(), HandlePacketError> {
        let index = if let Some(index) = packet.connection_id.index() {
            index
        } else {
            return Err(HandlePacketError::InvalidConnectionId)
        };

        if self.links.write().await.upgrade(index) {
            Ok(())
        } else {
            Err(HandlePacketError::AlreadyLinked)
        }
    }

    async fn handle_disconnect_notification(&self, packet: &DisconnectNotification) -> Result<(), HandlePacketError> {
        let index = if let Some(index) = packet.connection_id.index() {
            index
        } else {
            return Err(HandlePacketError::InvalidConnectionId)
        };

        if (*self.links.write().await).downgrade(index) {
            Ok(())
        } else {
            Err(HandlePacketError::AlreadyLinked)
        }
    }

    async fn handle_ping_request(&self, packet: &PingRequest) -> Result<(), HandlePacketError> {
        self.send_packet(Packet::PongResponse(
            PongResponse { ping_id: packet.ping_id }
        )).await.map_err(HandlePacketError::SendPacket)
    }

    async fn handle_pong_response(&self, _packet: &PongResponse) -> Result<(), HandlePacketError> {
        // TODO check ping_id
        Ok(())
    }

    async fn handle_oob_send(&self, _packet: &OobSend) -> Result<(), HandlePacketError> {
        Err(HandlePacketError::MustNotSend)
    }

    async fn handle_oob_receive(&self, packet: OobReceive) -> Result<(), HandlePacketError> {
        let mut tx = self.incoming_tx.clone();
        let msg = (
            self.pk.clone(),
            IncomingPacket::Oob(packet.sender_pk, packet.data)
        );

        tx.send(msg).await
            .map_err(HandlePacketError::SendTo)
    }

    async fn handle_data(&self, packet: Data) -> Result<(), HandlePacketError> {
        let index = if let Some(index) = packet.connection_id.index() {
            index
        } else {
            return Err(HandlePacketError::InvalidConnectionId)
        };

        let links = self.links.read().await;
        if let Some(link) = links.by_id(index) {
            let mut tx = self.incoming_tx.clone();
            let msg = (
                self.pk.clone(),
                IncomingPacket::Data(link.pk.clone(), packet.data)
            );

            tx.send(msg).await
                .map_err(HandlePacketError::SendTo)
        } else {
            Err(HandlePacketError::AlreadyLinked)
        }
    }

    async fn handle_onion_request(&self, _packet: &OnionRequest) -> Result<(), HandlePacketError> {
        Err(HandlePacketError::MustNotSend)
    }

    async fn handle_onion_response(&self, packet: OnionResponse) -> Result<(), HandlePacketError> {
        let mut tx = self.incoming_tx.clone();
        let msg = (
            self.pk.clone(),
            IncomingPacket::Onion(packet.payload)
        );

        tx.send(msg).await
            .map_err(HandlePacketError::SendTo)
    }

    /// Spawn a connection to this TCP relay if it is not connected already. The
    /// connection is spawned via `tokio::spawn` so the result future will be
    /// completed after first poll.
    async fn spawn_inner(&self, dht_sk: SecretKey, dht_pk: PublicKey) -> Result<(), SpawnError> { // TODO: send pings periodically
        let relay_pk = self.pk.clone();
        match *self.status.write().await {
            ref mut status @ ClientStatus::Disconnected
            | ref mut status @ ClientStatus::Sleeping =>
                *status = ClientStatus::Connecting,
            _ => return Ok(()),
        }

        let socket = TcpStream::connect(&self.addr).await
            .map_err(SpawnError::Io)?;

        let (socket, channel) =
            make_client_handshake(socket, &dht_pk, &dht_sk, &relay_pk).await
                .map_err(SpawnError::Io)?;

        let stats = Stats::new();
        let secure_socket =
            Framed::new(socket, Codec::new(channel, stats));
        let (mut to_server, mut from_server) =
            secure_socket.split();
        let (to_server_tx, to_server_rx) =
            mpsc::channel(CLIENT_CHANNEL_SIZE);

        match *self.status.write().await {
            ref mut status @ ClientStatus::Connecting =>
                *status = ClientStatus::Connected(to_server_tx),
            _ => return Ok(()),
        }

        *self.connection_attempts.write().await = 0;
        *self.connected_time.write().await = Some(clock_now());

        self.send_route_requests().await
            .map_err(SpawnError::SendTo)?;

        let mut to_server_rx = to_server_rx.map(Ok);
        let writer = to_server
            .send_all(&mut to_server_rx)
            .map_err(SpawnError::Encode);

        let reader = async {
            while let Some(packet) = from_server.next().await {
                let packet = packet
                    .map_err(SpawnError::ReadSocket)?;
                self.handle_packet(packet).await
                    .map_err(SpawnError::HandlePacket)?;
            }

            Result::<(), SpawnError>::Ok(())
        };

        futures::select! {
            res = reader.fuse() => res,
            res = writer.fuse() => res,
        }
    }

    async fn run(&self, dht_sk: SecretKey, dht_pk: PublicKey) -> Result<(), SpawnError> {
        let result = self.spawn_inner(dht_sk, dht_pk).await;

        match *self.status.write().await {
            ClientStatus::Sleeping => { },
            ref mut status => *status = ClientStatus::Disconnected,
        }
        if let Err(ref e) = result {
            error!("TCP relay connection error: {}", e);
            let mut connection_attempts = self.connection_attempts.write().await;
            *connection_attempts = connection_attempts.saturating_add(1);
        }
        *self.connected_time.write().await = None;
        self.links.write().await.clear();

        result
    }

    /// Spawn a connection to this TCP relay if it is not connected already. The
    /// connection is spawned via `tokio::spawn` so the result future will be
    /// completed after first poll.
    pub async fn spawn(self, dht_sk: SecretKey, dht_pk: PublicKey) -> Result<(), SpawnError> { // TODO: send pings periodically
        tokio::spawn(async move {
            self.run(dht_sk, dht_pk).await
        });
        Ok(())
    }

    /// Send `RouteRequest` packet with specified `PublicKey`.
    async fn send_route_request(&self, pk: PublicKey) -> Result<(), SendPacketError> {
        self.send_packet(Packet::RouteRequest(RouteRequest {
            pk
        })).await
    }

    /// Send `RouteRequest` packets for all nodes we should be connected to via
    /// the relay. It should be done for every fresh connection to the relay.
    async fn send_route_requests(&self) -> Result<(), SendPacketError> {
        let connections = self.connections.read().await;
        for pk in connections.iter() {
            self.send_route_request(pk.clone()).await?;
        }
        Ok(())
    }

    /// Send `Data` packet to a node via relay.
    pub async fn send_data(&self, destination_pk: PublicKey, data: DataPayload) -> Result<(), SendPacketError> {
        // it is important that the result future succeeds only if packet is
        // sent since we take only one successful future from several relays
        // when send data packet
        let links = self.links.read().await;
        if let Some(index) = links.id_by_pk(&destination_pk) {
            if links.by_id(index).map(|link| link.status) == Some(LinkStatus::Online) {
                self.send_packet(Packet::Data(Data {
                    connection_id: ConnectionId::from_index(index),
                    data,
                })).await
            } else {
                Err(SendPacketError::NotOnline)
            }
        } else {
            Err(SendPacketError::NotLinked)
        }
    }

    /// Send `OobSend` packet to a node via relay.
    pub async fn send_oob(&self, destination_pk: PublicKey, data: Vec<u8>) -> Result<(), SendPacketError> {
        self.send_packet(Packet::OobSend(OobSend {
            destination_pk,
            data,
        })).await
    }

    /// Send `OnionRequest` packet to the relay.
    pub async fn send_onion(&self, onion_request: OnionRequest) -> Result<(), SendPacketError> {
        self.send_packet(Packet::OnionRequest(onion_request)).await
    }

    /// Add connection to a friend via this relay. If we are connected to the
    /// relay `RouteRequest` packet will be sent. Also this packet will be sent
    /// when fresh connection is established.
    pub async fn add_connection(&self, pk: PublicKey) {
        if self.connections.write().await.insert(pk.clone()) {
            // ignore sending errors if we are not connected to the relay
            // in this case RouteRequest will be sent after connection
            self.send_route_request(pk).await.ok();
        }
    }

    /// Remove connection to a friend via this relay. If we are connected to the
    /// relay and linked to the friend `DisconnectNotification` packet will be
    /// sent.
    pub async fn remove_connection(&self, pk: PublicKey) -> Result<(), SendPacketError> {
        if self.connections.write().await.remove(&pk) {
            let mut links = self.links.write().await;
            if let Some(index) = links.id_by_pk(&pk) {
                links.take(index);
                self.send_packet(Packet::DisconnectNotification(DisconnectNotification {
                    connection_id: ConnectionId::from_index(index),
                })).await.ok();
            }

            Ok(())
        } else {
            Err(SendPacketError::NoSuchConnection)
        }
    }

    /// Drop connection to the TCP relay if it's connected.
    pub async fn disconnect(&self) {
        // just drop the sink to stop the connection
        *self.status.write().await = ClientStatus::Disconnected;
    }

    /// Drop connection to the TCP relay if it's connected changing status to
    /// `Sleeping`.
    pub async fn sleep(&self) {
        // just drop the sink to stop the connection
        *self.status.write().await = ClientStatus::Sleeping;
    }

    /// Check if TCP connection to the relay is established.
    pub async fn is_connected(&self) -> bool {
        matches!(*self.status.read().await, ClientStatus::Connected(_))
    }

    /// Check if TCP connection to the relay is not established.
    pub async fn is_disconnected(&self) -> bool {
        matches!(*self.status.read().await, ClientStatus::Disconnected)
    }

    /// Check if TCP connection to the relay is sleeping.
    pub async fn is_sleeping(&self) -> bool {
        matches!(*self.status.read().await, ClientStatus::Sleeping)
    }

    /// Number of unsuccessful attempts to establish connection to the relay.
    /// This value is always 0 for successfully connected relays.
    pub async fn connection_attempts(&self) -> u32 {
        *self.connection_attempts.read().await
    }

    /// Time when a connection to the relay was established. Only connected
    /// relays have this value.
    pub async fn connected_time(&self) -> Option<Instant> {
        *self.connected_time.read().await
    }

    /// Number of nodes we want to be connected to via this relay.
    pub async fn connections_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Check if connection to the node with specified `PublicKey` exists.
    pub async fn has_connection(&self, pk: PublicKey) -> bool {
        self.connections.read().await.contains(&pk)
    }

    /// Check if connection to the node with specified `PublicKey` is online.
    pub async fn is_connection_online(&self, pk: PublicKey) -> bool {
        let links = self.links.read().await;
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
    use rand::thread_rng;
    use tox_binary_io::*;

    use std::time::{Duration, Instant};
    use std::io::{Error, ErrorKind};

    use tokio::net::TcpListener;

    use tox_packet::dht::CryptoData;
    use tox_packet::ip_port::*;
    use tox_packet::onion::*;
    use crate::relay::server::{Server, tcp_run, tcp_run_connection};
    use crypto_box::{SalsaBox, aead::{AeadCore, generic_array::typenum::marker_traits::Unsigned}};

    pub async fn create_client() -> (mpsc::UnboundedReceiver<(PublicKey, IncomingPacket)>, mpsc::Receiver<Packet>, Client) {
        let mut rng = thread_rng();
        let relay_addr = "127.0.0.1:12345".parse().unwrap();
        let relay_pk = SecretKey::generate(&mut rng).public_key();
        let (incoming_tx, incoming_rx) = mpsc::unbounded();
        let (outgoing_tx, outgoing_rx) = mpsc::channel(CLIENT_CHANNEL_SIZE);
        let client = Client::new(relay_pk, relay_addr, incoming_tx);
        *client.status.write().await = ClientStatus::Connected(outgoing_tx);
        *client.connected_time.write().await = Some(Instant::now());
        (incoming_rx, outgoing_rx, client)
    }

    pub async fn set_connection_attempts(client: &Client, attempts: u32) {
        *client.connection_attempts.write().await = attempts;
    }

    #[tokio::test]
    async fn handle_route_request() {
        let mut rng = thread_rng();
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        let route_request = Packet::RouteRequest(RouteRequest {
            pk: SecretKey::generate(&mut rng).public_key(),
        });

        let error = client.handle_packet(route_request).await.err().unwrap();
        assert_eq!(error, HandlePacketError::MustNotSend);
    }

    #[tokio::test]
    async fn handle_route_response() {
        let mut rng = thread_rng();
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        let new_pk = SecretKey::generate(&mut rng).public_key();
        let index = 42;

        client.connections.write().await.insert(new_pk.clone());

        let route_response = Packet::RouteResponse(RouteResponse {
            connection_id: ConnectionId::from_index(index),
            pk: new_pk.clone(),
        });

        client.handle_packet(route_response).await.unwrap();

        let link = client.links.read().await.by_id(index).cloned().unwrap();

        assert_eq!(link.pk, new_pk);
        assert_eq!(link.status, LinkStatus::Registered);
    }

    #[tokio::test]
    async fn handle_route_response_occupied() {
        let mut rng = thread_rng();
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        let existing_pk = SecretKey::generate(&mut rng).public_key();
        let new_pk = SecretKey::generate(&mut rng).public_key();
        let index = 42;

        client.connections.write().await.insert(new_pk.clone());
        client.links.write().await.insert_by_id(existing_pk.clone(), index);

        let route_response = Packet::RouteResponse(RouteResponse {
            connection_id: ConnectionId::from_index(index),
            pk: new_pk,
        });

        assert!(client.handle_packet(route_response).await.is_err());

        let link = client.links.read().await.by_id(index).cloned().unwrap();

        assert_eq!(link.pk, existing_pk);
        assert_eq!(link.status, LinkStatus::Registered);
    }

    #[tokio::test]
    async fn handle_route_response_unexpected() {
        let mut rng = thread_rng();
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        let index = 42;
        let route_response = Packet::RouteResponse(RouteResponse {
            connection_id: ConnectionId::from_index(index),
            pk: SecretKey::generate(&mut rng).public_key(),
        });

        let error = client.handle_packet(route_response).await.err().unwrap();
        assert_eq!(error, HandlePacketError::UnexpectedRouteResponse);

        assert!(client.links.read().await.by_id(index).is_none());
    }

    #[tokio::test]
    async fn handle_route_response_0() {
        let mut rng = thread_rng();
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        let route_response = Packet::RouteResponse(RouteResponse {
            connection_id: ConnectionId::zero(),
            pk: SecretKey::generate(&mut rng).public_key(),
        });

        let error = client.handle_packet(route_response).await.err().unwrap();
        assert_eq!(error, HandlePacketError::InvalidConnectionId);
    }

    #[tokio::test]
    async fn handle_connect_notification() {
        let mut rng = thread_rng();
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        let existing_pk = SecretKey::generate(&mut rng).public_key();
        let index = 42;

        client.links.write().await.insert_by_id(existing_pk.clone(), index);

        let connect_notification = Packet::ConnectNotification(ConnectNotification {
            connection_id: ConnectionId::from_index(index),
        });

        client.handle_packet(connect_notification).await.unwrap();

        let link = client.links.read().await.by_id(index).cloned().unwrap();

        assert_eq!(link.pk, existing_pk);
        assert_eq!(link.status, LinkStatus::Online);
    }

    #[tokio::test]
    async fn handle_connect_notification_unexpected() {
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        let index = 42;
        let connect_notification = Packet::ConnectNotification(ConnectNotification {
            connection_id: ConnectionId::from_index(index),
        });

        let error = client.handle_packet(connect_notification).await.err().unwrap();
        assert_eq!(error, HandlePacketError::AlreadyLinked);

        assert!(client.links.read().await.by_id(index).is_none());
    }

    #[tokio::test]
    async fn handle_connect_notification_0() {
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        let connect_notification = Packet::ConnectNotification(ConnectNotification {
            connection_id: ConnectionId::zero(),
        });

        let error = client.handle_packet(connect_notification).await.err().unwrap();
        assert_eq!(error, HandlePacketError::InvalidConnectionId);
    }

    #[tokio::test]
    async fn handle_disconnect_notification() {
        let mut rng = thread_rng();
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        let existing_pk = SecretKey::generate(&mut rng).public_key();
        let index = 42;

        client.links.write().await.insert_by_id(existing_pk.clone(), index);
        client.links.write().await.upgrade(index);

        let disconnect_notification = Packet::DisconnectNotification(DisconnectNotification {
            connection_id: ConnectionId::from_index(index),
        });

        client.handle_packet(disconnect_notification).await.unwrap();

        let link = client.links.read().await.by_id(index).cloned().unwrap();

        assert_eq!(link.pk, existing_pk);
        assert_eq!(link.status, LinkStatus::Registered);
    }

    #[tokio::test]
    async fn handle_disconnect_notification_unexpected() {
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        let index = 42;
        let disconnect_notification = Packet::DisconnectNotification(DisconnectNotification {
            connection_id: ConnectionId::from_index(index),
        });

        let error = client.handle_packet(disconnect_notification).await.err().unwrap();
        assert_eq!(error, HandlePacketError::AlreadyLinked);

        assert!(client.links.read().await.by_id(index).is_none());
    }

    #[tokio::test]
    async fn handle_disconnect_notification_0() {
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        let disconnect_notification = Packet::DisconnectNotification(DisconnectNotification {
            connection_id: ConnectionId::zero(),
        });

        let error = client.handle_packet(disconnect_notification).await.err().unwrap();
        assert_eq!(error, HandlePacketError::InvalidConnectionId);
    }

    #[tokio::test]
    async fn handle_ping_request() {
        let (_incoming_rx, outgoing_rx, client) = create_client().await;

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
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        let ping_id = 42;
        let pong_response = Packet::PongResponse(PongResponse {
            ping_id
        });

        client.handle_packet(pong_response).await.unwrap();
    }

    #[tokio::test]
    async fn handle_oob_send() {
        let mut rng = thread_rng();
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        let oob_send = Packet::OobSend(OobSend {
            destination_pk: SecretKey::generate(&mut rng).public_key(),
            data: vec![42; 123],
        });

        let error = client.handle_packet(oob_send).await.err().unwrap();
        assert_eq!(error, HandlePacketError::MustNotSend);
    }

    #[tokio::test]
    async fn handle_oob_receive() {
        let mut rng = thread_rng();
        let (incoming_rx, _outgoing_rx, client) = create_client().await;

        let sender_pk = SecretKey::generate(&mut rng).public_key();
        let data = vec![42; 123];
        let oob_receive = Packet::OobReceive(OobReceive {
            sender_pk: sender_pk.clone(),
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
        let mut rng = thread_rng();
        let (incoming_rx, _outgoing_rx, client) = create_client().await;

        let sender_pk = SecretKey::generate(&mut rng).public_key();
        let index = 42;

        client.links.write().await.insert_by_id(sender_pk.clone(), index);
        client.links.write().await.upgrade(index);

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
        let (incoming_rx, _outgoing_rx, client) = create_client().await;

        let data_packet = Packet::Data(Data {
            connection_id: ConnectionId::from_index(42),
            data: DataPayload::CryptoData(CryptoData {
                nonce_last_bytes: 42,
                payload: vec![42; 123],
            }),
        });

        let error = client.handle_packet(data_packet).await.err().unwrap();
        assert_eq!(error, HandlePacketError::AlreadyLinked);

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(incoming_rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn handle_data_0() {
        let (incoming_rx, _outgoing_rx, client) = create_client().await;

        let data_packet = Packet::Data(Data {
            connection_id: ConnectionId::zero(),
            data: DataPayload::CryptoData(CryptoData {
                nonce_last_bytes: 42,
                payload: vec![42; 123],
            }),
        });

        let error = client.handle_packet(data_packet).await.err().unwrap();
        assert_eq!(error, HandlePacketError::InvalidConnectionId);

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(incoming_rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn handle_onion_request() {
        let mut rng = thread_rng();
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        let onion_request = Packet::OnionRequest(OnionRequest {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            ip_port: IpPort {
                protocol: ProtocolType::Tcp,
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345,
            },
            temporary_pk: SecretKey::generate(&mut rng).public_key(),
            payload: vec![42; 123],
        });

        let error = client.handle_packet(onion_request).await.err().unwrap();
        assert_eq!(error, HandlePacketError::MustNotSend);
    }

    #[tokio::test]
    async fn handle_onion_response() {
        let mut rng = thread_rng();
        let (incoming_rx, _outgoing_rx, client) = create_client().await;

        let payload = InnerOnionResponse::OnionDataResponse(OnionDataResponse {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            temporary_pk: SecretKey::generate(&mut rng).public_key(),
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
        let mut rng = thread_rng();
        let (_incoming_rx, outgoing_rx, client) = create_client().await;

        let destination_pk = SecretKey::generate(&mut rng).public_key();
        let data = DataPayload::CryptoData(CryptoData {
            nonce_last_bytes: 42,
            payload: vec![42; 123],
        });

        let index = 42;
        client.links.write().await.insert_by_id(destination_pk.clone(), index);
        client.links.write().await.upgrade(index);

        client.send_data(destination_pk, data.clone()).await.unwrap();

        let packet = unpack!(outgoing_rx.into_future().await.0.unwrap(), Packet::Data);

        assert_eq!(packet.connection_id, ConnectionId::from_index(index));
        assert_eq!(packet.data, data);
    }

    #[tokio::test]
    async fn send_data_not_linked() {
        let mut rng = thread_rng();
        let (_incoming_rx, outgoing_rx, client) = create_client().await;

        let destination_pk = SecretKey::generate(&mut rng).public_key();
        let data = DataPayload::CryptoData(CryptoData {
            nonce_last_bytes: 42,
            payload: vec![42; 123],
        });

        let error = client.send_data(destination_pk, data.clone()).await.err().unwrap();
        assert_eq!(error, SendPacketError::NotLinked);

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(outgoing_rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn send_data_not_online() {
        let mut rng = thread_rng();
        let (_incoming_rx, outgoing_rx, client) = create_client().await;

        let destination_pk = SecretKey::generate(&mut rng).public_key();
        let data = DataPayload::CryptoData(CryptoData {
            nonce_last_bytes: 42,
            payload: vec![42; 123],
        });

        let connection_id = 42;
        client.links.write().await.insert_by_id(destination_pk.clone(), connection_id - 16);

        let error = client.send_data(destination_pk, data.clone()).await.err().unwrap();
        assert_eq!(error, SendPacketError::NotOnline);

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(outgoing_rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn send_oob() {
        let mut rng = thread_rng();
        let (_incoming_rx, outgoing_rx, client) = create_client().await;

        let destination_pk = SecretKey::generate(&mut rng).public_key();
        let data = vec![42; 123];

        client.send_oob(destination_pk.clone(), data.clone()).await.unwrap();

        let packet = unpack!(outgoing_rx.into_future().await.0.unwrap(), Packet::OobSend);

        assert_eq!(packet.destination_pk, destination_pk);
        assert_eq!(packet.data, data);
    }

    #[tokio::test]
    async fn send_onion() {
        let mut rng = thread_rng();
        let (_incoming_rx, outgoing_rx, client) = create_client().await;

        let onion_request = OnionRequest {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            ip_port: IpPort {
                protocol: ProtocolType::Tcp,
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345,
            },
            temporary_pk: SecretKey::generate(&mut rng).public_key(),
            payload: vec![42; 123],
        };

        client.send_onion(onion_request.clone()).await.unwrap();

        let packet = unpack!(outgoing_rx.into_future().await.0.unwrap(), Packet::OnionRequest);

        assert_eq!(packet, onion_request);
    }

    #[tokio::test]
    async fn add_connection() {
        let mut rng = thread_rng();
        let (_incoming_rx, outgoing_rx, client) = create_client().await;

        let connection_pk = SecretKey::generate(&mut rng).public_key();

        client.add_connection(connection_pk.clone()).await;

        let (packet, outgoing_rx) = outgoing_rx.into_future().await;
        let packet = unpack!(packet.unwrap(), Packet::RouteRequest);

        assert_eq!(packet.pk, connection_pk);

        // RouteRequest shouldn't be sent again after we add the same connection
        client.add_connection(connection_pk).await;

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(outgoing_rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn remove_connection() {
        let mut rng = thread_rng();
        let (_incoming_rx, outgoing_rx, client) = create_client().await;

        let connection_pk = SecretKey::generate(&mut rng).public_key();
        let index = 42;

        client.connections.write().await.insert(connection_pk.clone());
        client.links.write().await.insert_by_id(connection_pk.clone(), index);

        client.remove_connection(connection_pk).await.unwrap();

        let packet = unpack!(outgoing_rx.into_future().await.0.unwrap(), Packet::DisconnectNotification);

        assert_eq!(packet.connection_id, ConnectionId::from_index(index));
    }

    #[tokio::test]
    async fn remove_connection_no_connection() {
        let mut rng = thread_rng();
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        let connection_pk = SecretKey::generate(&mut rng).public_key();

        let error = client.remove_connection(connection_pk).await.err().unwrap();
        assert_eq!(error, SendPacketError::NoSuchConnection);
    }

    #[tokio::test]
    async fn remove_connection_no_link() {
        let mut rng = thread_rng();
        let (_incoming_rx, outgoing_rx, client) = create_client().await;

        let connection_pk = SecretKey::generate(&mut rng).public_key();

        client.connections.write().await.insert(connection_pk.clone());

        client.remove_connection(connection_pk).await.unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(client);

        assert!(outgoing_rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn disconnect() {
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        assert!(client.is_connected().await);
        assert!(!client.is_disconnected().await);
        assert!(!client.is_sleeping().await);

        client.disconnect().await;

        assert!(!client.is_connected().await);
        assert!(client.is_disconnected().await);
        assert!(!client.is_sleeping().await);
    }

    #[tokio::test]
    async fn sleep() {
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        assert!(client.is_connected().await);
        assert!(!client.is_disconnected().await);
        assert!(!client.is_sleeping().await);

        client.sleep().await;

        assert!(!client.is_connected().await);
        assert!(!client.is_disconnected().await);
        assert!(client.is_sleeping().await);
    }

    #[tokio::test]
    async fn is_connection_online() {
        let mut rng = thread_rng();
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        let connection_pk = SecretKey::generate(&mut rng).public_key();
        let connection_id = 42;

        client.links.write().await.insert_by_id(connection_pk.clone(), connection_id - 16);

        assert!(!client.is_connection_online(connection_pk.clone()).await);

        client.links.write().await.upgrade(connection_id - 16);

        assert!(client.is_connection_online(connection_pk).await);
    }

    #[tokio::test]
    async fn connections_count() {
        let mut rng = thread_rng();
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        assert_eq!(client.connections_count().await, 0);

        let connection_pk = SecretKey::generate(&mut rng).public_key();

        client.connections.write().await.insert(connection_pk);

        assert_eq!(client.connections_count().await, 1);
    }

    #[tokio::test]
    async fn is_connection_online_no_connection() {
        let mut rng = thread_rng();
        let (_incoming_rx, _outgoing_rx, client) = create_client().await;

        let connection_pk = SecretKey::generate(&mut rng).public_key();

        assert!(!client.is_connection_online(connection_pk).await);
    }

    #[tokio::test]
    async fn spawn() {
        // waits until the relay becomes connected
        async fn on_connected(client: Client) -> Result<(), Error> {
            let mut interval = tokio::time::interval(Duration::from_millis(10));

            loop {
                interval.tick().await;

                match *client.status.read().await {
                    ClientStatus::Connecting => continue,
                    ClientStatus::Connected(_) => return Ok(()),
                    ref other => return Err(Error::new(ErrorKind::Other, format!("Invalid status: {:?}", other))),
                }
            }
        }

        // waits until link with PublicKey becomes online
        async fn on_online(client: Client, pk: PublicKey) -> Result<(), Error> {
            let mut interval = tokio::time::interval(Duration::from_millis(10));

            loop {
                interval.tick().await;

                let links = client.links.read().await;
                if let Some(index) = links.id_by_pk(&pk) {
                    let status = links.by_id(index).map(|link| link.status);
                    if status == Some(LinkStatus::Online) { return Ok(()) }
                }
            }
        }

        // run server
        let mut rng = thread_rng();
        let server_sk = SecretKey::generate(&mut rng);
        let server_pk = server_sk.public_key();

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(&addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let stats = Stats::new();
        let server_future = async {
            tcp_run(&Server::new(), listener, server_sk, stats, 2).await
                .map_err(|e| Error::new(ErrorKind::Other, e))
        };
        tokio::spawn(server_future);

        // run first client
        let client_sk_1 = SecretKey::generate(&mut rng);
        let client_pk_1 = client_sk_1.public_key();
        let (incoming_tx_1, mut incoming_rx_1) = mpsc::unbounded();
        let client_1 = Client::new(server_pk.clone(), addr, incoming_tx_1);
        // connection attempts should be set to 0 after successful connection
        set_connection_attempts(&client_1, 3).await;
        client_1.clone().spawn(client_sk_1.clone(), client_pk_1.clone()).await.unwrap();

        // run second client
        let client_sk_2 = SecretKey::generate(&mut rng);
        let client_pk_2 = client_sk_2.public_key();
        let (incoming_tx_2, mut incoming_rx_2) = mpsc::unbounded();
        let client_2 = Client::new(server_pk.clone(), addr, incoming_tx_2);
        // connection attempts should be set to 0 after successful connection
        set_connection_attempts(&client_2, 3).await;
        client_2.clone().spawn(client_sk_2, client_pk_2.clone()).await.unwrap();

        // wait until connections are established
        on_connected(client_1.clone()).await.unwrap();
        on_connected(client_2.clone()).await.unwrap();

        assert!(client_1.connected_time().await.is_some());
        assert!(client_2.connected_time().await.is_some());
        assert_eq!(client_1.connection_attempts().await, 0);
        assert_eq!(client_2.connection_attempts().await, 0);

        // add connections when relay is connected
        client_1.add_connection(client_pk_2.clone()).await;
        client_2.add_connection(client_pk_1.clone()).await;

        // wait until links become online
        on_online(client_1.clone(), client_pk_2.clone()).await.unwrap();
        on_online(client_2.clone(), client_pk_1.clone()).await.unwrap();

        let data_1 = DataPayload::CryptoData(CryptoData {
            nonce_last_bytes: 42,
            payload: vec![42; 123],
        });
        let data_2 = DataPayload::CryptoData(CryptoData {
            nonce_last_bytes: 42,
            payload: vec![43; 123],
        });
        client_1.send_data(client_pk_2.clone(), data_1.clone()).await.unwrap();
        client_2.send_data(client_pk_1.clone(), data_2.clone()).await.unwrap();

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
        let mut rng = thread_rng();
        let server_sk = SecretKey::generate(&mut rng);

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(&addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = Server::new();
        let stats = Stats::new();
        let server_future = async {
            let (connection, _) = listener.accept().await.unwrap();
            tcp_run_connection(&server, connection, server_sk, stats)
                .map_err(|e| Error::new(ErrorKind::Other, e)).await
        };

        // run a client with invalid server's pk
        let client_sk_1 = SecretKey::generate(&mut rng);
        let client_pk_1 = client_sk_1.public_key();
        let invalid_server_pk = SecretKey::generate(&mut rng).public_key();
        let (incoming_tx_1, _incoming_rx_1) = mpsc::unbounded();
        let client = Client::new(invalid_server_pk, addr, incoming_tx_1);
        let client_future = client.run(client_sk_1, client_pk_1)
            .map_err(|e| Error::new(ErrorKind::Other, e));

        let (server_res, client_res) = futures::join!(server_future, client_future);
        assert!(server_res.is_err()); // fail to process handshake
        assert!(client_res.is_err()); // fail to process handshake

        // connection_attempts should be increased
        assert_eq!(*client.connection_attempts.read().await, 1);
    }
}
