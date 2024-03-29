/*! The implementation of relay server
*/

use crate::relay::links::*;
use crate::relay::server::client::Client;
use tox_crypto::*;
use tox_packet::onion::InnerOnionResponse;
use tox_packet::relay::connection_id::ConnectionId;
use tox_packet::relay::*;

use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::channel::mpsc;
use futures::stream::FuturesUnordered;
use futures::{SinkExt, StreamExt};
use tokio::sync::RwLock;

/// Interval of time for packet sending
const TCP_SEND_TIMEOUT: Duration = Duration::from_millis(100);

/** A `Server` is a structure that holds connected clients, manages their links and handles
their responses. Notice that there is no actual network code here, the `Server` accepts packets
by value from `Server::handle_packet`, sends packets back to clients via
`futures::sync::mpsc::UnboundedSender<Packet>` channel, accepts onion responses from
`Server::handle_udp_onion_response` and sends onion requests via
`futures::sync::mpsc::UnboundedSender<OnionRequest>` channel. The outer code should manage how to
handshake connections, get packets from clients, pass them into `Server::handle_packet`, get onion
responses from UPD socket and send them to `Server::handle_udp_onion_response`, create `mpsc`
channels, take packets from `futures::sync::mpsc::UnboundedReceiver<Packet>` send them back
to clients via network.
*/
#[derive(Default, Clone)]
pub struct Server {
    state: Arc<RwLock<ServerState>>,
    // None if the server is not responsible to handle OnionRequests
    onion_sink: Option<mpsc::Sender<(OnionRequest, SocketAddr)>>,
}

#[derive(Default)]
struct ServerState {
    pub connected_clients: HashMap<PublicKey, Client>,
    pub keys_by_addr: HashMap<(IpAddr, /*port*/ u16), PublicKey>,
}

async fn send_packet(packet: Packet, mut tx: mpsc::Sender<Packet>) {
    tokio::time::timeout(TCP_SEND_TIMEOUT, tx.send(packet)).await.ok();
}

/// Send all packets concurrently. The error in a single sending
/// should not affect others.
async fn send_packets<T: IntoIterator<Item = (Packet, mpsc::Sender<Packet>)>>(packets: T) {
    let mut futures = packets
        .into_iter()
        .map(|(packet, tx)| send_packet(packet, tx))
        .collect::<FuturesUnordered<_>>();
    while futures.next().await.is_some() {}
}

/// The result of handling one TCP `Packet` whose main purpose is to avoid
/// blocking of server state while waiting for packets sending.
enum HandleAction {
    Send(Vec<(Packet, mpsc::Sender<Packet>)>),
    Onion(OnionRequest, SocketAddr),
}

impl Default for HandleAction {
    fn default() -> Self {
        HandleAction::empty()
    }
}

impl HandleAction {
    fn one(packet: Packet, tx: mpsc::Sender<Packet>) -> Self {
        HandleAction::Send(vec![(packet, tx)])
    }

    fn empty() -> Self {
        HandleAction::Send(Vec::new())
    }

    async fn execute(self, onion_sink: &Option<mpsc::Sender<(OnionRequest, SocketAddr)>>) {
        match self {
            HandleAction::Send(packets) => send_packets(packets).await,
            HandleAction::Onion(packet, saddr) => {
                if let Some(tx) = onion_sink {
                    tokio::time::timeout(TCP_SEND_TIMEOUT, tx.clone().send((packet, saddr)))
                        .await
                        .ok();
                }
            }
        }
    }
}

impl Server {
    /** Create a new `Server` without onion
     */
    pub fn new() -> Server {
        Server::default()
    }
    /** Create a new `Server` with onion
     */
    pub fn set_udp_onion_sink(&mut self, onion_sink: mpsc::Sender<(OnionRequest, SocketAddr)>) {
        self.onion_sink = Some(onion_sink)
    }
    /** Insert the client into `connected_clients`. If `connected_clients`
    contains a client with the same pk it will be terminated.
    */
    pub async fn insert(&self, client: Client) -> Result<(), Error> {
        let mut state = self.state.write().await;

        let packets = if state.connected_clients.contains_key(&client.pk()) {
            self.shutdown_client_inner(&client.pk(), &mut state)?
        } else {
            vec![]
        };

        state
            .keys_by_addr
            .insert((client.ip_addr(), client.port()), client.pk());
        state.connected_clients.insert(client.pk(), client);

        drop(state);

        send_packets(packets).await;

        Ok(())
    }
    /** The main processing function. Call in on each incoming packet from connected and
    handshaked client.
    */
    pub async fn handle_packet(&self, pk: &PublicKey, packet: Packet) -> Result<(), Error> {
        let action = match packet {
            Packet::RouteRequest(packet) => self.handle_route_request(pk, &packet).await,
            Packet::RouteResponse(packet) => self.handle_route_response(pk, &packet).await,
            Packet::ConnectNotification(packet) => self.handle_connect_notification(pk, &packet).await,
            Packet::DisconnectNotification(packet) => self.handle_disconnect_notification(pk, &packet).await,
            Packet::PingRequest(packet) => self.handle_ping_request(pk, &packet).await,
            Packet::PongResponse(packet) => self.handle_pong_response(pk, &packet).await,
            Packet::OobSend(packet) => self.handle_oob_send(pk, packet).await,
            Packet::OobReceive(packet) => self.handle_oob_receive(pk, &packet).await,
            Packet::OnionRequest(packet) => self.handle_onion_request(pk, packet).await,
            Packet::OnionResponse(packet) => self.handle_onion_response(pk, &packet).await,
            Packet::Data(packet) => self.handle_data(pk, packet).await,
        }?;
        action.execute(&self.onion_sink).await;
        Ok(())
    }
    /** Send `OnionResponse` packet to the client by it's `std::net::IpAddr`.
     */
    pub async fn handle_udp_onion_response(
        &self,
        ip_addr: IpAddr,
        port: u16,
        payload: InnerOnionResponse,
    ) -> Result<(), Error> {
        let state = self.state.read().await;
        let tx = if let Some(client) = state
            .keys_by_addr
            .get(&(ip_addr, port))
            .and_then(|pk| state.connected_clients.get(pk))
        {
            client.tx()
        } else {
            return Err(Error::new(
                ErrorKind::Other,
                "Cannot find client by ip_addr to send onion response",
            ));
        };

        drop(state);

        let packet = Packet::OnionResponse(OnionResponse { payload });
        send_packet(packet, tx).await;

        Ok(())
    }
    /** Gracefully shutdown client by pk, IP address and port. IP address and
    port are used to ensure that the right client will be removed. If the client
    with passed pk has different IP address or port it means that it was
    recently reconnected and it shouldn't be removed by the old connection
    finalization step. If IP address with port are correct remove it from the
    list of connected clients. If there are any clients mutually linked to
    current client, we send them corresponding `DisconnectNotification`.
    */
    pub async fn shutdown_client(&self, pk: &PublicKey, ip_addr: IpAddr, port: u16) -> Result<(), Error> {
        let mut state = self.state.write().await;

        // check that the client's address isn't changed
        if let Some(client) = state.connected_clients.get(pk) {
            if client.ip_addr() != ip_addr || client.port() != port {
                return Err(Error::new(ErrorKind::Other, "Client with pk has different address"));
            }
        } else {
            return Err(Error::new(ErrorKind::Other, "Cannot find client by pk to shutdown it"));
        }

        let packets = self.shutdown_client_inner(pk, &mut state)?;

        drop(state);

        send_packets(packets).await;

        Ok(())
    }

    /** Actual shutdown is done here.
     */
    fn shutdown_client_inner(
        &self,
        pk: &PublicKey,
        state: &mut ServerState,
    ) -> Result<Vec<(Packet, mpsc::Sender<Packet>)>, Error> {
        // remove client by pk from connected_clients
        let client_a = if let Some(client) = state.connected_clients.remove(pk) {
            client
        } else {
            return Err(Error::new(ErrorKind::Other, "Cannot find client by pk to shutdown it"));
        };

        state.keys_by_addr.remove(&(client_a.ip_addr(), client_a.port()));
        let result = client_a
            .links()
            .iter_links()
            .filter(|link| link.status == LinkStatus::Online)
            .filter_map(|link| {
                let client_b_pk = link.pk;
                if let Some(client_b) = state.connected_clients.get_mut(&client_b_pk) {
                    if let Some(a_id_in_client_b) = client_b.links().id_by_pk(pk) {
                        // they are linked, we should notify client_b
                        // link from client_b.links should be downgraded
                        client_b.links_mut().downgrade(a_id_in_client_b);

                        let packet = Packet::DisconnectNotification(DisconnectNotification {
                            connection_id: ConnectionId::from_index(a_id_in_client_b),
                        });
                        return Some((packet, client_b.tx()));
                    }
                }

                None
            })
            .collect();
        Ok(result)
    }
    // Here start the impl of `handle_***` methods

    async fn handle_route_request(&self, pk: &PublicKey, packet: &RouteRequest) -> Result<HandleAction, Error> {
        let mut state = self.state.write().await;

        // get client_a
        let client_a = if let Some(client) = state.connected_clients.get_mut(pk) {
            client
        } else {
            return Err(Error::new(ErrorKind::Other, "RouteRequest: no such PK"));
        };

        if pk == &packet.pk {
            // send RouteResponse(0) if client requests its own pk
            let packet = Packet::RouteResponse(RouteResponse {
                connection_id: ConnectionId::zero(),
                pk: pk.clone(),
            });
            return Ok(HandleAction::one(packet, client_a.tx()));
        }

        // check if client_a is already linked
        if let Some(index) = client_a.links().id_by_pk(&packet.pk) {
            // send RouteResponse if client was already linked to pk
            let packet = Packet::RouteResponse(RouteResponse {
                connection_id: ConnectionId::from_index(index),
                pk: packet.pk.clone(),
            });
            return Ok(HandleAction::one(packet, client_a.tx()));
        }

        // try to insert a new link
        let b_id_in_client_a = if let Some(index) = client_a.links_mut().insert(packet.pk.clone()) {
            index
        } else {
            // send RouteResponse(0) if no space to insert new link
            let packet = Packet::RouteResponse(RouteResponse {
                connection_id: ConnectionId::zero(),
                pk: packet.pk.clone(),
            });
            return Ok(HandleAction::one(packet, client_a.tx()));
        };

        let route_response = Packet::RouteResponse(RouteResponse {
            connection_id: ConnectionId::from_index(b_id_in_client_a),
            pk: packet.pk.clone(),
        });
        let route_response_tx = client_a.tx();

        // get client_b
        let client_b = if let Some(client) = state.connected_clients.get(&packet.pk) {
            client
        } else {
            return Ok(HandleAction::one(route_response, route_response_tx));
        };

        // check if current pk is linked inside other_client
        let a_id_in_client_b = if let Some(index) = client_b.links().id_by_pk(pk) {
            index
        } else {
            // they are not linked
            return Ok(HandleAction::one(route_response, route_response_tx));
        };

        // they are both linked, send RouteResponse and
        // send each other ConnectNotification
        // we don't care if connect notifications fail
        let client_a = state.connected_clients.get_mut(pk).unwrap();
        client_a.links_mut().upgrade(b_id_in_client_a);
        let connect_notification_a = Packet::ConnectNotification(ConnectNotification {
            connection_id: ConnectionId::from_index(b_id_in_client_a),
        });
        let connect_notification_a_tx = client_a.tx();

        let client_b = state.connected_clients.get_mut(&packet.pk).unwrap();
        client_b.links_mut().upgrade(a_id_in_client_b);
        let connect_notification_b = Packet::ConnectNotification(ConnectNotification {
            connection_id: ConnectionId::from_index(a_id_in_client_b),
        });
        let connect_notification_b_tx = client_b.tx();

        Ok(HandleAction::Send(vec![
            (route_response, route_response_tx),
            (connect_notification_a, connect_notification_a_tx),
            (connect_notification_b, connect_notification_b_tx),
        ]))
    }

    async fn handle_route_response(&self, _pk: &PublicKey, _packet: &RouteResponse) -> Result<HandleAction, Error> {
        Err(Error::new(
            ErrorKind::Other,
            "Client must not send RouteResponse to server",
        ))
    }

    async fn handle_connect_notification(
        &self,
        _pk: &PublicKey,
        _packet: &ConnectNotification,
    ) -> Result<HandleAction, Error> {
        // Although normally a client should not send ConnectNotification to server
        //  we ignore it for backward compatibility
        Ok(HandleAction::empty())
    }
    async fn handle_disconnect_notification(
        &self,
        pk: &PublicKey,
        packet: &DisconnectNotification,
    ) -> Result<HandleAction, Error> {
        let index = if let Some(index) = packet.connection_id.index() {
            index
        } else {
            return Err(Error::new(
                ErrorKind::Other,
                "DisconnectNotification: connection id is zero",
            ));
        };

        let mut state = self.state.write().await;

        // get client_a
        let a_link = if let Some(client_a) = state.connected_clients.get_mut(pk) {
            // unlink the link from client.links if any
            if let Some(link) = client_a.links_mut().take(index) {
                link
            } else {
                trace!(
                    "DisconnectNotification.connection_id is not linked for the client {:?}",
                    pk
                );
                // There is possibility that the first client disconnected but the second client
                // haven't received DisconnectNotification yet and have sent yet another packet.
                // In this case we don't want to throw an error and force disconnect the second client.
                // TODO: failure can be used to return an error and handle it inside ServerProcessor
                return Ok(HandleAction::empty());
            }
        } else {
            return Err(Error::new(ErrorKind::Other, "DisconnectNotification: no such PK"));
        };

        match a_link.status {
            LinkStatus::Registered => {
                // Do nothing because
                // client_b has not sent RouteRequest yet to connect to client_a
                Ok(HandleAction::empty())
            }
            LinkStatus::Online => {
                let client_b_pk = a_link.pk;
                // get client_b
                let client_b = if let Some(client) = state.connected_clients.get_mut(&client_b_pk) {
                    client
                } else {
                    // client_b is not connected to the server
                    // so ignore DisconnectNotification
                    return Ok(HandleAction::empty());
                };
                let a_id_in_client_b = if let Some(id) = client_b.links().id_by_pk(pk) {
                    id
                } else {
                    // No a_id_in_client_b
                    return Ok(HandleAction::empty());
                };
                // it is linked, we should notify client_b
                // link from client_b.links should be downgraded
                client_b.links_mut().downgrade(a_id_in_client_b);
                let packet = Packet::DisconnectNotification(DisconnectNotification {
                    connection_id: ConnectionId::from_index(a_id_in_client_b),
                });
                Ok(HandleAction::one(packet, client_b.tx()))
            }
        }
    }

    async fn handle_ping_request(&self, pk: &PublicKey, packet: &PingRequest) -> Result<HandleAction, Error> {
        if packet.ping_id == 0 {
            return Err(Error::new(ErrorKind::Other, "PingRequest.ping_id == 0"));
        }
        let state = self.state.read().await;
        if let Some(client_a) = state.connected_clients.get(pk) {
            let packet = Packet::PongResponse(PongResponse {
                ping_id: packet.ping_id,
            });
            Ok(HandleAction::one(packet, client_a.tx()))
        } else {
            Err(Error::new(ErrorKind::Other, "PingRequest: no such PK"))
        }
    }

    async fn handle_pong_response(&self, pk: &PublicKey, packet: &PongResponse) -> Result<HandleAction, Error> {
        if packet.ping_id == 0 {
            return Err(Error::new(ErrorKind::Other, "PongResponse.ping_id == 0"));
        }
        let mut state = self.state.write().await;
        if let Some(client_a) = state.connected_clients.get_mut(pk) {
            if packet.ping_id == client_a.ping_id() {
                client_a.set_last_pong_resp(Instant::now());

                Ok(HandleAction::empty())
            } else {
                Err(Error::new(ErrorKind::Other, "PongResponse.ping_id does not match"))
            }
        } else {
            Err(Error::new(ErrorKind::Other, "PongResponse: no such PK"))
        }
    }

    async fn handle_oob_send(&self, pk: &PublicKey, packet: OobSend) -> Result<HandleAction, Error> {
        if packet.data.is_empty() || packet.data.len() > 1024 {
            return Err(Error::new(ErrorKind::Other, "OobSend wrong data length"));
        }
        let state = self.state.read().await;
        if let Some(client_b) = state.connected_clients.get(&packet.destination_pk) {
            let packet = Packet::OobReceive(OobReceive {
                sender_pk: pk.clone(),
                data: packet.data,
            });
            Ok(HandleAction::one(packet, client_b.tx()))
        } else {
            Ok(HandleAction::empty())
        }
    }

    async fn handle_oob_receive(&self, _pk: &PublicKey, _packet: &OobReceive) -> Result<HandleAction, Error> {
        Err(Error::new(
            ErrorKind::Other,
            "Client must not send OobReceive to server",
        ))
    }

    async fn handle_onion_request(&self, pk: &PublicKey, packet: OnionRequest) -> Result<HandleAction, Error> {
        if self.onion_sink.is_some() {
            let state = self.state.read().await;
            if let Some(client) = state.connected_clients.get(pk) {
                let saddr = SocketAddr::new(client.ip_addr(), client.port());
                Ok(HandleAction::Onion(packet, saddr))
            } else {
                Err(Error::new(ErrorKind::Other, "OnionRequest: no such PK"))
            }
        } else {
            // Ignore OnionRequest as the server is not connected to onion subsystem
            Ok(HandleAction::empty())
        }
    }

    async fn handle_onion_response(&self, _pk: &PublicKey, _packet: &OnionResponse) -> Result<HandleAction, Error> {
        Err(Error::new(
            ErrorKind::Other,
            "Client must not send OnionResponse to server",
        ))
    }

    async fn handle_data(&self, pk: &PublicKey, packet: Data) -> Result<HandleAction, Error> {
        let index = if let Some(index) = packet.connection_id.index() {
            index
        } else {
            return Err(Error::new(ErrorKind::Other, "Data: connection id is zero"));
        };

        let state = self.state.read().await;

        // get client_a
        let client_a = if let Some(client) = state.connected_clients.get(pk) {
            client
        } else {
            return Err(Error::new(ErrorKind::Other, "Data: no such PK"));
        };

        // get the link from client.links if any
        let a_link = if let Some(link) = client_a.links().by_id(index) {
            link.clone()
        } else {
            trace!("Data.connection_id is not linked for the client {:?}", pk);
            // There is possibility that the first client disconnected but the second client
            // haven't received DisconnectNotification yet and have sent yet another packet.
            // In this case we don't want to throw an error and force disconnect the second client.
            // TODO: failure can be used to return an error and handle it inside ServerProcessor
            return Ok(HandleAction::empty());
        };

        match a_link.status {
            LinkStatus::Registered => {
                // Do nothing because
                // client_b has not sent RouteRequest yet to connect to client_a
                Ok(HandleAction::empty())
            }
            LinkStatus::Online => {
                let client_b_pk = a_link.pk;
                // get client_b
                let client_b = if let Some(client) = state.connected_clients.get(&client_b_pk) {
                    client
                } else {
                    // Do nothing because client_b is not connected to server
                    return Ok(HandleAction::empty());
                };
                let a_id_in_client_b = if let Some(id) = client_b.links().id_by_pk(pk) {
                    id
                } else {
                    // No a_id_in_client_b
                    return Ok(HandleAction::empty());
                };
                // it is linked, we should send data to client_b
                let packet = Packet::Data(Data {
                    connection_id: ConnectionId::from_index(a_id_in_client_b),
                    data: packet.data,
                });
                Ok(HandleAction::one(packet, client_b.tx()))
            }
        }
    }

    /** Remove timedout connected clients
     */
    fn remove_timedout_clients(&self, state: &mut ServerState) -> Result<Vec<(Packet, mpsc::Sender<Packet>)>, Error> {
        let keys = state
            .connected_clients
            .iter()
            .filter(|(_key, client)| client.is_pong_timedout())
            .map(|(key, _client)| key.clone())
            .collect::<Vec<PublicKey>>();

        let mut packets = Vec::new();

        for key in keys {
            // failure in removing one client should not affect other clients
            packets.extend(self.shutdown_client_inner(&key, state)?);
        }

        Ok(packets)
    }

    /** Send pings to all connected clients and terminate all timed out clients.
     */
    pub async fn send_pings(&self) -> Result<(), Error> {
        let mut state = self.state.write().await;

        let mut packets = self.remove_timedout_clients(&mut state)?;

        for client in state.connected_clients.values_mut() {
            if client.is_ping_interval_passed() {
                let packet = Packet::PingRequest(PingRequest {
                    ping_id: client.new_ping_id(),
                });
                packets.push((packet, client.tx()));
            }
        }

        drop(state);

        send_packets(packets).await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::relay::server::client::*;
    use crate::relay::server::{Client, Server};
    use rand::thread_rng;
    use tox_packet::dht::CryptoData;
    use tox_packet::ip_port::*;
    use tox_packet::onion::*;

    use crypto_box::{
        aead::{generic_array::typenum::marker_traits::Unsigned, AeadCore},
        SalsaBox,
    };
    use futures::channel::mpsc;
    use futures::StreamExt;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use crate::time::*;

    #[tokio::test]
    async fn server_is_clonable() {
        let server = Server::new();
        let (client_1, _rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        server.insert(client_1).await.unwrap();
        let _cloned = server.clone();
        // that's all.
    }

    /// A function that generates random keypair, random `std::net::IpAddr`,
    /// random port, creates mpsc channel and returns created with them Client
    fn create_random_client(saddr: SocketAddr) -> (Client, mpsc::Receiver<Packet>) {
        let client_pk = SecretKey::generate(&mut thread_rng()).public_key();
        let (tx, rx) = mpsc::channel(32);
        let client = Client::new(tx, &client_pk, saddr.ip(), saddr.port());
        (client, rx)
    }

    #[tokio::test]
    async fn normal_communication_scenario() {
        let server = Server::new();

        let (client_1, rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        let client_ip_addr_1 = client_1.ip_addr();
        let client_port_1 = client_1.port();

        // client 1 connects to the server
        server.insert(client_1).await.unwrap();

        let (client_2, rx_2) = create_random_client("1.2.3.5:12345".parse().unwrap());
        let client_pk_2 = client_2.pk();

        // emulate send RouteRequest from client_1
        server
            .handle_packet(
                &client_pk_1,
                Packet::RouteRequest(RouteRequest {
                    pk: client_pk_2.clone(),
                }),
            )
            .await
            .unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, rx_1) = rx_1.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::RouteResponse(RouteResponse {
                pk: client_pk_2.clone(),
                connection_id: ConnectionId::from_index(0)
            })
        );

        {
            // check links
            let state = server.state.read().await;

            // check client_1.links[client_2] == Registered
            let client_a = &state.connected_clients[&client_pk_1];
            let link_id = client_a.links().id_by_pk(&client_pk_2).unwrap();
            assert_eq!(client_a.links().by_id(link_id).unwrap().status, LinkStatus::Registered);
        }

        // client 2 connects to the server
        server.insert(client_2).await.unwrap();

        // emulate send RouteRequest from client_1 again
        server
            .handle_packet(
                &client_pk_1,
                Packet::RouteRequest(RouteRequest {
                    pk: client_pk_2.clone(),
                }),
            )
            .await
            .unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, rx_1) = rx_1.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::RouteResponse(RouteResponse {
                pk: client_pk_2.clone(),
                connection_id: ConnectionId::from_index(0)
            })
        );

        {
            // check links
            let state = server.state.read().await;

            // check client_2.links[client_1] == None
            let client_b = &state.connected_clients[&client_pk_2];
            assert!(client_b.links().id_by_pk(&client_pk_1).is_none());
        }

        // emulate send RouteRequest from client_2
        server
            .handle_packet(
                &client_pk_2,
                Packet::RouteRequest(RouteRequest {
                    pk: client_pk_1.clone(),
                }),
            )
            .await
            .unwrap();

        // the server should put RouteResponse into rx_2
        let (packet, rx_2) = rx_2.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::RouteResponse(RouteResponse {
                pk: client_pk_1.clone(),
                connection_id: ConnectionId::from_index(0)
            })
        );
        // AND
        // the server should put ConnectNotification into rx_1
        let (packet, _rx_1) = rx_1.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::ConnectNotification(ConnectNotification {
                connection_id: ConnectionId::from_index(0)
            })
        );
        // AND
        // the server should put ConnectNotification into rx_2
        let (packet, rx_2) = rx_2.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::ConnectNotification(ConnectNotification {
                connection_id: ConnectionId::from_index(0)
            })
        );

        {
            // check links
            let state = server.state.read().await;

            // check client_1.links[client_2] == Online
            let client_a = &state.connected_clients[&client_pk_1];
            let link_id = client_a.links().id_by_pk(&client_pk_2).unwrap();
            assert_eq!(client_a.links().by_id(link_id).unwrap().status, LinkStatus::Online);

            // check client_2.links[client_1] == Online
            let client_b = &state.connected_clients[&client_pk_2];
            let link_id = client_b.links().id_by_pk(&client_pk_1).unwrap();
            assert_eq!(client_a.links().by_id(link_id).unwrap().status, LinkStatus::Online);
        }

        // emulate send Data from client_1
        server
            .handle_packet(
                &client_pk_1,
                Packet::Data(Data {
                    connection_id: ConnectionId::from_index(0),
                    data: DataPayload::CryptoData(CryptoData {
                        nonce_last_bytes: 42,
                        payload: vec![42; 123],
                    }),
                }),
            )
            .await
            .unwrap();

        // the server should put Data into rx_2
        let (packet, rx_2) = rx_2.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::Data(Data {
                connection_id: ConnectionId::from_index(0),
                data: DataPayload::CryptoData(CryptoData {
                    nonce_last_bytes: 42,
                    payload: vec![42; 123],
                }),
            })
        );

        // emulate client_1 disconnected
        server
            .shutdown_client(&client_pk_1, client_ip_addr_1, client_port_1)
            .await
            .unwrap();
        // the server should put DisconnectNotification into rx_2
        let (packet, _rx_2) = rx_2.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::DisconnectNotification(DisconnectNotification {
                connection_id: ConnectionId::from_index(0)
            })
        );

        // check client_2.links[client_1] == Registered
        let state = server.state.read().await;
        let client_b = &state.connected_clients[&client_pk_2];
        assert_eq!(client_b.links().by_id(0).unwrap().status, LinkStatus::Registered);
    }
    #[tokio::test]
    async fn handle_route_request() {
        let server = Server::new();

        let (client_1, rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        let (client_2, _rx_2) = create_random_client("1.2.3.5:12345".parse().unwrap());
        let client_pk_2 = client_2.pk();
        server.insert(client_2).await.unwrap();

        // emulate send RouteRequest from client_1
        server
            .handle_packet(
                &client_pk_1,
                Packet::RouteRequest(RouteRequest {
                    pk: client_pk_2.clone(),
                }),
            )
            .await
            .unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, _rx_1) = rx_1.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::RouteResponse(RouteResponse {
                pk: client_pk_2.clone(),
                connection_id: ConnectionId::from_index(0)
            })
        );

        {
            // check links
            let state = server.state.read().await;

            // check client_1.links[client_2] == Registered
            let client_a = &state.connected_clients[&client_pk_1];
            let link_id = client_a.links().id_by_pk(&client_pk_2).unwrap();
            assert_eq!(client_a.links().by_id(link_id).unwrap().status, LinkStatus::Registered);

            // check client_2.links[client_1] == None
            let client_b = &state.connected_clients[&client_pk_2];
            assert!(client_b.links().id_by_pk(&client_pk_1).is_none());
        }
    }
    #[tokio::test]
    async fn handle_route_request_to_itself() {
        let server = Server::new();

        let (client_1, rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        // emulate send RouteRequest from client_1
        server
            .handle_packet(
                &client_pk_1,
                Packet::RouteRequest(RouteRequest {
                    pk: client_pk_1.clone(),
                }),
            )
            .await
            .unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, _rx_1) = rx_1.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::RouteResponse(RouteResponse {
                pk: client_pk_1,
                connection_id: ConnectionId::zero()
            })
        );
    }
    #[tokio::test]
    async fn handle_route_request_too_many_connections() {
        let server = Server::new();

        let (client_1, mut rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        // send 240 RouteRequest
        for i in 0..240 {
            let saddr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12346 + u16::from(i));
            let (other_client, _other_rx) = create_random_client(saddr);
            let other_client_pk = other_client.pk();
            server.insert(other_client).await.unwrap();

            // emulate send RouteRequest from client_1
            server
                .handle_packet(
                    &client_pk_1,
                    Packet::RouteRequest(RouteRequest {
                        pk: other_client_pk.clone(),
                    }),
                )
                .await
                .unwrap();

            // the server should put RouteResponse into rx_1
            let (packet, rx_1_nested) = rx_1.into_future().await;
            assert_eq!(
                packet.unwrap(),
                Packet::RouteResponse(RouteResponse {
                    pk: other_client_pk,
                    connection_id: ConnectionId::from_index(i)
                })
            );
            rx_1 = rx_1_nested;
        }
        // and send one more again
        let (other_client, _other_rx) = create_random_client("1.2.3.5:12345".parse().unwrap());
        let other_client_pk = other_client.pk();
        server.insert(other_client).await.unwrap();
        // emulate send RouteRequest from client_1
        server
            .handle_packet(
                &client_pk_1,
                Packet::RouteRequest(RouteRequest {
                    pk: other_client_pk.clone(),
                }),
            )
            .await
            .unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, _rx_1) = rx_1.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::RouteResponse(RouteResponse {
                pk: other_client_pk,
                connection_id: ConnectionId::zero()
            })
        );
    }
    #[tokio::test]
    async fn handle_connect_notification() {
        let server = Server::new();

        let (client_1, _rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        // emulate send ConnectNotification from client_1
        let handle_res = server
            .handle_packet(
                &client_pk_1,
                Packet::ConnectNotification(ConnectNotification {
                    connection_id: ConnectionId::from_index(42),
                }),
            )
            .await;
        assert!(handle_res.is_ok());
    }
    #[tokio::test]
    async fn handle_disconnect_notification() {
        let server = Server::new();

        let (client_1, rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        let (client_2, rx_2) = create_random_client("1.2.3.5:12345".parse().unwrap());
        let client_pk_2 = client_2.pk();
        server.insert(client_2).await.unwrap();

        // emulate send RouteRequest from client_1
        server
            .handle_packet(
                &client_pk_1,
                Packet::RouteRequest(RouteRequest {
                    pk: client_pk_2.clone(),
                }),
            )
            .await
            .unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, rx_1) = rx_1.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::RouteResponse(RouteResponse {
                pk: client_pk_2.clone(),
                connection_id: ConnectionId::from_index(0)
            })
        );

        // emulate send RouteRequest from client_2
        server
            .handle_packet(
                &client_pk_2,
                Packet::RouteRequest(RouteRequest {
                    pk: client_pk_1.clone(),
                }),
            )
            .await
            .unwrap();

        // the server should put RouteResponse into rx_2
        let (packet, rx_2) = rx_2.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::RouteResponse(RouteResponse {
                pk: client_pk_1.clone(),
                connection_id: ConnectionId::from_index(0)
            })
        );
        // AND
        // the server should put ConnectNotification into rx_1
        let (packet, rx_1) = rx_1.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::ConnectNotification(ConnectNotification {
                connection_id: ConnectionId::from_index(0)
            })
        );
        // AND
        // the server should put ConnectNotification into rx_2
        let (packet, rx_2) = rx_2.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::ConnectNotification(ConnectNotification {
                connection_id: ConnectionId::from_index(0)
            })
        );

        {
            // check links
            let state = server.state.read().await;

            // check client_1.links[client_2] == Online
            let client_a = &state.connected_clients[&client_pk_1];
            let link_id = client_a.links().id_by_pk(&client_pk_2).unwrap();
            assert_eq!(client_a.links().by_id(link_id).unwrap().status, LinkStatus::Online);

            // check client_2.links[client_1] == Online
            let client_b = &state.connected_clients[&client_pk_2];
            let link_id = client_b.links().id_by_pk(&client_pk_1).unwrap();
            assert_eq!(client_a.links().by_id(link_id).unwrap().status, LinkStatus::Online);
        }

        // emulate send DisconnectNotification from client_1
        server
            .handle_packet(
                &client_pk_1,
                Packet::DisconnectNotification(DisconnectNotification {
                    connection_id: ConnectionId::from_index(0),
                }),
            )
            .await
            .unwrap();

        // the server should put DisconnectNotification into rx_2
        let (packet, _rx_2) = rx_2.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::DisconnectNotification(DisconnectNotification {
                connection_id: ConnectionId::from_index(0)
            })
        );

        {
            // check links
            let state = server.state.read().await;

            // check client_1.links[client_2] == None
            let client_a = &state.connected_clients[&client_pk_1];
            assert!(client_a.links().id_by_pk(&client_pk_2).is_none());

            // check client_2.links[client_1] == Registered
            let client_b = &state.connected_clients[&client_pk_2];
            let link_id = client_b.links().id_by_pk(&client_pk_1).unwrap();
            assert_eq!(client_b.links().by_id(link_id).unwrap().status, LinkStatus::Registered);
        }

        // emulate send DisconnectNotification from client_2
        server
            .handle_packet(
                &client_pk_2,
                Packet::DisconnectNotification(DisconnectNotification {
                    connection_id: ConnectionId::from_index(0),
                }),
            )
            .await
            .unwrap();

        {
            // check links
            let state = server.state.read().await;

            // check client_2.links[client_1] == None
            let client_b = &state.connected_clients[&client_pk_2];
            assert!(client_b.links().id_by_pk(&client_pk_2).is_none());
        }

        // check that DisconnectNotification from client_2 did not put anything in client1.rx
        // necessary to drop server so that rx.collect() can be finished
        drop(server);
        assert!(rx_1.collect::<Vec<_>>().await.is_empty());
    }
    #[tokio::test]
    async fn handle_disconnect_notification_other_not_linked() {
        let server = Server::new();

        let (client_1, _rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        let (client_2, rx_2) = create_random_client("1.2.3.5:12345".parse().unwrap());
        let client_pk_2 = client_2.pk();
        server.insert(client_2).await.unwrap();

        // emulate send RouteRequest from client_1
        server
            .handle_packet(&client_pk_1, Packet::RouteRequest(RouteRequest { pk: client_pk_2 }))
            .await
            .unwrap();

        // emulate send DisconnectNotification from client_1
        let handle_res = server
            .handle_packet(
                &client_pk_1,
                Packet::DisconnectNotification(DisconnectNotification {
                    connection_id: ConnectionId::from_index(0),
                }),
            )
            .await;
        assert!(handle_res.is_ok());

        // check that packets from client_1 did not put anything in client2.rx
        // necessary to drop server so that rx.collect() can be finished
        drop(server);
        assert!(rx_2.collect::<Vec<_>>().await.is_empty());
    }
    #[tokio::test]
    async fn handle_disconnect_notification_0() {
        let server = Server::new();

        let client_pk = SecretKey::generate(&mut thread_rng()).public_key();

        let handle_res = server
            .handle_packet(
                &client_pk,
                Packet::DisconnectNotification(DisconnectNotification {
                    connection_id: ConnectionId::zero(),
                }),
            )
            .await;
        assert!(handle_res.is_err());
    }
    #[tokio::test]
    async fn handle_ping_request() {
        let server = Server::new();

        let (client_1, rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        // emulate send PingRequest from client_1
        server
            .handle_packet(&client_pk_1, Packet::PingRequest(PingRequest { ping_id: 42 }))
            .await
            .unwrap();

        // the server should put PongResponse into rx_1
        let (packet, _rx_1) = rx_1.into_future().await;
        assert_eq!(packet.unwrap(), Packet::PongResponse(PongResponse { ping_id: 42 }));
    }
    #[tokio::test]
    async fn handle_oob_send() {
        let server = Server::new();

        let (client_1, _rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        let (client_2, rx_2) = create_random_client("1.2.3.5:12345".parse().unwrap());
        let client_pk_2 = client_2.pk();
        server.insert(client_2).await.unwrap();

        // emulate send OobSend from client_1
        server
            .handle_packet(
                &client_pk_1,
                Packet::OobSend(OobSend {
                    destination_pk: client_pk_2,
                    data: vec![13; 1024],
                }),
            )
            .await
            .unwrap();

        // the server should put OobReceive into rx_2
        let (packet, _rx_2) = rx_2.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::OobReceive(OobReceive {
                sender_pk: client_pk_1,
                data: vec![13; 1024]
            })
        );
    }
    #[tokio::test]
    async fn handle_onion_request() {
        let (udp_onion_sink, udp_onion_stream) = mpsc::channel(1);
        let mut server = Server::new();
        server.set_udp_onion_sink(udp_onion_sink);

        let (client_1, _rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        let client_addr_1 = client_1.ip_addr();
        let client_port_1 = client_1.port();
        server.insert(client_1).await.unwrap();

        let request = OnionRequest {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            ip_port: IpPort {
                protocol: ProtocolType::Tcp,
                ip_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                port: 12345,
            },
            temporary_pk: SecretKey::generate(&mut thread_rng()).public_key(),
            payload: vec![13; 170],
        };
        let handle_res = server
            .handle_packet(&client_pk_1, Packet::OnionRequest(request.clone()))
            .await;
        assert!(handle_res.is_ok());

        let (packet, _) = udp_onion_stream.into_future().await;
        let (packet, saddr) = packet.unwrap();

        assert_eq!(saddr.ip(), client_addr_1);
        assert_eq!(saddr.port(), client_port_1);
        assert_eq!(packet, request);
    }
    #[tokio::test]
    async fn handle_udp_onion_response() {
        let server = Server::new();

        let (client_1, rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_addr_1 = client_1.ip_addr();
        let client_port_1 = client_1.port();
        server.insert(client_1).await.unwrap();

        let payload = InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 123],
        });
        let handle_res = server
            .handle_udp_onion_response(client_addr_1, client_port_1, payload.clone())
            .await;
        assert!(handle_res.is_ok());

        let (packet, _) = rx_1.into_future().await;
        assert_eq!(packet.unwrap(), Packet::OnionResponse(OnionResponse { payload }));
    }
    #[tokio::test]
    async fn insert_with_same_pk() {
        let server = Server::new();

        let (mut client_1, _rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let (mut client_2, rx_2) = create_random_client("1.2.3.4:12346".parse().unwrap());

        // link client_1 with client_2
        let index_1 = client_1.links_mut().insert(client_2.pk()).unwrap();
        assert!(client_1.links_mut().upgrade(index_1));
        let index_2 = client_2.links_mut().insert(client_1.pk()).unwrap();
        assert!(client_2.links_mut().upgrade(index_2));

        let client_pk_1 = client_1.pk();
        let client_addr_3 = "1.2.3.4".parse().unwrap();
        let client_port_3 = 12347;
        let (tx_3, _rx_3) = mpsc::channel(32);
        let client_3 = Client::new(tx_3, &client_pk_1, client_addr_3, client_port_3);

        server.insert(client_1).await.unwrap();
        server.insert(client_2).await.unwrap();

        // replace client_1 with client_3
        server.insert(client_3).await.unwrap();

        let (packet, _) = rx_2.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::DisconnectNotification(DisconnectNotification {
                connection_id: ConnectionId::from_index(index_2)
            })
        );

        let state = server.state.read().await;
        let client = &state.connected_clients[&client_pk_1];

        assert_eq!(client.ip_addr(), client_addr_3);
        assert_eq!(client.port(), client_port_3);
    }
    #[tokio::test]
    async fn shutdown_other_not_linked() {
        let server = Server::new();

        let (client_1, rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        let client_ip_addr_1 = client_1.ip_addr();
        let client_port_1 = client_1.port();
        server.insert(client_1).await.unwrap();

        let (client_2, _rx_2) = create_random_client("1.2.3.5:12345".parse().unwrap());
        let client_pk_2 = client_2.pk();
        server.insert(client_2).await.unwrap();

        // emulate send RouteRequest from client_1
        server
            .handle_packet(
                &client_pk_1,
                Packet::RouteRequest(RouteRequest {
                    pk: client_pk_2.clone(),
                }),
            )
            .await
            .unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, _rx_1) = rx_1.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::RouteResponse(RouteResponse {
                pk: client_pk_2,
                connection_id: ConnectionId::from_index(0)
            })
        );

        // emulate shutdown
        let handle_res = server
            .shutdown_client(&client_pk_1, client_ip_addr_1, client_port_1)
            .await;
        assert!(handle_res.is_ok());
    }
    #[tokio::test]
    async fn handle_data_other_not_linked() {
        let server = Server::new();

        let (client_1, rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        let (client_2, _rx_2) = create_random_client("1.2.3.5:12345".parse().unwrap());
        let client_pk_2 = client_2.pk();
        server.insert(client_2).await.unwrap();

        // emulate send RouteRequest from client_1
        server
            .handle_packet(
                &client_pk_1,
                Packet::RouteRequest(RouteRequest {
                    pk: client_pk_2.clone(),
                }),
            )
            .await
            .unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, _rx_1) = rx_1.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::RouteResponse(RouteResponse {
                pk: client_pk_2,
                connection_id: ConnectionId::from_index(0)
            })
        );

        // emulate send Data from client_1
        let handle_res = server
            .handle_packet(
                &client_pk_1,
                Packet::Data(Data {
                    connection_id: ConnectionId::from_index(0),
                    data: DataPayload::CryptoData(CryptoData {
                        nonce_last_bytes: 42,
                        payload: vec![42; 123],
                    }),
                }),
            )
            .await;
        assert!(handle_res.is_ok());
    }
    #[tokio::test]
    async fn handle_data_0() {
        let server = Server::new();

        let client_pk = SecretKey::generate(&mut thread_rng()).public_key();

        let handle_res = server
            .handle_packet(
                &client_pk,
                Packet::Data(Data {
                    connection_id: ConnectionId::zero(),
                    data: DataPayload::CryptoData(CryptoData {
                        nonce_last_bytes: 42,
                        payload: vec![42; 123],
                    }),
                }),
            )
            .await;
        assert!(handle_res.is_err());
    }

    ////////////////////////////////////////////////////////////////////////////////////////
    // Here be all handle_* tests with wrong args
    #[tokio::test]
    async fn handle_route_response() {
        let server = Server::new();

        let (client_1, _rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        // emulate send RouteResponse from client_1
        let handle_res = server
            .handle_packet(
                &client_pk_1,
                Packet::RouteResponse(RouteResponse {
                    pk: client_pk_1.clone(),
                    connection_id: ConnectionId::from_index(42),
                }),
            )
            .await;
        assert!(handle_res.is_err());
    }
    #[tokio::test]
    async fn handle_disconnect_notification_not_linked() {
        let server = Server::new();

        let (client_1, rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        // emulate send DisconnectNotification from client_1
        let handle_res = server
            .handle_packet(
                &client_pk_1,
                Packet::DisconnectNotification(DisconnectNotification {
                    connection_id: ConnectionId::from_index(0),
                }),
            )
            .await;
        assert!(handle_res.is_ok());

        // Necessary to drop tx so that rx.collect() can be finished
        drop(server);

        assert!(rx_1.collect::<Vec<_>>().await.is_empty());
    }
    #[tokio::test]
    async fn handle_ping_request_0() {
        let server = Server::new();

        let (client_1, _rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        // emulate send PingRequest from client_1
        let handle_res = server
            .handle_packet(&client_pk_1, Packet::PingRequest(PingRequest { ping_id: 0 }))
            .await;
        assert!(handle_res.is_err());
    }
    #[tokio::test]
    async fn handle_pong_response_0() {
        let server = Server::new();

        let (client_1, _rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        // emulate send PongResponse from client_1
        let handle_res = server
            .handle_packet(&client_pk_1, Packet::PongResponse(PongResponse { ping_id: 0 }))
            .await;
        assert!(handle_res.is_err());
    }
    #[tokio::test]
    async fn handle_oob_send_empty_data() {
        let server = Server::new();

        let (client_1, _rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        let (client_2, _rx_2) = create_random_client("1.2.3.5:12345".parse().unwrap());
        let client_pk_2 = client_2.pk();
        server.insert(client_2).await.unwrap();

        // emulate send OobSend from client_1
        let handle_res = server
            .handle_packet(
                &client_pk_1,
                Packet::OobSend(OobSend {
                    destination_pk: client_pk_2,
                    data: vec![],
                }),
            )
            .await;
        assert!(handle_res.is_err());
    }
    #[tokio::test]
    async fn handle_data_self_not_linked() {
        let server = Server::new();

        let (client_1, rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        // emulate send Data from client_1
        let handle_res = server
            .handle_packet(
                &client_pk_1,
                Packet::Data(Data {
                    connection_id: ConnectionId::from_index(0),
                    data: DataPayload::CryptoData(CryptoData {
                        nonce_last_bytes: 42,
                        payload: vec![42; 123],
                    }),
                }),
            )
            .await;
        assert!(handle_res.is_ok());

        // Necessary to drop tx so that rx.collect() can be finished
        drop(server);

        assert!(rx_1.collect::<Vec<_>>().await.is_empty());
    }
    #[tokio::test]
    async fn handle_oob_send_to_loooong_data() {
        let server = Server::new();

        let (client_1, _rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        let (client_2, _rx_2) = create_random_client("1.2.3.5:12345".parse().unwrap());
        let client_pk_2 = client_2.pk();
        server.insert(client_2).await.unwrap();

        // emulate send OobSend from client_1
        let handle_res = server
            .handle_packet(
                &client_pk_1,
                Packet::OobSend(OobSend {
                    destination_pk: client_pk_2,
                    data: vec![42; 1024 + 1],
                }),
            )
            .await;
        assert!(handle_res.is_err());
    }
    #[tokio::test]
    async fn handle_oob_recv() {
        let server = Server::new();

        let (client_1, _rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        let (client_2, _rx_2) = create_random_client("1.2.3.5:12345".parse().unwrap());
        let client_pk_2 = client_2.pk();
        server.insert(client_2).await.unwrap();

        // emulate send OobReceive from client_1
        let handle_res = server
            .handle_packet(
                &client_pk_1,
                Packet::OobReceive(OobReceive {
                    sender_pk: client_pk_2,
                    data: vec![42; 1024],
                }),
            )
            .await;
        assert!(handle_res.is_err());
    }
    #[tokio::test]
    async fn handle_onion_request_disabled_onion_loooong_data() {
        let server = Server::new();

        let (client_1, _rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        let request = OnionRequest {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            ip_port: IpPort {
                protocol: ProtocolType::Tcp,
                ip_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                port: 12345,
            },
            temporary_pk: SecretKey::generate(&mut thread_rng()).public_key(),
            payload: vec![13; 1500],
        };
        let handle_res = server.handle_packet(&client_pk_1, Packet::OnionRequest(request)).await;
        assert!(handle_res.is_ok());
    }
    #[tokio::test]
    async fn handle_onion_response() {
        let server = Server::new();

        let (client_1, _rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        let payload = InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 123],
        });
        let handle_res = server
            .handle_packet(&client_pk_1, Packet::OnionResponse(OnionResponse { payload }))
            .await;
        assert!(handle_res.is_err());
    }
    #[tokio::test]
    async fn handle_udp_onion_response_for_unknown_client() {
        let (udp_onion_sink, _) = mpsc::channel(1);
        let mut server = Server::new();
        server.set_udp_onion_sink(udp_onion_sink);

        let client_addr_1 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let client_port_1 = 12345u16;
        let client_pk_1 = SecretKey::generate(&mut thread_rng()).public_key();
        let (tx_1, _rx_1) = mpsc::channel(1);
        let client_1 = Client::new(tx_1, &client_pk_1, client_addr_1, client_port_1);
        server.insert(client_1).await.unwrap();

        let client_addr_2 = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        let client_port_2 = 54321u16;

        let payload = InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 123],
        });
        let handle_res = server
            .handle_udp_onion_response(client_addr_2, client_port_2, payload)
            .await;
        assert!(handle_res.is_err());
    }

    ////////////////////////////////////////////////////////////////////////////////////////
    // Here be all handle_* tests from PK or to PK not in connected clients list
    #[tokio::test]
    async fn handle_route_request_not_connected() {
        let mut rng = thread_rng();
        let server = Server::new();
        let client_pk_1 = SecretKey::generate(&mut rng).public_key();
        let client_pk_2 = SecretKey::generate(&mut rng).public_key();

        // emulate send RouteRequest from client_pk_1
        let handle_res = server
            .handle_packet(&client_pk_1, Packet::RouteRequest(RouteRequest { pk: client_pk_2 }))
            .await;
        assert!(handle_res.is_err());
    }
    #[tokio::test]
    async fn handle_disconnect_notification_not_connected() {
        let server = Server::new();
        let client_pk_1 = SecretKey::generate(&mut thread_rng()).public_key();

        // emulate send DisconnectNotification from client_1
        let handle_res = server
            .handle_packet(
                &client_pk_1,
                Packet::DisconnectNotification(DisconnectNotification {
                    connection_id: ConnectionId::from_index(42),
                }),
            )
            .await;
        assert!(handle_res.is_err());
    }
    #[tokio::test]
    async fn handle_disconnect_notification_other_not_connected() {
        let server = Server::new();

        let (client_1, _rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        let client_pk_2 = SecretKey::generate(&mut thread_rng()).public_key();

        // emulate send RouteRequest from client_1
        server
            .handle_packet(&client_pk_1, Packet::RouteRequest(RouteRequest { pk: client_pk_2 }))
            .await
            .unwrap();

        // emulate send DisconnectNotification from client_1
        let handle_res = server
            .handle_packet(
                &client_pk_1,
                Packet::DisconnectNotification(DisconnectNotification {
                    connection_id: ConnectionId::from_index(0),
                }),
            )
            .await;
        assert!(handle_res.is_ok());
    }
    #[tokio::test]
    async fn handle_ping_request_not_connected() {
        let server = Server::new();
        let client_pk_1 = SecretKey::generate(&mut thread_rng()).public_key();

        // emulate send PingRequest from client_1
        let handle_res = server
            .handle_packet(&client_pk_1, Packet::PingRequest(PingRequest { ping_id: 42 }))
            .await;
        assert!(handle_res.is_err());
    }
    #[tokio::test]
    async fn handle_pong_response_not_connected() {
        let server = Server::new();
        let client_pk_1 = SecretKey::generate(&mut thread_rng()).public_key();

        // emulate send PongResponse from client_1
        let handle_res = server
            .handle_packet(&client_pk_1, Packet::PongResponse(PongResponse { ping_id: 42 }))
            .await;
        assert!(handle_res.is_err());
    }
    #[tokio::test]
    async fn handle_oob_send_not_connected() {
        let mut rng = thread_rng();
        let server = Server::new();
        let client_pk_1 = SecretKey::generate(&mut rng).public_key();
        let client_pk_2 = SecretKey::generate(&mut rng).public_key();

        // emulate send OobSend from client_1
        let handle_res = server
            .handle_packet(
                &client_pk_1,
                Packet::OobSend(OobSend {
                    destination_pk: client_pk_2,
                    data: vec![42; 1024],
                }),
            )
            .await;
        assert!(handle_res.is_ok());
    }
    #[tokio::test]
    async fn handle_data_not_connected() {
        let server = Server::new();
        let client_pk_1 = SecretKey::generate(&mut thread_rng()).public_key();

        // emulate send Data from client_1
        let handle_res = server
            .handle_packet(
                &client_pk_1,
                Packet::Data(Data {
                    connection_id: ConnectionId::from_index(0),
                    data: DataPayload::CryptoData(CryptoData {
                        nonce_last_bytes: 42,
                        payload: vec![42; 123],
                    }),
                }),
            )
            .await;
        assert!(handle_res.is_err());
    }
    #[tokio::test]
    async fn handle_data_other_not_connected() {
        let server = Server::new();

        let (client_1, rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        let client_pk_2 = SecretKey::generate(&mut thread_rng()).public_key();

        // emulate send RouteRequest from client_1
        server
            .handle_packet(
                &client_pk_1,
                Packet::RouteRequest(RouteRequest {
                    pk: client_pk_2.clone(),
                }),
            )
            .await
            .unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, _rx_1) = rx_1.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::RouteResponse(RouteResponse {
                pk: client_pk_2,
                connection_id: ConnectionId::from_index(0)
            })
        );

        // emulate send Data from client_1
        let handle_res = server
            .handle_packet(
                &client_pk_1,
                Packet::Data(Data {
                    connection_id: ConnectionId::from_index(0),
                    data: DataPayload::CryptoData(CryptoData {
                        nonce_last_bytes: 42,
                        payload: vec![42; 123],
                    }),
                }),
            )
            .await;
        assert!(handle_res.is_ok());
    }
    #[tokio::test]
    async fn shutdown_different_addr() {
        let server = Server::new();

        let (client, _rx) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk = client.pk();
        server.insert(client).await.unwrap();

        // emulate shutdown
        let handle_res = server
            .shutdown_client(&client_pk, "1.2.3.4".parse().unwrap(), 12346)
            .await;
        assert!(handle_res.is_err());

        let state = server.state.read().await;

        assert!(state.connected_clients.contains_key(&client_pk));
    }
    #[tokio::test]
    async fn shutdown_not_connected() {
        let server = Server::new();
        let client_pk = SecretKey::generate(&mut thread_rng()).public_key();
        let client_ip_addr = "1.2.3.4".parse().unwrap();
        let client_port = 12345;

        // emulate shutdown
        let handle_res = server.shutdown_client(&client_pk, client_ip_addr, client_port).await;
        assert!(handle_res.is_err());
    }
    #[tokio::test]
    async fn shutdown_inner_not_connected() {
        let server = Server::new();
        let client_pk = SecretKey::generate(&mut thread_rng()).public_key();

        let mut state = server.state.write().await;

        // emulate shutdown
        let handle_res = server.shutdown_client_inner(&client_pk, &mut state);
        assert!(handle_res.is_err());
    }
    #[tokio::test]
    async fn shutdown_other_not_connected() {
        let server = Server::new();

        let (client_1, rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        let client_ip_addr_1 = client_1.ip_addr();
        let client_port_1 = client_1.port();
        server.insert(client_1).await.unwrap();

        let client_pk_2 = SecretKey::generate(&mut thread_rng()).public_key();

        // emulate send RouteRequest from client_1
        server
            .handle_packet(
                &client_pk_1,
                Packet::RouteRequest(RouteRequest {
                    pk: client_pk_2.clone(),
                }),
            )
            .await
            .unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, _rx_1) = rx_1.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::RouteResponse(RouteResponse {
                pk: client_pk_2,
                connection_id: ConnectionId::from_index(0)
            })
        );

        // emulate shutdown
        let handle_res = server
            .shutdown_client(&client_pk_1, client_ip_addr_1, client_port_1)
            .await;
        assert!(handle_res.is_ok());
    }
    #[tokio::test]
    async fn send_anything_to_dropped_client() {
        let server = Server::new();

        let (client_1, rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        let (client_2, _rx_2) = create_random_client("1.2.3.5:12345".parse().unwrap());
        let client_pk_2 = client_2.pk();
        server.insert(client_2).await.unwrap();

        drop(rx_1);

        // emulate send RouteRequest from client_1
        let handle_res = server
            .handle_packet(&client_pk_1, Packet::RouteRequest(RouteRequest { pk: client_pk_2 }))
            .await;
        assert!(handle_res.is_ok())
    }
    #[tokio::test]
    async fn send_onion_request_to_dropped_stream() {
        let (udp_onion_sink, udp_onion_stream) = mpsc::channel(1);
        let mut server = Server::new();
        server.set_udp_onion_sink(udp_onion_sink);

        let (client_1, _rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let client_pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        drop(udp_onion_stream);

        // emulate send OnionRequest from client_1
        let request = OnionRequest {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            ip_port: IpPort {
                protocol: ProtocolType::Tcp,
                ip_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                port: 12345,
            },
            temporary_pk: SecretKey::generate(&mut thread_rng()).public_key(),
            payload: vec![13; 170],
        };
        let handle_res = server.handle_packet(&client_pk_1, Packet::OnionRequest(request)).await;
        assert!(handle_res.is_ok());
    }
    #[tokio::test]
    async fn tcp_send_pings_test() {
        let server = Server::new();

        // client #1
        let (client_1, rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        // client #2
        let (client_2, rx_2) = create_random_client("1.2.3.5:12345".parse().unwrap());
        let pk_2 = client_2.pk();
        server.insert(client_2).await.unwrap();

        // client #3
        let (client_3, rx_3) = create_random_client("1.2.3.6:12345".parse().unwrap());
        let pk_3 = client_3.pk();
        server.insert(client_3).await.unwrap();

        tokio::time::pause();
        // time when all entries is needed to send PingRequest
        tokio::time::advance(TCP_PING_FREQUENCY + Duration::from_secs(1)).await;

        let sender_res = server.send_pings().await;
        assert!(sender_res.is_ok());

        let (packet, _rx_1) = rx_1.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::PingRequest(PingRequest {
                ping_id: server.state.read().await.connected_clients[&pk_1].ping_id()
            })
        );
        let (packet, _rx_2) = rx_2.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::PingRequest(PingRequest {
                ping_id: server.state.read().await.connected_clients[&pk_2].ping_id()
            })
        );
        let (packet, _rx_3) = rx_3.into_future().await;
        assert_eq!(
            packet.unwrap(),
            Packet::PingRequest(PingRequest {
                ping_id: server.state.read().await.connected_clients[&pk_3].ping_id()
            })
        );
    }
    #[tokio::test]
    async fn tcp_send_remove_timedouts() {
        let server = Server::new();

        // client #1
        let (client_1, _rx_1) = create_random_client("1.2.3.4:12345".parse().unwrap());
        let pk_1 = client_1.pk();
        server.insert(client_1).await.unwrap();

        // client #2
        let (client_2, _rx_2) = create_random_client("1.2.3.5:12345".parse().unwrap());
        let pk_2 = client_2.pk();
        server.insert(client_2).await.unwrap();

        // client #3
        let (mut client_3, _rx_3) = create_random_client("1.2.3.6:12345".parse().unwrap());
        let pk_3 = client_3.pk();

        tokio::time::pause();
        // time when all entries is timedout and should be removed
        tokio::time::advance(TCP_PING_FREQUENCY + TCP_PING_TIMEOUT + Duration::from_secs(1)).await;

        client_3.set_last_pong_resp(clock_now());
        server.insert(client_3).await.unwrap();
        let sender_res = server.send_pings().await;
        assert!(sender_res.is_ok());

        assert!(!server.state.read().await.connected_clients.contains_key(&pk_1));
        assert!(!server.state.read().await.connected_clients.contains_key(&pk_2));
        assert!(server.state.read().await.connected_clients.contains_key(&pk_3));
    }
}
