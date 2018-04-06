/*
    Copyright © 2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2018 Namsoo CHO <nscho66@gmail.com>

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


/*!
Functionality needed to work as a DHT node.
This module works on top of other modules.
*/

use futures::{Stream, future, stream};
use futures::sync::mpsc;
use parking_lot::RwLock;
use tokio_io::IoFuture;

use std::io::{ErrorKind, Error};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::Arc;

use toxcore::crypto_core::*;
use toxcore::dht::packet::*;
use toxcore::dht::packed_node::*;
use toxcore::dht::kbucket::*;
use toxcore::dht::client::*;
use toxcore::onion::packet::*;

/// Shorthand for the transmit half of the message channel.
type Tx = mpsc::UnboundedSender<(DhtPacket, SocketAddr)>;

/**
Own DHT node data.

Contains:

- DHT public key
- DHT secret key
- Close List ([`Kbucket`] with nodes close to own DHT public key)

Before a [`PackedNode`] is added to the Close List, it needs to be
checked whether:

- it can be added to [`Kbucket`] \(using [`Kbucket::can_add()`])
- [`PackedNode`] is actually online

Once the first check passes node is added to the temporary list, and
a [`NodesRequest`] request is sent to it in order to check whether it's
online. If the node responds correctly within [`PING_TIMEOUT`], it's
removed from temporary list and added to the Close List.

[`NodesRequest`]: ../dht/struct.NodesRequest.html
[`Kbucket`]: ../dht/struct.Kbucket.html
[`Kbucket::can_add()`]: ../dht/struct.Kbucket.html#method.can_add
[`PackedNode`]: ../dht/struct.PackedNode.html
*/
#[derive(Clone)]
pub struct Server {
    /// secret key
    pub sk: SecretKey,
    /// public key
    pub pk: PublicKey,
    /// tx split of channel to send packet to this peer via udp socket
    pub tx: Tx,
    // struct to hold info of server states.
    state: Arc<RwLock<ServerState>>,
    // symmetric key used for onion return encryption
    onion_symmetric_key: Arc<RwLock<PrecomputedKey>>,
}

#[derive(Debug)]
// hold client object connected and kbucket object, this struct object is shared by threads
struct ServerState {
    /// store client object which has sent request packet to peer
    pub peers_cache: HashMap<PublicKey, Client>,
    /// Close List (contains nodes close to own DHT PK)
    pub kbucket: Kbucket,
}

impl Server {
    /**
    Create new `Server` instance.
    */
    pub fn new(tx: Tx, pk: PublicKey, sk: SecretKey) -> Server {
        let kbucket = Kbucket::new(KBUCKET_BUCKETS, &pk);

        debug!("Created new Server instance");
        Server {
            sk,
            pk,
            tx,
            state: Arc::new(RwLock::new(ServerState {
                peers_cache: HashMap::new(),
                kbucket,
            })),
            onion_symmetric_key: Arc::new(RwLock::new(new_symmetric_key())),
        }
    }

    /// create new client
    pub fn create_client(&self, addr: &SocketAddr, pk: PublicKey) -> Client {
        let precomputed_key = encrypt_precompute(&pk, &self.sk);
        Client::new(precomputed_key, self.pk, *addr, self.tx.clone())
    }
    /// get client from cache
    pub fn get_client(&self, pk: &PublicKey) -> Option<Client> {
        let state = self.state.read();
        // Client entry is inserted before sending *Request.
        if let Some(client) = state.peers_cache.get(pk) {
            Some(client.clone())
        }
        else {
            None
        }
    }
    /// send PingRequest to all peer in kbucket    
    pub fn send_pings(&self) -> IoFuture<()> {
        let mut state = self.state.write();
        let kbucket_c = state.kbucket.iter();

        let ping_sender = kbucket_c.map(move |peer| {
            let mut client = self.create_client(&peer.saddr, peer.pk);
            let result = client.send_ping_request();
            state.peers_cache.insert(peer.pk, client);
            result
        });

        let pings_stream = stream::futures_unordered(ping_sender).then(|_| Ok(()));

        Box::new(pings_stream.for_each(|()| Ok(())))
    }
    /// send NodesRequest to random peer at every 20 seconds
    pub fn send_nodes_req(&self, friend_pk: PublicKey) -> IoFuture<()> {
        let mut state = self.state.write();
        if let Some(peer) = state.kbucket.get_random_node() {
            let mut client = self.create_client(&peer.saddr, peer.pk);
            let result = client.send_nodes_request(friend_pk);
            state.peers_cache.insert(peer.pk, client);
            result
        }
        else {
            return Box::new(future::ok(()));
        }
    }
    /// send NatPingRequests to peers at every 3 seconds
    pub fn send_nat_ping_req(&self, peer: PackedNode, friend_pk: PublicKey) -> IoFuture<()> {
        let mut client = self.create_client(&peer.saddr, peer.pk);
        let result = client.send_nat_ping_request(friend_pk);
        let mut state = self.state.write();
        state.peers_cache.insert(peer.pk, client);
        result
    }
    /**
    Function to handle incoming packets. If there is a response packet,
    send back it to the peer.
    */
    pub fn handle_packet(&self, (packet, addr): (DhtPacket, SocketAddr)) -> IoFuture<()>
    {
        match packet {
            DhtPacket::PingRequest(packet) => {
                debug!("Received ping request");
                let client = self.create_client(&addr, packet.pk);
                self.handle_ping_req(client, packet)
            },
            DhtPacket::PingResponse(packet) => {
                debug!("Received ping response");
                if let Some(client) = self.get_client(&packet.pk) {
                    self.handle_ping_resp(client, packet)
                } else { // If there doesn't exist client in hash, then the PingRequest sent is not from me. Do nothing.
                    Box::new(future::ok(()))
                }
            },
            DhtPacket::NodesRequest(packet) => {
                debug!("Received NodesRequest");
                let client = self.create_client(&addr, packet.pk);
                self.handle_nodes_req(client, packet)
            },
            DhtPacket::NodesResponse(packet) => {
                debug!("Received NodesResponse");
                if let Some(client) = self.get_client(&packet.pk) {
                    self.handle_nodes_resp(client, packet)
                } else { // If there doesn't exist client in hash, then the NodesRequest sent is not from me. Do nothing.
                    Box::new(future::ok(()))
                }
            },
            DhtPacket::DhtRequest(dr) => {
                // The packet kind of DhtRequest is in encrypted payload,
                // so decrypting is needed first.
                let payload = dr.get_payload(&self.sk)
                    .map(|p| p)
                    .map_err(|e| {
                        e
                    });
                match payload {
                    Ok(DhtRequestPayload::NatPingRequest(pl)) => {
                        debug!("Received nat ping request");
                        let client = self.create_client(&addr, dr.spk);
                        self.handle_nat_ping_req(client, dr, pl)
                    },
                    Ok(DhtRequestPayload::NatPingResponse(pl)) => {
                        debug!("Received nat ping response");
                        if let Some(client) = self.get_client(&dr.spk) {
                            self.handle_nat_ping_resp(client, dr, pl)
                        } else { // If there doesn't exist client in hash, then the PingRequest sent is not from me. Do nothing.
                            Box::new(future::ok(()))
                        }
                    },
                    _p => {
                        Box::new( future::err(
                            Error::new(ErrorKind::Other,
                                "received packet are not handled"
                        )))
                    },
                }
            },
            DhtPacket::LanDiscovery(packet) => {
                debug!("Received LanDiscovery");
                let client = self.create_client(&addr, packet.pk);
                self.handle_lan_discovery(client, packet)
            },
            DhtPacket::OnionRequest0(packet) => {
                debug!("Received OnionRequest0");
                self.handle_onion_request_0(packet, addr)
            },
            DhtPacket::OnionRequest1(packet) => {
                debug!("Received OnionRequest1");
                self.handle_onion_request_1(packet, addr)
            },
            DhtPacket::OnionRequest2(packet) => {
                debug!("Received OnionRequest2");
                self.handle_onion_request_2(packet, addr)
            },
            DhtPacket::OnionResponse3(packet) => {
                debug!("Received OnionResponse3");
                self.handle_onion_response_3(packet)
            },
            DhtPacket::OnionResponse2(packet) => {
                debug!("Received OnionResponse2");
                self.handle_onion_response_2(packet)
            },
            DhtPacket::OnionResponse1(packet) => {
                debug!("Received OnionResponse1");
                self.handle_onion_response_1(packet)
            },
            ref p => {
                error!("received packet are not handled {:?}", p);
                Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "received packet are not handled"
                )))
            }
        }
    }
    /**
    handle received PingRequest packet, then create PingResponse packet
    and send back it to the peer.
    */
    fn handle_ping_req(&self, client: Client, request: PingRequest) -> IoFuture<()>
    {
        if let Ok(payload) = request.get_payload(&self.sk) {
            let resp_payload = PingResponsePayload {
                id: payload.id,
            };
            client.send_ping_response(resp_payload)
        }
        else {
            error!("get_payload() fail upon PingRequest");
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "get_payload() fail upon PingRequest"
            )))
        }
    }
    /**
    handle received PingResponse packet. If ping_id is correct, try_add peer to kbucket.
    */
    fn handle_ping_resp(&self, client: Client, request: PingResponse) -> IoFuture<()>
    {
        if let Ok(payload) = request.get_payload(&self.sk) {
            if payload.id == 0 {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "PingResponse.ping_id == 0"
                )))
            }
            if client.ping_id == payload.id {
                let packed_node = PackedNode {
                    saddr: client.addr,
                    pk: request.pk,
                };
                let mut state = self.state.write();
                state.kbucket.try_add(&packed_node);
                Box::new( future::ok(()) )
            }
            else {
                Box::new( future::err(
                    Error::new(ErrorKind::Other, "PingResponse.ping_id does not match")
                ))
            }
        }
        else {
            error!("get_payload() fail upon PingResponse");
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "get_payload() fail upon PingResponse"
            )))
        }
    }
    /**
    handle received NodesRequest packet, responds with NodesResponse
    */
    fn handle_nodes_req(&self, client: Client, request: NodesRequest) -> IoFuture<()> {
        if let Ok(payload) = request.get_payload(&self.sk) {
            let state = self.state.read();
            let close_nodes = state.kbucket.get_closest(&self.pk);
            if !close_nodes.is_empty() {
                let resp_payload = NodesResponsePayload {
                    nodes: close_nodes,
                    id: payload.id,
                };
                client.send_nodes_response(resp_payload)
            } else {
                error!("get_closest() return nothing");
                Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "get_closest() return nothing"
                )))
            }
        }
        else {
            error!("get_payload() fail upon NodesRequest");
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "get_payload() fail upon NodesRequest"
            )))
        }
    }
    /**
    handle received NodesResponse from peer.
    */
    fn handle_nodes_resp(&self, client: Client, request: NodesResponse) -> IoFuture<()> {
        if let Ok(payload) = request.get_payload(&self.sk) {
            if payload.id == 0 {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "NodesResponse.ping_id == 0"
                )))
            }
            if client.ping_id == payload.id {
                let mut state = self.state.write();
                for node in &payload.nodes {
                    state.kbucket.try_add(node);
                }
                Box::new( future::ok(()) )
            }
            else {
                Box::new( future::err(
                    Error::new(ErrorKind::Other, "NodesResponse.ping_id does not match")
                ))
            }
        }
        else {
            error!("get_payload() fail upon NodesResponse");
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "get_payload() fail upon NodesResponse"
            )))
        }
    }

    /**
    handle received NatPingRequest packet, respond with NatPingResponse
    */
    pub fn handle_nat_ping_req(&self, client: Client, request: DhtRequest, payload: NatPingRequest) -> IoFuture<()> {
        if request.rpk == self.pk { // the target peer is me
            let resp_payload = NatPingResponse {
                id: payload.id,
            };
            client.send_nat_ping_response(&request.spk, resp_payload)
        // search kbucket to find target peer
        } else {
            let state = self.state.read();
            if let Some(addr) = state.kbucket.get_node(&request.rpk) {
                client.send_nat_ping_packet(&addr, request.clone())
            }
            else { // do nothing
                Box::new( future::ok(()) )
            }
        }
    }

    /**
    handle received NatPingResponse packet, start hole-punching
    */
    pub fn handle_nat_ping_resp(&self, client: Client, request: DhtRequest, payload: NatPingResponse) -> IoFuture<()> {
        if request.rpk == self.pk { // the target peer is me
            if payload.id == 0 {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "NodesResponse.ping_id == 0"
                )))
            }
            if client.ping_id == payload.id {
                // TODO: start hole-punching
                Box::new( future::ok(()) )
            }
            else {
                Box::new( future::err(
                    Error::new(ErrorKind::Other, "NatPingResponse.ping_id does not match")
                ))
            }
        // search kbucket to find target peer
        } else {
            let state = self.state.read();
            if let Some(addr) = state.kbucket.get_node(&request.rpk) {
                client.send_nat_ping_packet(&addr, request.clone())
            }
            else { // do nothing
                Box::new( future::ok(()) )
            }
        }
    }
    /**
    handle received LanDiscovery packet, then create NodesRequest packet
    and send back it to the peer.
    */
    fn handle_lan_discovery(&self, mut client: Client, packet: LanDiscovery) -> IoFuture<()> {
        let mut state = self.state.write();
        let result = client.send_nodes_request(packet.pk);
        state.peers_cache.insert(packet.pk, client);
        result
    }
    /**
    send LanDiscovery packet to all broadcast addresses when dht_node runs as ipv4 mode
    */
    pub fn send_lan_discovery_ipv4(&self) -> IoFuture<()> {
        // addr is dummy, actual lan discovery packet sending logic exists in client
        let addr: SocketAddr = "127.0.0.1:33445".parse().unwrap();
        let client = self.create_client(&addr, self.pk);
        client.send_lan_discovery_ipv4()
    }
    /**
    send LanDiscovery packet to all broadcast addresses when dht_node runs as ipv6 mode
    */
    pub fn send_lan_discovery_ipv6(&self) -> IoFuture<()> {
        // addr is dummy, actual lan discovery packet sending logic exists in client
        let addr: SocketAddr = "[::1]:33445".parse().unwrap(); // 33445 is default port for tox
        let client = self.create_client(&addr, self.pk);
        client.send_lan_discovery_ipv6()
    }
    /**
    handle received OnionRequest0 packet, then create OnionRequest1 packet
    and send it to the next peer.
    */
    pub fn handle_onion_request_0(&self, packet: OnionRequest0, addr: SocketAddr) -> IoFuture<()> {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        let shared_secret = precompute(&packet.temporary_pk, &self.sk);
        if let Ok(payload) = packet.get_payload(&shared_secret) {
            let onion_return = OnionReturn::new(
                &onion_symmetric_key,
                &IpPort::from_saddr(addr),
                None // no previous onion return
            );
            let next_packet = DhtPacket::OnionRequest1(OnionRequest1 {
                nonce: packet.nonce,
                temporary_pk: payload.temporary_pk,
                payload: payload.inner,
                onion_return
            });
            // TODO: get rid of this client
            self.create_client(&addr, packet.temporary_pk).send_to(payload.ip_port.to_saddr(), next_packet)
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "get_payload() fail upon OnionRequest0"
            )))
        }
    }
    /**
    handle received OnionRequest1 packet, then create OnionRequest2 packet
    and send it to the next peer.
    */
    pub fn handle_onion_request_1(&self, packet: OnionRequest1, addr: SocketAddr) -> IoFuture<()> {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        let shared_secret = precompute(&packet.temporary_pk, &self.sk);
        if let Ok(payload) = packet.get_payload(&shared_secret) {
            let onion_return = OnionReturn::new(
                &onion_symmetric_key,
                &IpPort::from_saddr(addr),
                Some(&packet.onion_return)
            );
            let next_packet = DhtPacket::OnionRequest2(OnionRequest2 {
                nonce: packet.nonce,
                temporary_pk: payload.temporary_pk,
                payload: payload.inner,
                onion_return
            });
            // TODO: get rid of this client
            self.create_client(&addr, packet.temporary_pk).send_to(payload.ip_port.to_saddr(), next_packet)
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "get_payload() fail upon OnionRequest1"
            )))
        }
    }
    /**
    handle received OnionRequest2 packet, then create AnnounceRequest
    or OnionDataRequest packet and send it to the next peer.
    */
    pub fn handle_onion_request_2(&self, packet: OnionRequest2, addr: SocketAddr) -> IoFuture<()> {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        let shared_secret = precompute(&packet.temporary_pk, &self.sk);
        if let Ok(payload) = packet.get_payload(&shared_secret) {
            let onion_return = OnionReturn::new(
                &onion_symmetric_key,
                &IpPort::from_saddr(addr),
                Some(&packet.onion_return)
            );
            let next_packet = match payload.inner {
                InnerOnionRequest::InnerAnnounceRequest(inner) => DhtPacket::AnnounceRequest(AnnounceRequest {
                    inner,
                    onion_return
                }),
                InnerOnionRequest::InnerOnionDataRequest(inner) => DhtPacket::OnionDataRequest(OnionDataRequest {
                    inner,
                    onion_return
                }),
            };
            // TODO: get rid of this client
            self.create_client(&addr, packet.temporary_pk).send_to(payload.ip_port.to_saddr(), next_packet)
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "get_payload() fail upon OnionRequest2"
            )))
        }
    }
    /**
    handle received OnionResponse3 packet, then create OnionResponse2 packet
    and send it to the next peer which address is stored in encrypted onion return.
    */
    pub fn handle_onion_response_3(&self, packet: OnionResponse3) -> IoFuture<()> {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        if let Ok((ip_port, Some(next_onion_return))) = packet.onion_return.get_payload(&onion_symmetric_key) {
            let next_packet = DhtPacket::OnionResponse2(OnionResponse2 {
                onion_return: next_onion_return,
                payload: packet.payload
            });
            // TODO: get rid of this client
            self.create_client(&ip_port.to_saddr(), gen_keypair().0).send_to(ip_port.to_saddr(), next_packet)
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "get_payload() fail upon OnionResponse3"
            )))
        }
    }
    /**
    handle received OnionResponse2 packet, then create OnionResponse1 packet
    and send it to the next peer which address is stored in encrypted onion return.
    */
    pub fn handle_onion_response_2(&self, packet: OnionResponse2) -> IoFuture<()> {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        if let Ok((ip_port, Some(next_onion_return))) = packet.onion_return.get_payload(&onion_symmetric_key) {
            let next_packet = DhtPacket::OnionResponse1(OnionResponse1 {
                onion_return: next_onion_return,
                payload: packet.payload
            });
            // TODO: get rid of this client
            self.create_client(&ip_port.to_saddr(), gen_keypair().0).send_to(ip_port.to_saddr(), next_packet)
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "get_payload() fail upon OnionResponse2"
            )))
        }
    }
    /**
    handle received OnionResponse1 packet, then create AnnounceResponse
    or OnionDataResponse packet and send it to the next peer which address
    is stored in encrypted onion return.
    */
    pub fn handle_onion_response_1(&self, packet: OnionResponse1) -> IoFuture<()> {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        if let Ok((ip_port, None)) = packet.onion_return.get_payload(&onion_symmetric_key) {
            let next_packet = match packet.payload {
                InnerOnionResponse::AnnounceResponse(inner) => DhtPacket::AnnounceResponse(inner),
                InnerOnionResponse::OnionDataResponse(inner) => DhtPacket::OnionDataResponse(inner),
            };
            // TODO: get rid of this client
            self.create_client(&ip_port.to_saddr(), gen_keypair().0).send_to(ip_port.to_saddr(), next_packet)
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "get_payload() fail upon OnionResponse1"
            )))
        }
    }
    /// refresh onion symmetric key to enforce onion paths expiration
    pub fn refresh_onion_key(&self) {
        *self.onion_symmetric_key.write() = new_symmetric_key();
    }
    /// add PackedNode object to kbucket as a thread-safe manner
    pub fn try_add_to_kbucket(&self, pn: &PackedNode) -> bool {
        let mut state = self.state.write();
        state.kbucket.try_add(pn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use quickcheck::TestResult;
    use futures::Future;
    use std::net::SocketAddr;
    use toxcore::binary_io::*;

    const ONION_RETURN_1_PAYLOAD_SIZE: usize = ONION_RETURN_1_SIZE - NONCEBYTES;
    const ONION_RETURN_2_PAYLOAD_SIZE: usize = ONION_RETURN_2_SIZE - NONCEBYTES;

    fn create_node() -> (Server, PrecomputedKey, PublicKey, SecretKey,
            mpsc::UnboundedReceiver<(DhtPacket, SocketAddr)>, SocketAddr) {
        crypto_init();

        let (pk, sk) = gen_keypair();
        let (tx, rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
        let alice = Server::new(tx, pk, sk);
        let (bob_pk, bob_sk) = gen_keypair();
        let precomp = precompute(&alice.pk, &bob_sk);

        let addr: SocketAddr = "127.0.0.1:12346".parse().unwrap();
        (alice, precomp, bob_pk, bob_sk, rx, addr)
    }
    fn clear_kbucket(alice: &Server) {
        let mut state = alice.state.write();
        state.kbucket = Kbucket::new(KBUCKET_BUCKETS, &alice.pk);
    }
    fn clear_peers_cache(alice: &Server) {
        let mut state = alice.state.write();
        state.peers_cache.clear();
    }
    fn add_to_peers_cache(alice: &Server, pk: PublicKey, client: &Client) {
        let mut state = alice.state.write();
        state.peers_cache.insert(pk, client.clone());
    }
    fn is_pk_in_kbucket(alice: &Server, pk: PublicKey) -> bool {
        let state = alice.state.read();
        state.kbucket.contains(&pk)
    }
    fn is_kbucket_eq(alice: &Server, kbuc: Kbucket) {
        let state = alice.state.read();
        assert_eq!(state.kbucket, kbuc);
    }
    #[test]
    fn server_is_clonable() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, _addr) = create_node();
        let _ = alice.clone();
    }
    // new()
    #[test]
    fn server_new_test() {
        crypto_init();

        let (pk, sk) = gen_keypair();
        let tx: Tx = mpsc::unbounded().0;
        let _ = Server::new(tx, pk, sk);
    }
    // create_client()
    quickcheck! {
        fn server_create_client_test(packet: PingRequest) -> TestResult {
            crypto_init();

            let (pk, sk) = gen_keypair();
            let(tx, _) = mpsc::unbounded();
            let alice = Server::new(tx, pk, sk);
            let addr1: SocketAddr = "127.0.0.1:12345".parse().unwrap();
            let client1 = alice.create_client(&addr1, packet.pk);
            // try one more time
            let client2 = alice.create_client(&addr1, packet.pk);
            assert_eq!(client1.pk, client2.pk);
            assert_eq!(client1.precomputed_key, client2.precomputed_key);
            let addr2: SocketAddr = "127.0.0.2:54321".parse().unwrap();
            let client3 = alice.create_client(&addr2, packet.pk);
            assert_eq!(client1.precomputed_key, client3.precomputed_key);
            assert_ne!(client1.addr, client3.addr);
            TestResult::passed()
        }
    }
    // get_client()
    #[test]
    fn server_get_client_test() {
        let (alice, _precomp, bob_pk, _bob_sk, _rx, addr) = create_node();
        // Try to get client on empty hash table
        assert!(alice.get_client(&bob_pk).is_none());
        // Now test with entry
        let client = alice.create_client(&addr, bob_pk);
        add_to_peers_cache(&alice, bob_pk, &client);
        assert_eq!(client.pk, alice.get_client(&bob_pk).unwrap().pk);
    }
    // handle_packet()
    quickcheck! {
        fn server_handle_packet_test(prq: PingRequestPayload,
                                    prs: PingResponsePayload,
                                    nrq: NodesRequestPayload,
                                    nrs: NodesResponsePayload,
                                    nat_req: NatPingRequest,
                                    nat_res: NatPingResponse) -> TestResult
        {
            let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();
            // handle ping request, request from bob peer
            let ping_req = DhtPacket::PingRequest(PingRequest::new(&precomp, &bob_pk, prq));
            alice.handle_packet((ping_req, addr)).wait().unwrap();
            let (received, rx) = rx.into_future().wait().unwrap();
            debug!("received packet {:?}", received.clone().unwrap().1);
            let (packet, _addr) = received.unwrap();
            let mut buf = [0; 512];
            let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
            let (_, ping_res) = PingResponse::from_bytes(&buf[..size]).unwrap();
            let ping_resp_payload = ping_res.get_payload(&bob_sk).unwrap();
            assert_eq!(ping_resp_payload.id, prq.id);

            // handle ping response
            clear_peers_cache(&alice);
            let ping_res = DhtPacket::PingResponse(PingResponse::new(&precomp, &bob_pk, prs));
            // Try to handle_packet() without registered client, it just returns ok()
            assert!(alice.handle_packet((ping_res.clone(), addr)).wait().is_ok());
            // Now, test with client
            let mut client = alice.create_client(&addr, bob_pk);
            client.ping_id = prs.id;
            add_to_peers_cache(&alice, bob_pk, &client);
            alice.handle_packet((ping_res, addr)).wait().unwrap();
            assert!(is_pk_in_kbucket(&alice, bob_pk));

            // handle nodes request from bob
            let nodes_req = DhtPacket::NodesRequest(NodesRequest::new(&precomp, &bob_pk, nrq));
            alice.handle_packet((nodes_req, addr)).wait().unwrap();
            let (received, rx) = rx.into_future().wait().unwrap();
            debug!("received packet {:?}", received.clone().unwrap().0);
            let (packet, _addr) = received.unwrap();
            let mut buf = [0; 512];
            let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
            let (_, nodes_res) = NodesResponse::from_bytes(&buf[..size]).unwrap();
            let nodes_resp_payload = nodes_res.get_payload(&bob_sk).unwrap();
            assert_eq!(nodes_resp_payload.id, nrq.id);

            // handle nodes response
            clear_peers_cache(&alice);
            let nodes_res = DhtPacket::NodesResponse(NodesResponse::new(&precomp, &bob_pk, nrs.clone()));
            // Try to handle_packet() without registered client, it just returns ok()
            assert!(alice.handle_packet((nodes_res.clone(), addr)).wait().is_ok());
            // Now, test with client
            let mut client = alice.create_client(&addr, bob_pk);
            client.ping_id = nrs.id;
            clear_kbucket(&alice);
            add_to_peers_cache(&alice, bob_pk, &client);
            let mut kbuc = Kbucket::new(KBUCKET_BUCKETS, &alice.pk);
            for pn in &nrs.nodes {
                kbuc.try_add(pn);
            }
            alice.handle_packet((nodes_res, addr)).wait().unwrap();
            is_kbucket_eq(&alice, kbuc);

            // handle nat ping request
            let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
            let nat_ping_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &bob_pk, nat_payload.clone()));
            alice.handle_packet((nat_ping_req, addr)).wait().unwrap();
            let (received, _rx) = rx.into_future().wait().unwrap();
            debug!("received packet {:?}", received.clone().unwrap().0);
            let (packet, _addr) = received.unwrap();
            let mut buf = [0; 512];
            let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
            let (_, dht_req) = DhtRequest::from_bytes(&buf[..size]).unwrap();
            let dht_payload = dht_req.get_payload(&bob_sk).unwrap();
            let (_, size) = dht_payload.to_bytes((&mut buf, 0)).unwrap();
            let (_, nat_ping_resp_payload) = NatPingResponse::from_bytes(&buf[..size]).unwrap();
            assert_eq!(nat_ping_resp_payload.id, nat_req.id);

            let nat_ping_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &alice.pk, nat_payload));
            assert!(!alice.handle_packet((nat_ping_req, addr)).wait().is_ok());

            // handle nat ping response
            clear_peers_cache(&alice);
            let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
            let nat_ping_res = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &bob_pk, nat_payload.clone()));
            // Try to handle_packet() without registered client, it just returns ok()
            assert!(alice.handle_packet((nat_ping_res.clone(), addr)).wait().is_ok());
            // Now, test with client
            let mut client = alice.create_client(&addr, bob_pk);
            client.ping_id = nat_res.id;
            add_to_peers_cache(&alice, bob_pk, &client);
            assert!(alice.handle_packet((nat_ping_res, addr)).wait().is_ok());

            let nat_ping_res = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &alice.pk, nat_payload));
            assert!(!alice.handle_packet((nat_ping_res, addr)).wait().is_ok());

            TestResult::passed()
        }
    }
    // test handle_packet() with invlid packet type
    #[test]
    fn server_handle_packet_with_invalid_packet_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();
        let packet = DhtPacket::BootstrapInfo(BootstrapInfo {
            version: 00,
            motd: b"Hello".to_owned().to_vec(),
        });
        assert!(alice.handle_packet((packet, addr)).wait().is_err());
    }
    // test handle_packet() with invlid DhtRequest packet payload
    #[test]
    fn server_handle_packet_with_invalid_payload_test() {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_packet = DhtPacket::DhtRequest( DhtRequest {
            rpk: bob_pk,
            spk: alice_pk,
            nonce,
            payload: invalid_payload_encoded
        } );
        let addr: SocketAddr = "127.0.0.1:12346".parse().unwrap();
        let (tx, _rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
        let alice = Server::new(tx, alice_pk, alice_sk);
        assert!(alice.handle_packet((invalid_packet, addr)).wait().is_err());
    }
    // handle_ping_req()
    #[test]
    fn server_handle_ping_req_test() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();
        // handle ping request, request from bob peer
        let prq = PingRequestPayload { id: random_u64() };
        let ping_req = PingRequest::new(&precomp, &bob_pk, prq);
        let pk = alice.pk;
        let client = alice.create_client(&addr, pk);
        alice.handle_ping_req(client, ping_req).wait().unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        debug!("received packet {:?}", received.clone().unwrap().1);
        let (packet, _addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, ping_res) = PingResponse::from_bytes(&buf[..size]).unwrap();
        let ping_resp_payload = ping_res.get_payload(&alice.sk).unwrap();
        assert_eq!(ping_resp_payload.id, prq.id);
        // error case: can't decrypt
        let prq = PingRequestPayload { id: random_u64() };
        let ping_req = PingRequest::new(&precomp, &alice.pk, prq);
        let client = alice.create_client(&addr, bob_pk);
        assert!(!alice.handle_ping_req(client, ping_req).wait().is_ok());
    }

    // handle_ping_resp()
    #[test]
    fn server_handle_ping_resp_test() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();
        // handle ping response, request from bob peer
        let prs = PingResponsePayload { id: random_u64() };
        let ping_resp = PingResponse::new(&precomp, &bob_pk, prs);
        let mut client = alice.create_client(&addr, bob_pk);
        client.ping_id = prs.id;
        assert!(alice.handle_ping_resp(client, ping_resp).wait().is_ok());

        let prs = PingResponsePayload { id: random_u64() };
        let ping_resp = PingResponse::new(&precomp, &alice.pk, prs);
        let mut client = alice.create_client(&addr, bob_pk);
        client.ping_id = prs.id;
        assert!(alice.handle_ping_resp(client, ping_resp).wait().is_err());

        // ping_id = 0
        let prs = PingResponsePayload { id: 0 };
        let ping_resp = PingResponse::new(&precomp, &bob_pk, prs);
        let mut client = alice.create_client(&addr, bob_pk);
        client.ping_id = 0;
        assert!(alice.handle_ping_resp(client.clone(), ping_resp.clone()).wait().is_err());
        // incorrect ping_id
        let prs = PingResponsePayload { id: random_u64() };
        let ping_resp = PingResponse::new(&precomp, &bob_pk, prs);
        let mut client = alice.create_client(&addr, bob_pk);
        client.ping_id = prs.id + 1;
        assert!(alice.handle_ping_resp(client, ping_resp).wait().is_err());
    }

    // handle_nodes_req()
    #[test]
    fn server_handle_nodes_req_test() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();
        // error case, empty kbucket
        let nrq = NodesRequestPayload { pk: bob_pk, id: random_u64() };
        let nodes_req = NodesRequest::new(&precomp, &bob_pk, nrq);
        let client = alice.create_client(&addr, bob_pk);
        assert!(alice.handle_nodes_req(client, nodes_req).wait().is_err());
        // success case
        let packed_node = PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &bob_pk);

        alice.try_add_to_kbucket(&packed_node);

        let nrq = NodesRequestPayload { pk: bob_pk, id: random_u64() };
        let nodes_req = NodesRequest::new(&precomp, &bob_pk, nrq);
        let client = alice.create_client(&addr, bob_pk);
        alice.handle_nodes_req(client, nodes_req).wait().unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        debug!("received packet {:?}", received.clone().unwrap().0);
        let (packet, _addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, nodes_res) = NodesResponse::from_bytes(&buf[..size]).unwrap();
        let nodes_resp_payload = nodes_res.get_payload(&bob_sk).unwrap();
        assert_eq!(nodes_resp_payload.id, nrq.id);
        // error case, can't decrypt
        let nodes_req = NodesRequest::new(&precomp, &alice.pk, nrq);
        let client = alice.create_client(&addr, bob_pk);
        assert!(alice.handle_nodes_req(client, nodes_req).wait().is_err());
    }

    // handle_nodes_resp()
    #[test]
    fn server_handle_nodes_resp_test() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();
        // handle nodes response, request from bob peer
        let nrs = NodesResponsePayload { nodes: vec![
            PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &gen_keypair().0)
        ], id: 38 };

        let nodes_resp = NodesResponse::new(&precomp, &bob_pk, nrs.clone());
        let mut client = alice.create_client(&addr, bob_pk);
        client.ping_id = 38;
        alice.handle_nodes_resp(client, nodes_resp).wait().unwrap();
        let mut kbuc = Kbucket::new(KBUCKET_BUCKETS, &alice.pk);
        for pn in &nrs.nodes {
            kbuc.try_add(pn);
        }

        is_kbucket_eq(&alice, kbuc);

        // error case, can't decrypt
        let nodes_resp = NodesResponse::new(&precomp, &alice.pk, nrs.clone());
        let pk = alice.pk;
        let mut client = alice.create_client(&addr, pk);
        client.ping_id = 38;
        assert!(alice.handle_nodes_resp(client, nodes_resp).wait().is_err());
        // ping_id = 0
        let nrs = NodesResponsePayload { nodes: vec![
            PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &gen_keypair().0)
        ], id: 0 };
        let nodes_resp = NodesResponse::new(&precomp, &bob_pk, nrs.clone());
        let mut client = alice.create_client(&addr, bob_pk);
        client.ping_id = 0;
        assert!(alice.handle_nodes_resp(client.clone(), nodes_resp.clone()).wait().is_err());
        // incorrect ping_id
        let nrs = NodesResponsePayload { nodes: vec![
            PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &gen_keypair().0)
        ], id: 38 };
        let nodes_resp = NodesResponse::new(&precomp, &bob_pk, nrs.clone());
        let mut client = alice.create_client(&addr, bob_pk);
        client.ping_id = 38 + 1;
        assert!(alice.handle_nodes_resp(client, nodes_resp).wait().is_err());
    }

    // handle nat ping request
    #[test]
    fn server_handle_nat_ping_req_test() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();
        let nat_req = NatPingRequest { id: random_u64() };
        let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
        let dht_req = DhtRequest::new(&precomp, &alice.pk, &alice.pk, nat_payload.clone());
        let alice_pk = alice.pk;
        let client = alice.create_client(&addr, alice_pk);
        alice.handle_nat_ping_req(client, dht_req, nat_req).wait().unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        debug!("received packet {:?}", received.clone().unwrap().1);
        let (packet, _addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, dht_req) = DhtRequest::from_bytes(&buf[..size]).unwrap();
        let dht_payload = dht_req.get_payload(&alice.sk).unwrap();
        let (_, size) = dht_payload.to_bytes((&mut buf, 0)).unwrap();
        let (_, nat_ping_resp_payload) = NatPingResponse::from_bytes(&buf[..size]).unwrap();
        assert_eq!(nat_ping_resp_payload.id, nat_req.id);
        // if receiver' pk != node's pk just returns ok()
        let nat_req = NatPingRequest { id: random_u64() };
        let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
        let dht_req = DhtRequest::new(&precomp, &bob_pk, &bob_pk, nat_payload.clone());
        let alice_pk = alice.pk;
        let client = alice.create_client(&addr, alice_pk);
        assert!(alice.handle_nat_ping_req(client, dht_req, nat_req).wait().is_ok());
        // if receiver' pk != node's pk and receiver's pk exists in kbucket, returns ok()
        let pn = PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &bob_pk);

        alice.try_add_to_kbucket(&pn);
        let nat_req = NatPingRequest { id: random_u64() };
        let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
        let dht_req = DhtRequest::new(&precomp, &bob_pk, &bob_pk, nat_payload.clone());
        let alice_pk = alice.pk;
        let client = alice.create_client(&addr, alice_pk);
        assert!(alice.handle_nat_ping_req(client, dht_req, nat_req).wait().is_ok());
    }

    // handle nat ping response
    #[test]
    fn server_handle_nat_ping_resp_test() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();
        // if receiver' pk != node's pk just returns ok()
        let nat_res = NatPingResponse { id: random_u64() };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtRequest::new(&precomp, &bob_pk, &bob_pk, nat_payload.clone());
        let client = alice.create_client(&addr, bob_pk);
        assert!(alice.handle_nat_ping_resp(client, dht_req, nat_res).wait().is_ok());
        // if receiver' pk != node's pk and receiver's pk exists in kbucket, returns ok()
        let pn = PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &bob_pk);

        alice.try_add_to_kbucket(&pn);
        let nat_res = NatPingResponse { id: random_u64() };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtRequest::new(&precomp, &bob_pk, &bob_pk, nat_payload.clone());
        let client = alice.create_client(&addr, bob_pk);
        assert!(alice.handle_nat_ping_resp(client, dht_req, nat_res).wait().is_ok());
        // success case
        let nat_res = NatPingResponse { id: random_u64() };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtRequest::new(&precomp, &alice.pk, &bob_pk, nat_payload.clone());
        let mut client = alice.create_client(&addr, bob_pk);
        client.ping_id = nat_res.id;
        assert!(alice.handle_nat_ping_resp(client, dht_req, nat_res).wait().is_ok());
        // error case, incorrect ping_id
        let nat_res = NatPingResponse { id: random_u64() };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtRequest::new(&precomp, &alice.pk, &bob_pk, nat_payload.clone());
        let mut client = alice.create_client(&addr, bob_pk);
        client.ping_id = nat_res.id + 1;
        assert!(alice.handle_nat_ping_resp(client.clone(), dht_req, nat_res).wait().is_err());
        // error case, ping_id = 0
        let nat_res = NatPingResponse { id: 0 };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtRequest::new(&precomp, &alice.pk, &bob_pk, nat_payload.clone());
        let mut client = alice.create_client(&addr, bob_pk);
        client.ping_id = 0;
        assert!(alice.handle_nat_ping_resp(client, dht_req, nat_res).wait().is_err());
    }

    #[test]
    fn server_handle_onion_request_0_test() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let temporary_pk = gen_keypair().0;
        let inner = vec![42, 123];
        let ip_port = IpPort {
          ip_addr: "5.6.7.8".parse().unwrap(),
          port: 12345
        };
        let payload = OnionRequest0Payload {
            ip_port: ip_port.clone(),
            temporary_pk,
            inner: inner.clone()
        };
        let packet = DhtPacket::OnionRequest0(OnionRequest0::new(&precomp, &bob_pk, payload));

        assert!(alice.handle_packet((packet, addr)).wait().is_ok());

        let (packet, _rx) = rx.into_future().wait().unwrap();

        let (next, addr_to_send) = match packet {
            Some((DhtPacket::OnionRequest1(next), addr_to_send)) => (next, addr_to_send),
            p => panic!("Expected OnionRequest1 but got {:?}", p)
        };

        assert_eq!(addr_to_send, ip_port.to_saddr());
        assert_eq!(next.temporary_pk, temporary_pk);
        assert_eq!(next.payload, inner);
        let onion_symmetric_key = alice.onion_symmetric_key.read();
        assert_eq!(next.onion_return.get_payload(&onion_symmetric_key).unwrap().0, IpPort::from_saddr(addr));
    }

    #[test]
    fn server_handle_onion_request_0_invalid_payload_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let packet = DhtPacket::OnionRequest0(OnionRequest0 {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42, 123] // not encrypted with dht pk
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_err());
    }

    #[test]
    fn server_handle_onion_request_1_test() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let temporary_pk = gen_keypair().0;
        let inner = vec![42, 123];
        let ip_port = IpPort {
          ip_addr: "5.6.7.8".parse().unwrap(),
          port: 12345
        };
        let payload = OnionRequest1Payload {
            ip_port: ip_port.clone(),
            temporary_pk,
            inner: inner.clone()
        };
        let onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
        };
        let packet = DhtPacket::OnionRequest1(OnionRequest1::new(&precomp, &bob_pk, payload, onion_return));

        assert!(alice.handle_packet((packet, addr)).wait().is_ok());

        let (packet, _rx) = rx.into_future().wait().unwrap();

        let (next, addr_to_send) = match packet {
            Some((DhtPacket::OnionRequest2(next), addr_to_send)) => (next, addr_to_send),
            p => panic!("Expected OnionRequest2 but got {:?}", p)
        };

        assert_eq!(addr_to_send, ip_port.to_saddr());
        assert_eq!(next.temporary_pk, temporary_pk);
        assert_eq!(next.payload, inner);
        let onion_symmetric_key = alice.onion_symmetric_key.read();
        assert_eq!(next.onion_return.get_payload(&onion_symmetric_key).unwrap().0, IpPort::from_saddr(addr));
    }

    #[test]
    fn server_handle_onion_request_1_invalid_payload_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let packet = DhtPacket::OnionRequest1(OnionRequest1 {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42, 123], // not encrypted with dht pk
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
            }
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_err());
    }

    #[test]
    fn server_handle_onion_request_2_with_announce_request_test() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let inner = InnerAnnounceRequest {
            nonce: gen_nonce(),
            pk: gen_keypair().0,
            payload: vec![42, 123]
        };
        let ip_port = IpPort {
          ip_addr: "5.6.7.8".parse().unwrap(),
          port: 12345
        };
        let payload = OnionRequest2Payload {
            ip_port: ip_port.clone(),
            inner: InnerOnionRequest::InnerAnnounceRequest(inner.clone())
        };
        let onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
        };
        let packet = DhtPacket::OnionRequest2(OnionRequest2::new(&precomp, &bob_pk, payload, onion_return));

        assert!(alice.handle_packet((packet, addr)).wait().is_ok());

        let (packet, _rx) = rx.into_future().wait().unwrap();

        let (next, addr_to_send) = match packet {
            Some((DhtPacket::AnnounceRequest(next), addr_to_send)) => (next, addr_to_send),
            p => panic!("Expected OnionDataRequest but got {:?}", p)
        };

        assert_eq!(addr_to_send, ip_port.to_saddr());
        assert_eq!(next.inner, inner);
        let onion_symmetric_key = alice.onion_symmetric_key.read();
        assert_eq!(next.onion_return.get_payload(&onion_symmetric_key).unwrap().0, IpPort::from_saddr(addr));
    }

    #[test]
    fn server_handle_onion_request_2_with_onion_data_request_test() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let inner = InnerOnionDataRequest {
            destination_pk: gen_keypair().0,
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42, 123]
        };
        let ip_port = IpPort {
          ip_addr: "5.6.7.8".parse().unwrap(),
          port: 12345
        };
        let payload = OnionRequest2Payload {
            ip_port: ip_port.clone(),
            inner: InnerOnionRequest::InnerOnionDataRequest(inner.clone())
        };
        let onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
        };
        let packet = DhtPacket::OnionRequest2(OnionRequest2::new(&precomp, &bob_pk, payload, onion_return));

        assert!(alice.handle_packet((packet, addr)).wait().is_ok());

        let (packet, _rx) = rx.into_future().wait().unwrap();

        let (next, addr_to_send) = match packet {
            Some((DhtPacket::OnionDataRequest(next), addr_to_send)) => (next, addr_to_send),
            p => panic!("Expected OnionDataRequest but got {:?}", p)
        };

        assert_eq!(addr_to_send, ip_port.to_saddr());
        assert_eq!(next.inner, inner);
        let onion_symmetric_key = alice.onion_symmetric_key.read();
        assert_eq!(next.onion_return.get_payload(&onion_symmetric_key).unwrap().0, IpPort::from_saddr(addr));
    }

    #[test]
    fn server_handle_onion_request_2_invalid_payload_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let packet = DhtPacket::OnionRequest2(OnionRequest2 {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42, 123], // not encrypted with dht pk
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
            }
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_err());
    }

    // send_pings()
    #[test]
    fn server_send_pings_test() {
        let (alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let (ping_pk, ping_sk) = gen_keypair();

        let pn = PackedNode::new(false, SocketAddr::V4("127.1.1.1:12345".parse().unwrap()), &ping_pk);
        alice.try_add_to_kbucket(&pn);
        let pn = PackedNode::new(false, SocketAddr::V4("127.0.0.1:33445".parse().unwrap()), &bob_pk);
        alice.try_add_to_kbucket(&pn);

        alice.send_pings().wait().unwrap();

        rx.take(2).map(|received| {
            let (packet, addr) = received;
            let mut buf = [0; 512];
            let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
            let (_, ping_req) = PingRequest::from_bytes(&buf[..size]).unwrap();
            if addr == SocketAddr::V4("127.0.0.1:33445".parse().unwrap()) {
                let client = alice.get_client(&bob_pk).unwrap();
                let ping_req_payload = ping_req.get_payload(&bob_sk).unwrap();
                assert_eq!(ping_req_payload.id, client.ping_id);                
            } else {
                let client = alice.get_client(&ping_pk).unwrap();
                let ping_req_payload = ping_req.get_payload(&ping_sk).unwrap();
                assert_eq!(ping_req_payload.id, client.ping_id);
            }
        }).collect().wait().unwrap();
    }
    // send_nodes_req()
    #[test]
    fn server_send_nodes_req_test() {
        let (alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        // If there is no entry in kbucket, then it returns just ok()
        let alice_pk = alice.pk;
        assert!(alice.send_nodes_req(alice_pk).wait().is_ok());
        // Now, test with kbucket entry
        let node = PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &bob_pk);

        let alice_pk = alice.pk;
        alice.try_add_to_kbucket(&node);

        alice.send_nodes_req(alice_pk).wait().unwrap();

        let client = alice.get_client(&bob_pk).unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, _addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, nodes_req) = NodesRequest::from_bytes(&buf[..size]).unwrap();
        let nodes_req_payload = nodes_req.get_payload(&bob_sk).unwrap();
        assert_eq!(nodes_req_payload.id, client.ping_id);
    }
    // send_nat_ping_req()
    #[test]
    fn server_send_nat_ping_req_test() {
        let (alice, _precomp, bob_pk, _bob_sk, rx, _addr) = create_node();
        let node = PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &alice.pk);
        alice.try_add_to_kbucket(&node);

        alice.send_nat_ping_req(node, bob_pk).wait().unwrap();

        let client = alice.get_client(&alice.pk).unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, _addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, nat_ping_req) = DhtRequest::from_bytes(&buf[..size]).unwrap();
        let nat_ping_req_payload = nat_ping_req.get_payload(&alice.sk).unwrap();
        let (_, size) = nat_ping_req_payload.to_bytes((&mut buf, 0)).unwrap();
        let (_, nat_ping_req_payload) = NatPingRequest::from_bytes(&buf[..size]).unwrap();
        assert_eq!(nat_ping_req_payload.id, client.ping_id);
    }
    #[test]
    fn server_handle_lan_discovery_test() {
        let (alice, _precomp, bob_pk, bob_sk, rx, addr) = create_node();

        let lan = LanDiscovery { pk: bob_pk };
        let client = alice.create_client(&addr, bob_pk);
        alice.handle_lan_discovery(client.clone(), lan).wait().unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        debug!("received packet {:?}", received.clone().unwrap().0);
        let (packet, _addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, nodes_req) = NodesRequest::from_bytes(&buf[..size]).unwrap();
        let _nodes_req_payload = nodes_req.get_payload(&bob_sk).unwrap();
        assert_eq!(nodes_req.pk, client.pk);
    }
    #[test]
    fn server_send_lan_discovery_ipv4_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, _addr) = create_node();
        alice.send_lan_discovery_ipv6().wait().unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, _addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, lan_discovery) = LanDiscovery::from_bytes(&buf[..size]).unwrap();
        assert_eq!(alice.pk, lan_discovery.pk);
    }
    #[test]
    fn server_send_lan_discovery_ipv6_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, _addr) = create_node();
        alice.send_lan_discovery_ipv6().wait().unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, _addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, lan_discovery) = LanDiscovery::from_bytes(&buf[..size]).unwrap();
        assert_eq!(alice.pk, lan_discovery.pk);
    }
}
