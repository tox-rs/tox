/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2018 Namsoo CHO <nscho66@gmail.com>
    Copyright © 2018 Evgeny Kurnevsky <kurnevsky@gmail.com>
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

/*!
Functionality needed to work as a DHT node.
This module works on top of other modules.
*/

pub mod client;

use futures::{Future, Sink, Stream, future, stream};
use futures::sync::mpsc;
use get_if_addrs;
use get_if_addrs::IfAddr;
use parking_lot::RwLock;
use tokio_io::IoFuture;

use std::io::{ErrorKind, Error};
use std::net::{IpAddr, SocketAddr};
use std::collections::HashMap;
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::{Duration, Instant};

use toxcore::crypto_core::*;
use toxcore::dht::packet::*;
use toxcore::dht::packed_node::*;
use toxcore::dht::kbucket::*;
use toxcore::onion::packet::*;
use toxcore::onion::onion_announce::*;
use toxcore::dht::server::client::*;

/// Shorthand for the transmit half of the message channel.
type Tx = mpsc::UnboundedSender<(DhtPacket, SocketAddr)>;

/// Ping timeout in seconds
pub const PING_TIMEOUT: u64 = 5;

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
    // onion announce struct to handle onion packets
    onion_announce: Arc<RwLock<OnionAnnounce>>
}

#[derive(Debug)]
// hold client object connected and kbucket object, this struct object is shared by threads
struct ServerState {
    /// store client object which has sent request packet to peer
    pub peers_cache: HashMap<PublicKey, ClientData>,
    /// Close List (contains nodes close to own DHT PK)
    pub kbucket: Kbucket,
}

impl Server {
    /**
    Create new `Server` instance.
    */
    pub fn new(tx: Tx, pk: PublicKey, sk: SecretKey) -> Server {
        let kbucket = Kbucket::new(&pk);

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
            onion_announce: Arc::new(RwLock::new(OnionAnnounce::new(pk))),
        }
    }
    /// remove timed-out clients, also remove node from kbucket
    pub fn remove_timedout_clients(&self, timeout: Duration) -> IoFuture<()> {
        let mut state = self.state.write();
        let timeout_peers = state.peers_cache.iter()
            .filter(|&(_pk, client)| client.last_resp_time.elapsed() > timeout)
            .map(|(pk, _client)| *pk)
            .collect::<Vec<_>>();

        timeout_peers.into_iter().for_each(|pk| state.kbucket.remove(&pk));

        state.peers_cache.retain(|&_pk, ref client|
            client.last_resp_time.elapsed() <= timeout);
        Box::new(future::ok(()))
    }

    /// remove PING_TIMEOUT timed out ping_ids of PingHash
    pub fn remove_timedout_ping_ids(&self, timeout: Duration) -> IoFuture<()> {
        let mut state = self.state.write();
        state.peers_cache.iter_mut()
            .map(|(_pk, client)|
                client.clear_timedout(timeout)
            ).collect::<Vec<_>>();

        Box::new( future::ok(()) )
    }

    /// send PingRequest to all peers in kbucket
    pub fn send_pings(&self) -> IoFuture<()> {
        let mut state = self.state.write();
        let ping_sender = state.kbucket.iter().map(|peer| {
            let client = state.peers_cache.entry(peer.pk).or_insert_with(ClientData::new);

            let payload = PingRequestPayload {
                id: client.add_ping_id(),
            };
            let ping_req = DhtPacket::PingRequest(PingRequest::new(
                &precompute(&peer.pk, &self.sk),
                &self.pk,
                payload
            ));
            self.send_to(peer.saddr, ping_req)
        });

        let pings_stream = stream::futures_unordered(ping_sender).then(|_| Ok(()));

        Box::new(pings_stream.for_each(|()| Ok(())))
    }

    /// Send NodesRequest to random peer every 20 seconds
    pub fn periodical_nodes_req(&self) -> IoFuture<()> {
        let peer = match self.get_random_node() {
            None => {
                return Box::new( future::ok(()))
            },
            Some(peer) => peer,
        };

        self.send_nodes_req(peer)
    }
    
    // Get random node from kbucket
    fn get_random_node(&self) -> Option<PackedNode> {
        let state = self.state.read();
        state.kbucket.get_random_node()
    }

    // Send NodesRequest to peer
    fn send_nodes_req(&self, target_peer: PackedNode) -> IoFuture<()> {
        // Check if packet is going to be sent to ourself.
        if self.pk == target_peer.pk {
            return Box::new(
                future::err(
                    Error::new(ErrorKind::Other, "friend's pk is mine")
                )
            )
        }

        let mut state = self.state.write();
        let client = state.peers_cache.entry(target_peer.pk).or_insert_with(ClientData::new);

        let payload = NodesRequestPayload {
            pk: target_peer.pk,
            id: client.add_ping_id(),
        };
        let nodes_req = DhtPacket::NodesRequest(NodesRequest::new(
            &precompute(&target_peer.pk, &self.sk),
            &self.pk,
            payload
        ));

        self.send_to(target_peer.saddr, nodes_req)
    }
    /// send NatPingRequests to peers every 3 seconds
    pub fn send_nat_ping_req(&self, peer: PackedNode, friend_pk: PublicKey) -> IoFuture<()> {
        let mut state = self.state.write();

        let client = state.peers_cache.entry(peer.pk).or_insert_with(ClientData::new);

        let payload = DhtRequestPayload::NatPingRequest(NatPingRequest {
            id: client.add_ping_id(),
        });
        let nat_ping_req = DhtPacket::DhtRequest(DhtRequest::new(
            &precompute(&peer.pk, &self.sk),
            &friend_pk,
            &self.pk,
            payload
        ));
        self.send_to(peer.saddr, nat_ping_req)
    }
    /**
    Function to handle incoming packets. If there is a response packet,
    send back it to the peer.
    */
    pub fn handle_packet(&self, (packet, addr): (DhtPacket, SocketAddr)) -> IoFuture<()> {
        match packet {
            DhtPacket::PingRequest(packet) => {
                debug!("Received ping request");
                self.handle_ping_req(packet, addr)
            },
            DhtPacket::PingResponse(packet) => {
                debug!("Received ping response");
                self.handle_ping_resp(packet)
            },
            DhtPacket::NodesRequest(packet) => {
                debug!("Received NodesRequest");
                self.handle_nodes_req(packet, addr)
            },
            DhtPacket::NodesResponse(packet) => {
                debug!("Received NodesResponse");
                self.handle_nodes_resp(packet)
            },
            DhtPacket::DhtRequest(packet) => {
                debug!("Received DhtRequest");
                self.handle_dht_req(packet, addr)
            },
            DhtPacket::LanDiscovery(packet) => {
                debug!("Received LanDiscovery");
                self.handle_lan_discovery(packet, addr)
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
            DhtPacket::AnnounceRequest(packet) => {
                debug!("Received AnnounceRequest");
                self.handle_announce_request(packet, addr)
            },
            DhtPacket::OnionDataRequest(packet) => {
                debug!("Received OnionDataRequest");
                self.handle_onion_data_request(packet)
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
                Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        format!("DhtPacket is not handled {:?}", p)
                )))
            }
        }
    }

    /// actual send method
    fn send_to(&self, addr: SocketAddr, packet: DhtPacket) -> IoFuture<()> {
        Box::new(self.tx.clone() // clone tx sender for 1 send only
            .send((packet, addr))
            .map(|_tx| ()) // ignore tx because it was cloned
            .map_err(|e| {
                // This may only happen if rx is gone
                // So cast SendError<T> to a corresponding std::io::Error
                debug!("send to peer error {:?}", e);
                Error::from(ErrorKind::UnexpectedEof)
            })
        )
    }

    /// get broadcast addresses for host's network interfaces
    fn get_ipv4_broadcast_addrs() -> Vec<IpAddr> {
        let ifs = get_if_addrs::get_if_addrs().expect("no network interface");
        ifs.iter().filter_map(|interface|
            match interface.addr {
                IfAddr::V4(ref addr) => addr.broadcast,
                _ => None,
        })
        .map(|addr|
            IpAddr::V4(addr)
        )
        .collect()
    }

    /**
    handle received PingRequest packet, then create PingResponse packet
    and send back it to the peer.
    */
    fn handle_ping_req(&self, packet: PingRequest, addr: SocketAddr) -> IoFuture<()> {
        let payload = packet.get_payload(&self.sk);
        let payload = match payload {
            Err(e) => {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        format!("PingRequest::get_payload() failed: {:?}", e)
                )))
            },
            Ok(payload) => payload,
        };

        let resp_payload = PingResponsePayload {
            id: payload.id,
        };
        let ping_resp = DhtPacket::PingResponse(PingResponse::new(
            &precompute(&packet.pk, &self.sk),
            &self.pk,
            resp_payload
        ));
        self.send_to(addr, ping_resp)
    }
    /**
    handle received PingResponse packet. If ping_id is correct, try_add peer to kbucket.
    */
    fn handle_ping_resp(&self, packet: PingResponse) -> IoFuture<()> {
        let mut state = self.state.write();
        let payload = packet.get_payload(&self.sk);
        let payload = match payload {
            Err(e) => {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        format!("PingResponse::get_payload() failed: {:?}", e)
                )))
            },
            Ok(payload) => payload,
        };

        if payload.id == 0u64 {
            return Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "PingResponse.ping_id == 0"
            )))
        }

        let client = state.peers_cache.get_mut(&packet.pk);
        let client = match client {
            None => {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "get_client() failed in handle_ping_resp()"
                )))
            },
            Some(client) => client,
        };

        let timeout_dur = Duration::from_secs(PING_TIMEOUT);
        if client.check_ping_id(payload.id, timeout_dur) {
            client.last_resp_time = Instant::now();
            Box::new( future::ok(()) )
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other, "PingResponse.ping_id does not match")
            ))
        }
    }
    /**
    handle received NodesRequest packet, responds with NodesResponse
    */
    fn handle_nodes_req(&self, packet: NodesRequest, addr: SocketAddr) -> IoFuture<()> {
        let state = self.state.read();

        let payload = packet.get_payload(&self.sk);
        let payload = match payload {
            Err(e) => {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        format!("NodesRequest::get_payload() failed: {:?}", e)
                )))
            },
            Ok(payload) => payload,
        };

        let close_nodes = state.kbucket.get_closest(&self.pk);
        let resp_payload = NodesResponsePayload {
            nodes: close_nodes,
            id: payload.id,
        };
        let nodes_resp = DhtPacket::NodesResponse(NodesResponse::new(
            &precompute(&packet.pk, &self.sk),
            &self.pk,
            resp_payload
        ));
        self.send_to(addr, nodes_resp)
    }
    /**
    handle received NodesResponse from peer.
    */
    fn handle_nodes_resp(&self, packet: NodesResponse) -> IoFuture<()> {
        let mut state = self.state.write();
        let state = state.deref_mut();

        let payload = packet.get_payload(&self.sk);
        let payload = match payload {
            Err(e) => {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        format!("NodesResponse::get_payload() failed: {:?}", e)
                )))
            },
            Ok(payload) => payload,
        };

        let client = state.peers_cache.get_mut(&packet.pk);
        let client = match client {
            None => {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "get_client() failed in handle_nodes_resp()"
                )))
            },
            Some(client) => client,
        };

        let timeout_dur = Duration::from_secs(PING_TIMEOUT);
        if client.check_ping_id(payload.id, timeout_dur) {
            // TODO: replace it with addto_list
            for node in &payload.nodes {
                // not worried about removing evicted nodes from peers_cache
                // they will be removed by timeout eventually since we won't
                // ping them anymore
                state.kbucket.try_add(node);
            }
            Box::new( future::ok(()) )
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other, "NodesResponse.ping_id does not match")
            ))
        }
    }

    /**
    handle received DhtRequest, resend if it's sent for someone else, parse and
    handle payload if it's sent for us
    */
    fn handle_dht_req(&self, packet: DhtRequest, addr: SocketAddr) -> IoFuture<()> {
        if packet.rpk == self.pk { // the target peer is me
            let payload = packet.get_payload(&self.sk);
            let payload = match payload {
                Err(err) => {
                    return Box::new( future::err(
                        Error::new(ErrorKind::Other,
                            format!("DhtRequest::get_payload failed with: {:?}", err)
                    )))
                },
                Ok(payload) => payload,
            };

            match payload {
                DhtRequestPayload::NatPingRequest(nat_payload) => {
                    debug!("Received nat ping request");
                    self.handle_nat_ping_req(nat_payload, &packet.spk, addr)
                },
                DhtRequestPayload::NatPingResponse(nat_payload) => {
                    debug!("Received nat ping response");
                    self.handle_nat_ping_resp(nat_payload, &packet.spk)
                },
            }
        } else {
            let state = self.state.read();
            if let Some(addr) = state.kbucket.get_node(&packet.rpk) { // search kbucket to find target peer
                let packet = DhtPacket::DhtRequest(packet);
                self.send_to(addr, packet)
            } else { // do nothing
                Box::new( future::ok(()) )
            }
        }
    }

    /**
    handle received NatPingRequest packet, respond with NatPingResponse
    */
    fn handle_nat_ping_req(&self, payload: NatPingRequest, spk: &PublicKey, addr: SocketAddr) -> IoFuture<()> {
        let resp_payload = DhtRequestPayload::NatPingResponse(NatPingResponse {
            id: payload.id,
        });
        let nat_ping_resp = DhtPacket::DhtRequest(DhtRequest::new(
            &precompute(spk, &self.sk),
            spk,
            &self.pk,
            resp_payload
        ));
        self.send_to(addr, nat_ping_resp)
    }

    /**
    handle received NatPingResponse packet, start hole-punching
    */
    fn handle_nat_ping_resp(&self, payload: NatPingResponse, spk: &PublicKey) -> IoFuture<()> {
        let mut state = self.state.write();

        let client = state.peers_cache.get_mut(spk);
        let client = match client {
            None => {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "get_client() failed in handle_nat_ping_resp()"
                )))
            },
            Some(client) => client,
        };

        if payload.id == 0 {
            return Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "NodesResponse.ping_id == 0"
            )))
        }

        let timeout_dur = Duration::from_secs(PING_TIMEOUT);
        if client.check_ping_id(payload.id, timeout_dur) {
            // TODO: start hole-punching
            Box::new( future::ok(()) )
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other, "NatPingResponse.ping_id does not match")
            ))
        }
    }
    /**
    handle received LanDiscovery packet, then create NodesRequest packet
    and send back it to the peer.
    */
    fn handle_lan_discovery(&self, packet: LanDiscovery, addr: SocketAddr) -> IoFuture<()> {
        // if Lan Discovery packet has my PK, then it is sent by myself.
        if packet.pk == self.pk {
            return Box::new(future::ok(()));
        }

        let target_node = PackedNode {
            saddr: addr,
            pk: packet.pk,
        };

        self.send_nodes_req(target_node)
    }
    /**
    send LanDiscovery packet to all broadcast addresses when dht_node runs as ipv4 mode
    */
    pub fn send_lan_discovery_ipv4(&self) -> IoFuture<()> {
        let mut ip_addrs = Server::get_ipv4_broadcast_addrs();
        // Ipv4 global broadcast address
        ip_addrs.push(
            "255.255.255.255".parse().unwrap()
        );
        let lan_packet = DhtPacket::LanDiscovery(LanDiscovery {
            pk: self.pk,
        });
        let lan_sender = ip_addrs.iter().map(|&addr|
            self.send_to(SocketAddr::new(addr, 33445), lan_packet.clone()) // 33445 is default port for tox
        );

        let lan_stream = stream::futures_unordered(lan_sender).then(|_| Ok(()));
        Box::new(lan_stream.for_each(|()| Ok(())))
    }
    /**
    send LanDiscovery packet to all broadcast addresses when dht_node runs as ipv6 mode
    */
    pub fn send_lan_discovery_ipv6(&self) -> IoFuture<()> {
        let mut ip_addrs = Server::get_ipv4_broadcast_addrs();
        // Ipv6 broadcast address
        ip_addrs.push(
            "::1".parse().unwrap() // TODO: it should be FF02::1, but for now, my LAN config has no route to address of FF02::1
        );
        // Ipv4 global broadcast address
        ip_addrs.push(
            "::ffff:255.255.255.255".parse().unwrap()
        );
        let lan_packet = DhtPacket::LanDiscovery(LanDiscovery {
            pk: self.pk,
        });
        let lan_sender = ip_addrs.iter().map(|&addr|
            self.send_to(SocketAddr::new(addr, 33445), lan_packet.clone()) // 33445 is default port for tox
        );

        let lan_stream = stream::futures_unordered(lan_sender).then(|_| Ok(()));
        Box::new(lan_stream.for_each(|()| Ok(())))
    }
    /**
    handle received OnionRequest0 packet, then create OnionRequest1 packet
    and send it to the next peer.
    */
    fn handle_onion_request_0(&self, packet: OnionRequest0, addr: SocketAddr) -> IoFuture<()> {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        let shared_secret = precompute(&packet.temporary_pk, &self.sk);
        let payload = packet.get_payload(&shared_secret);
        let payload = match payload {
            Err(e) => {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        format!("OnionRequest0::get_payload() failed: {:?}", e)
                )))
            },
            Ok(payload) => payload,
        };

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
        self.send_to(payload.ip_port.to_saddr(), next_packet)
    }
    /**
    handle received OnionRequest1 packet, then create OnionRequest2 packet
    and send it to the next peer.
    */
    fn handle_onion_request_1(&self, packet: OnionRequest1, addr: SocketAddr) -> IoFuture<()> {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        let shared_secret = precompute(&packet.temporary_pk, &self.sk);
        let payload = packet.get_payload(&shared_secret);
        let payload = match payload {
            Err(e) => {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        format!("OnionRequest1::get_payload() failed: {:?}", e)
                )))
            },
            Ok(payload) => payload,
        };

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
        self.send_to(payload.ip_port.to_saddr(), next_packet)
    }
    /**
    handle received OnionRequest2 packet, then create AnnounceRequest
    or OnionDataRequest packet and send it to the next peer.
    */
    fn handle_onion_request_2(&self, packet: OnionRequest2, addr: SocketAddr) -> IoFuture<()> {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        let shared_secret = precompute(&packet.temporary_pk, &self.sk);
        let payload = packet.get_payload(&shared_secret);
        let payload = match payload {
            Err(e) => {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        format!("OnionRequest2::get_payload() failed: {:?}", e)
                )))
            },
            Ok(payload) => payload,
        };

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
        self.send_to(payload.ip_port.to_saddr(), next_packet)
    }
    /**
    handle received AnnounceRequest packet and send AnnounceResponse packet back
    if request succeed.
    */
    fn handle_announce_request(&self, packet: AnnounceRequest, addr: SocketAddr) -> IoFuture<()> {
        let mut onion_announce = self.onion_announce.write();
        let state = self.state.read();
        let onion_return = packet.onion_return.clone();
        let response = onion_announce.handle_announce_request(packet, &self.sk, &state.kbucket, addr);
        match response {
            Ok(response) => self.send_to(addr, DhtPacket::OnionResponse3(OnionResponse3 {
                onion_return,
                payload: InnerOnionResponse::AnnounceResponse(response)
            })),
            Err(e) => Box::new(future::err(e))
        }
    }
    /**
    handle received OnionDataRequest packet and send OnionResponse3 with inner
    OnionDataResponse to destination node through its onion path.
    */
    fn handle_onion_data_request(&self, packet: OnionDataRequest) -> IoFuture<()> {
        let onion_announce = self.onion_announce.read();
        match onion_announce.handle_data_request(packet) {
            Ok((response, addr)) => self.send_to(addr, DhtPacket::OnionResponse3(response)),
            Err(e) => Box::new(future::err(e))
        }
    }
    /**
    handle received OnionResponse3 packet, then create OnionResponse2 packet
    and send it to the next peer which address is stored in encrypted onion return.
    */
    fn handle_onion_response_3(&self, packet: OnionResponse3) -> IoFuture<()> {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        let payload = packet.onion_return.get_payload(&onion_symmetric_key);
        let payload = match payload {
            Err(e) => {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        format!("OnionResponse3::get_payload() failed: {:?}", e)
                )))
            },
            Ok(payload) => payload,
        };

        if let (ip_port, Some(next_onion_return)) = payload {
            let next_packet = DhtPacket::OnionResponse2(OnionResponse2 {
                onion_return: next_onion_return,
                payload: packet.payload
            });
            self.send_to(ip_port.to_saddr(), next_packet)
        } else {
            return Box::new( future::err(
                Error::new(ErrorKind::Other,
                    format!("OnionResponse3 next_onion_return is none")
            )))
        }
    }
    /**
    handle received OnionResponse2 packet, then create OnionResponse1 packet
    and send it to the next peer which address is stored in encrypted onion return.
    */
    fn handle_onion_response_2(&self, packet: OnionResponse2) -> IoFuture<()> {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        let payload = packet.onion_return.get_payload(&onion_symmetric_key);
        let payload = match payload {
            Err(e) => {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        format!("OnionResponse2::get_payload() failed: {:?}", e)
                )))
            },
            Ok(payload) => payload,
        };

        if let (ip_port, Some(next_onion_return)) = payload {
            let next_packet = DhtPacket::OnionResponse1(OnionResponse1 {
                onion_return: next_onion_return,
                payload: packet.payload
            });
            self.send_to(ip_port.to_saddr(), next_packet)
        } else {
            return Box::new( future::err(
                Error::new(ErrorKind::Other,
                    format!("OnionResponse2 next_onion_return is none")
            )))
        }
    }
    /**
    handle received OnionResponse1 packet, then create AnnounceResponse
    or OnionDataResponse packet and send it to the next peer which address
    is stored in encrypted onion return.
    */
    fn handle_onion_response_1(&self, packet: OnionResponse1) -> IoFuture<()> {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        let payload = packet.onion_return.get_payload(&onion_symmetric_key);
        let payload = match payload {
            Err(e) => {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        format!("OnionResponse1::get_payload() failed: {:?}", e)
                )))
            },
            Ok(payload) => payload,
        };

        if let (ip_port, None) = payload {
            let next_packet = match packet.payload {
                InnerOnionResponse::AnnounceResponse(inner) => DhtPacket::AnnounceResponse(inner),
                InnerOnionResponse::OnionDataResponse(inner) => DhtPacket::OnionDataResponse(inner),
            };
            self.send_to(ip_port.to_saddr(), next_packet)
        } else {
            return Box::new( future::err(
                Error::new(ErrorKind::Other,
                    format!("OnionResponse1 next_onion_return is some")
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

    use futures::Future;
    use std::net::SocketAddr;
    use toxcore::binary_io::*;

    const ONION_RETURN_1_PAYLOAD_SIZE: usize = ONION_RETURN_1_SIZE - NONCEBYTES;
    const ONION_RETURN_2_PAYLOAD_SIZE: usize = ONION_RETURN_2_SIZE - NONCEBYTES;
    const ONION_RETURN_3_PAYLOAD_SIZE: usize = ONION_RETURN_3_SIZE - NONCEBYTES;

    macro_rules! unpack {
        ($variable:expr, $variant:path) => (
            match $variable {
                $variant(inner) => inner,
                other => panic!("Expected {} but got {:?}", stringify!($variant), other),
            }
        )
    }

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

    fn add_to_peers_cache(alice: &Server, pk: PublicKey, client: ClientData) {
        let mut state = alice.state.write();
        state.peers_cache.insert(pk, client);
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

    // handle_ping_req()
    #[test]
    fn server_handle_ping_req_test() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();

        // handle ping request, request from bob peer
        let req_payload = PingRequestPayload { id: 42 };
        let ping_req = DhtPacket::PingRequest(PingRequest::new(&precomp, &bob_pk, req_payload));

        assert!(alice.handle_packet((ping_req, addr)).wait().is_ok());

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let ping_resp = unpack!(packet, DhtPacket::PingResponse);
        let ping_resp_payload = ping_resp.get_payload(&bob_sk).unwrap();

        assert_eq!(ping_resp_payload.id, req_payload.id);
    }

    #[test]
    fn server_handle_ping_req_invalid_payload_test() {
        let (alice, precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        // error case: can't decrypt
        let req_payload = PingRequestPayload { id: 42 };
        let ping_req = DhtPacket::PingRequest(PingRequest::new(&precomp, &alice.pk, req_payload));

        assert!(alice.handle_packet((ping_req, addr)).wait().is_err());
    }

    // handle_ping_resp()
    #[test]
    fn server_handle_ping_resp_test() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        // handle ping response, request from bob peer
        // success case
        let mut client = ClientData::new();
        let ping_id = client.add_ping_id();
        let resp_payload = PingResponsePayload { id: ping_id };
        let ping_resp = DhtPacket::PingResponse(PingResponse::new(&precomp, &bob_pk, resp_payload));

        add_to_peers_cache(&alice, bob_pk, client);

        assert!(alice.handle_packet((ping_resp, addr)).wait().is_ok());
    }

    #[test]
    fn server_handle_ping_resp_invalid_payload_test() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        // wrong PK, decrypt fail
        let mut client = ClientData::new();
        let ping_id = client.add_ping_id();
        let prs = PingResponsePayload { id: ping_id };
        let ping_resp = DhtPacket::PingResponse(PingResponse::new(&precomp, &alice.pk, prs));

        add_to_peers_cache(&alice, bob_pk, client);

        assert!(alice.handle_packet((ping_resp, addr)).wait().is_err());
    }

    #[test]
    fn server_handle_ping_resp_ping_id_is_0_test() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        // ping_id = 0, fail
        let prs = PingResponsePayload { id: 0 };
        let ping_resp = DhtPacket::PingResponse(PingResponse::new(&precomp, &bob_pk, prs));

        let client = ClientData::new();
        add_to_peers_cache(&alice, bob_pk, client);

        assert!(alice.handle_packet((ping_resp, addr)).wait().is_err());
    }

    #[test]
    fn server_handle_ping_resp_invalid_ping_id_test() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        // incorrect ping_id, fail
        let mut client = ClientData::new();
        let ping_id = client.add_ping_id();
        let prs = PingResponsePayload { id: ping_id + 1 };
        let ping_resp = DhtPacket::PingResponse(PingResponse::new(&precomp, &bob_pk, prs));

        add_to_peers_cache(&alice, bob_pk, client);

        assert!(alice.handle_packet((ping_resp, addr)).wait().is_err());
    }

    // handle_nodes_req()
    #[test]
    fn server_handle_nodes_req_test() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();

        // success case
        let packed_node = PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &bob_pk);

        assert!(alice.try_add_to_kbucket(&packed_node));

        let req_payload = NodesRequestPayload { pk: bob_pk, id: 42 };
        let nodes_req = DhtPacket::NodesRequest(NodesRequest::new(&precomp, &bob_pk, req_payload));

        assert!(alice.handle_packet((nodes_req, addr)).wait().is_ok());

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let nodes_resp = unpack!(packet, DhtPacket::NodesResponse);

        let nodes_resp_payload = nodes_resp.get_payload(&bob_sk).unwrap();

        assert_eq!(nodes_resp_payload.id, req_payload.id);
    }

    #[test]
    fn server_handle_nodes_req_invalid_payload_test() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        // error case, can't decrypt
        let req_payload = NodesRequestPayload { pk: bob_pk, id: 42 };
        let nodes_req = DhtPacket::NodesRequest(NodesRequest::new(&precomp, &alice.pk, req_payload));

        assert!(alice.handle_packet((nodes_req, addr)).wait().is_err());
    }

    // handle_nodes_resp()
    #[test]
    fn server_handle_nodes_resp_test() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let node = vec![PackedNode::new(false, addr, &bob_pk)];

        // handle nodes response, request from bob peer
        let mut client = ClientData::new();
        let ping_id = client.add_ping_id();
        let resp_payload = NodesResponsePayload { nodes: node, id: ping_id };
        let nodes_resp = DhtPacket::NodesResponse(NodesResponse::new(&precomp, &bob_pk, resp_payload.clone()));

        add_to_peers_cache(&alice, bob_pk, client);

        assert!(alice.handle_packet((nodes_resp, addr)).wait().is_ok());

        let mut kbucket = Kbucket::new(&alice.pk);
        for pn in &resp_payload.nodes {
            kbucket.try_add(pn);
        }

        let state = alice.state.read();

        assert_eq!(state.kbucket, kbucket);
    }

    #[test]
    fn server_handle_nodes_resp_invalid_payload_test() {
        let (alice, precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        // error case, can't decrypt
        let resp_payload = NodesResponsePayload { nodes: vec![
            PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &gen_keypair().0)
        ], id: 38 };
        let nodes_resp = DhtPacket::NodesResponse(NodesResponse::new(&precomp, &alice.pk, resp_payload));

        assert!(alice.handle_packet((nodes_resp, addr)).wait().is_err());
    }

    #[test]
    fn server_handle_nodes_resp_ping_id_is_0_test() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        // ping_id = 0
        let resp_payload = NodesResponsePayload { nodes: vec![
            PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &gen_keypair().0)
        ], id: 0 };
        let nodes_resp = DhtPacket::NodesResponse(NodesResponse::new(&precomp, &bob_pk, resp_payload));

        let client = ClientData::new();
        add_to_peers_cache(&alice, bob_pk, client);

        assert!(alice.handle_packet((nodes_resp, addr)).wait().is_err());
    }

    #[test]
    fn server_handle_nodes_resp_invalid_ping_id_test() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        // incorrect ping_id
        let mut client = ClientData::new();
        let ping_id = client.add_ping_id();
        let resp_payload = NodesResponsePayload { nodes: vec![
            PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &gen_keypair().0)
        ], id: ping_id + 1 };
        let nodes_resp = DhtPacket::NodesResponse(NodesResponse::new(&precomp, &bob_pk, resp_payload));

        add_to_peers_cache(&alice, bob_pk, client);

        assert!(alice.handle_packet((nodes_resp, addr)).wait().is_err());
    }

    // handle_dht_req
    #[test]
    fn server_handle_dht_req_for_unknown_node_test() {
        let (alice, _precomp, bob_pk, bob_sk, _rx, addr) = create_node();

        let (charlie_pk, _charlie_sk) = gen_keypair();
        let precomp = precompute(&charlie_pk, &bob_sk);

        // if receiver' pk != node's pk just returns ok()
        let nat_req = NatPingRequest { id: 42 };
        let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
        let dht_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &charlie_pk, &bob_pk, nat_payload));

        assert!(alice.handle_packet((dht_req, addr)).wait().is_ok());
    }

    #[test]
    fn server_handle_dht_req_for_known_node_test() {
        let (alice, _precomp, bob_pk, bob_sk, _rx, addr) = create_node();

        let (charlie_pk, _charlie_sk) = gen_keypair();
        let precomp = precompute(&charlie_pk, &bob_sk);

        // if receiver' pk != node's pk and receiver's pk exists in kbucket, returns ok()
        let pn = PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &charlie_pk);
        alice.try_add_to_kbucket(&pn);

        let nat_req = NatPingRequest { id: 42 };
        let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
        let dht_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &charlie_pk, &bob_pk, nat_payload));

        assert!(alice.handle_packet((dht_req, addr)).wait().is_ok());
    }

    #[test]
    fn server_handle_dht_req_invalid_payload() {
        let (alice, _precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let dht_req = DhtPacket::DhtRequest(DhtRequest {
            rpk: alice.pk,
            spk: bob_pk,
            nonce: gen_nonce(),
            payload: vec![42, 123]
        });

        assert!(alice.handle_packet((dht_req, addr)).wait().is_err());
    }

    // handle nat ping request
    #[test]
    fn server_handle_nat_ping_req_test() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();

        let nat_req = NatPingRequest { id: 42 };
        let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
        let dht_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &bob_pk, nat_payload));

        assert!(alice.handle_packet((dht_req, addr)).wait().is_ok());

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let dht_req = unpack!(packet, DhtPacket::DhtRequest);
        let dht_payload = dht_req.get_payload(&bob_sk).unwrap();
        let nat_ping_resp_payload = unpack!(dht_payload, DhtRequestPayload::NatPingResponse);

        assert_eq!(nat_ping_resp_payload.id, nat_req.id);
    }

    // handle nat ping response
    #[test]
    fn server_handle_nat_ping_resp_test() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        // success case
        let mut client = ClientData::new();
        let ping_id = client.add_ping_id();
        let nat_res = NatPingResponse { id: ping_id };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &bob_pk, nat_payload));

        add_to_peers_cache(&alice, bob_pk, client);

        assert!(alice.handle_packet((dht_req, addr)).wait().is_ok());
    }

    #[test]
    fn server_handle_nat_ping_resp_ping_id_is_0_test() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        // error case, ping_id = 0
        let nat_res = NatPingResponse { id: 0 };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &bob_pk, nat_payload));

        let client = ClientData::new();
        add_to_peers_cache(&alice, bob_pk, client);

        assert!(alice.handle_packet((dht_req, addr)).wait().is_err());
    }

    #[test]
    fn server_handle_nat_ping_resp_invalid_ping_id_test() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        // error case, incorrect ping_id
        let mut client = ClientData::new();
        let ping_id = client.add_ping_id();
        let nat_res = NatPingResponse { id: ping_id + 1 };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &bob_pk, nat_payload));

        add_to_peers_cache(&alice, bob_pk, client);

        assert!(alice.handle_packet((dht_req, addr)).wait().is_err());
    }

    // handle_onion_request_0
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

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, DhtPacket::OnionRequest1);

        assert_eq!(next_packet.temporary_pk, temporary_pk);
        assert_eq!(next_packet.payload, inner);

        let onion_symmetric_key = alice.onion_symmetric_key.read();
        let onion_return_payload = next_packet.onion_return.get_payload(&onion_symmetric_key).unwrap();

        assert_eq!(onion_return_payload.0, IpPort::from_saddr(addr));
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

    // handle_onion_request_1
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

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, DhtPacket::OnionRequest2);

        assert_eq!(next_packet.temporary_pk, temporary_pk);
        assert_eq!(next_packet.payload, inner);

        let onion_symmetric_key = alice.onion_symmetric_key.read();
        let onion_return_payload = next_packet.onion_return.get_payload(&onion_symmetric_key).unwrap();

        assert_eq!(onion_return_payload.0, IpPort::from_saddr(addr));
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

    // handle_onion_request_2
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

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, DhtPacket::AnnounceRequest);

        assert_eq!(next_packet.inner, inner);

        let onion_symmetric_key = alice.onion_symmetric_key.read();
        let onion_return_payload = next_packet.onion_return.get_payload(&onion_symmetric_key).unwrap();

        assert_eq!(onion_return_payload.0, IpPort::from_saddr(addr));
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

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, DhtPacket::OnionDataRequest);

        assert_eq!(next_packet.inner, inner);

        let onion_symmetric_key = alice.onion_symmetric_key.read();
        let onion_return_payload = next_packet.onion_return.get_payload(&onion_symmetric_key).unwrap();
        
        assert_eq!(onion_return_payload.0, IpPort::from_saddr(addr));
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

    // handle_announce_request
    #[test]
    fn server_handle_announce_request_test() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let sendback_data = 42;
        let payload = AnnounceRequestPayload {
            ping_id: initial_ping_id(),
            search_pk: gen_keypair().0,
            data_pk: gen_keypair().0,
            sendback_data
        };
        let inner = InnerAnnounceRequest::new(&precomp, &bob_pk, payload);
        let onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
        };
        let packet = DhtPacket::AnnounceRequest(AnnounceRequest {
            inner,
            onion_return: onion_return.clone()
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_ok());

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let response = unpack!(packet, DhtPacket::OnionResponse3);

        assert_eq!(response.onion_return, onion_return);

        let response = unpack!(response.payload, InnerOnionResponse::AnnounceResponse);

        assert_eq!(response.sendback_data, sendback_data);

        let payload = response.get_payload(&precomp).unwrap();

        assert_eq!(payload.announce_status, AnnounceStatus::Failed);
    }

    // handle_onion_data_request
    #[test]
    fn server_handle_onion_data_request_test() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        // get ping id

        let payload = AnnounceRequestPayload {
            ping_id: initial_ping_id(),
            search_pk: gen_keypair().0,
            data_pk: gen_keypair().0,
            sendback_data: 42
        };
        let inner = InnerAnnounceRequest::new(&precomp, &bob_pk, payload);
        let onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
        };
        let packet = DhtPacket::AnnounceRequest(AnnounceRequest {
            inner,
            onion_return: onion_return.clone()
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_ok());

        let (received, rx) = rx.into_future().wait().unwrap();
        let (packet, _addr_to_send) = received.unwrap();
        let response = unpack!(packet, DhtPacket::OnionResponse3);
        let response = unpack!(response.payload, InnerOnionResponse::AnnounceResponse);
        let payload = response.get_payload(&precomp).unwrap();
        let ping_id = payload.ping_id_or_pk;

        // announce node

        let payload = AnnounceRequestPayload {
            ping_id,
            search_pk: gen_keypair().0,
            data_pk: gen_keypair().0,
            sendback_data: 42
        };
        let inner = InnerAnnounceRequest::new(&precomp, &bob_pk, payload);
        let packet = DhtPacket::AnnounceRequest(AnnounceRequest {
            inner,
            onion_return: onion_return.clone()
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_ok());

        // send onion data request

        let nonce = gen_nonce();
        let temporary_pk = gen_keypair().0;
        let payload = vec![42; 123];
        let inner = InnerOnionDataRequest {
            destination_pk: bob_pk,
            nonce,
            temporary_pk,
            payload: payload.clone()
        };
        let packet = DhtPacket::OnionDataRequest(OnionDataRequest {
            inner,
            onion_return: onion_return.clone()
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_ok());

        let (received, _rx) = rx.skip(1).into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let response = unpack!(packet, DhtPacket::OnionResponse3);

        assert_eq!(response.onion_return, onion_return);

        let response = unpack!(response.payload, InnerOnionResponse::OnionDataResponse);

        assert_eq!(response.nonce, nonce);
        assert_eq!(response.temporary_pk, temporary_pk);
        assert_eq!(response.payload, payload);
    }

    // handle_onion_response_3
    #[test]
    fn server_handle_onion_response_3_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read();

        let ip_port = IpPort {
          ip_addr: "5.6.7.8".parse().unwrap(),
          port: 12345
        };
        let next_onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
        };
        let onion_return = OnionReturn::new(&onion_symmetric_key, &ip_port, Some(&next_onion_return));
        let payload = InnerOnionResponse::AnnounceResponse(AnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42, 123]
        });
        let packet = DhtPacket::OnionResponse3(OnionResponse3 {
            onion_return,
            payload: payload.clone()
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_ok());

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, DhtPacket::OnionResponse2);

        assert_eq!(next_packet.payload, payload);
        assert_eq!(next_packet.onion_return, next_onion_return);
    }

    #[test]
    fn server_handle_onion_response_3_invalid_onion_return_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE] // not encrypted with onion_symmetric_key
        };
        let payload = InnerOnionResponse::AnnounceResponse(AnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42, 123]
        });
        let packet = DhtPacket::OnionResponse3(OnionResponse3 {
            onion_return,
            payload
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_err());
    }

    #[test]
    fn server_handle_onion_response_3_invalid_next_onion_return_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read();

        let ip_port = IpPort {
          ip_addr: "5.6.7.8".parse().unwrap(),
          port: 12345
        };
        let onion_return = OnionReturn::new(&onion_symmetric_key, &ip_port, None);
        let inner = OnionDataResponse {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42, 123]
        };
        let packet = DhtPacket::OnionResponse3(OnionResponse3 {
            onion_return,
            payload: InnerOnionResponse::OnionDataResponse(inner.clone())
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_err());
    }

    // handle_onion_response_2
    #[test]
    fn server_handle_onion_response_2_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read();

        let ip_port = IpPort {
          ip_addr: "5.6.7.8".parse().unwrap(),
          port: 12345
        };
        let next_onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
        };
        let onion_return = OnionReturn::new(&onion_symmetric_key, &ip_port, Some(&next_onion_return));
        let payload = InnerOnionResponse::AnnounceResponse(AnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42, 123]
        });
        let packet = DhtPacket::OnionResponse2(OnionResponse2 {
            onion_return,
            payload: payload.clone()
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_ok());

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, DhtPacket::OnionResponse1);

        assert_eq!(next_packet.payload, payload);
        assert_eq!(next_packet.onion_return, next_onion_return);
    }

    #[test]
    fn server_handle_onion_response_2_invalid_onion_return_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE] // not encrypted with onion_symmetric_key
        };
        let payload = InnerOnionResponse::AnnounceResponse(AnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42, 123]
        });
        let packet = DhtPacket::OnionResponse2(OnionResponse2 {
            onion_return,
            payload
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_err());
    }

    #[test]
    fn server_handle_onion_response_2_invalid_next_onion_return_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read();

        let ip_port = IpPort {
          ip_addr: "5.6.7.8".parse().unwrap(),
          port: 12345
        };
        let onion_return = OnionReturn::new(&onion_symmetric_key, &ip_port, None);
        let inner = OnionDataResponse {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42, 123]
        };
        let packet = DhtPacket::OnionResponse2(OnionResponse2 {
            onion_return,
            payload: InnerOnionResponse::OnionDataResponse(inner.clone())
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_err());
    }

    // handle_onion_response_1
    #[test]
    fn server_handle_onion_response_1_with_announce_response_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read();

        let ip_port = IpPort {
          ip_addr: "5.6.7.8".parse().unwrap(),
          port: 12345
        };
        let onion_return = OnionReturn::new(&onion_symmetric_key, &ip_port, None);
        let inner = AnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42, 123]
        };
        let packet = DhtPacket::OnionResponse1(OnionResponse1 {
            onion_return,
            payload: InnerOnionResponse::AnnounceResponse(inner.clone())
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_ok());

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, DhtPacket::AnnounceResponse);

        assert_eq!(next_packet, inner);
    }

    #[test]
    fn server_handle_onion_response_1_with_onion_data_response_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read();

        let ip_port = IpPort {
          ip_addr: "5.6.7.8".parse().unwrap(),
          port: 12345
        };
        let onion_return = OnionReturn::new(&onion_symmetric_key, &ip_port, None);
        let inner = OnionDataResponse {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42, 123]
        };
        let packet = DhtPacket::OnionResponse1(OnionResponse1 {
            onion_return,
            payload: InnerOnionResponse::OnionDataResponse(inner.clone())
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_ok());

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, DhtPacket::OnionDataResponse);

        assert_eq!(next_packet, inner);
    }

    #[test]
    fn server_handle_onion_response_1_invalid_onion_return_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE] // not encrypted with onion_symmetric_key
        };
        let payload = InnerOnionResponse::AnnounceResponse(AnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42, 123]
        });
        let packet = DhtPacket::OnionResponse1(OnionResponse1 {
            onion_return,
            payload
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_err());
    }

    #[test]
    fn server_handle_onion_response_1_invalid_next_onion_return_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read();

        let ip_port = IpPort {
          ip_addr: "5.6.7.8".parse().unwrap(),
          port: 12345
        };
        let next_onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
        };
        let onion_return = OnionReturn::new(&onion_symmetric_key, &ip_port, Some(&next_onion_return));
        let inner = OnionDataResponse {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42, 123]
        };
        let packet = DhtPacket::OnionResponse1(OnionResponse1 {
            onion_return,
            payload: InnerOnionResponse::OnionDataResponse(inner.clone())
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_err());
    }

    // send_pings()
    #[test]
    fn server_send_pings_test() {
        let (alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let (ping_pk, ping_sk) = gen_keypair();

        let pn = PackedNode::new(false, SocketAddr::V4("127.1.1.1:12345".parse().unwrap()), &ping_pk);
        assert!(alice.try_add_to_kbucket(&pn));
        let pn = PackedNode::new(false, SocketAddr::V4("127.0.0.1:33445".parse().unwrap()), &bob_pk);
        assert!(alice.try_add_to_kbucket(&pn));

        alice.send_pings().wait().unwrap();

        let mut state = alice.state.write();
        rx.take(2).map(|received| {
            let (packet, addr) = received;
            let mut buf = [0; 512];
            let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
            let (_, ping_req) = PingRequest::from_bytes(&buf[..size]).unwrap();
            if addr == SocketAddr::V4("127.0.0.1:33445".parse().unwrap()) {
                let client = state.peers_cache.get_mut(&bob_pk).unwrap();
                let ping_req_payload = ping_req.get_payload(&bob_sk).unwrap();
                let dur = Duration::from_secs(PING_TIMEOUT);
                assert!(client.check_ping_id(ping_req_payload.id, dur));
            } else {
                let client = state.peers_cache.get_mut(&ping_pk).unwrap();
                let ping_req_payload = ping_req.get_payload(&ping_sk).unwrap();
                let dur = Duration::from_secs(PING_TIMEOUT);
                assert!(client.check_ping_id(ping_req_payload.id, dur));
            }
        }).collect().wait().unwrap();
    }

    // periodical_nodes_req()
    #[test]
    fn server_periodical_nodes_req_test() {
        let (alice, _precomp, bob_pk, bob_sk, rx, addr) = create_node();

        // If there is no entry in kbucket, then it returns just ok()
        assert!(alice.periodical_nodes_req().wait().is_ok());

        // Now, test with kbucket entry
        let node = PackedNode::new(false, addr, &bob_pk);

        alice.try_add_to_kbucket(&node);

        alice.periodical_nodes_req().wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let nodes_req = unpack!(packet, DhtPacket::NodesRequest);
        let nodes_req_payload = nodes_req.get_payload(&bob_sk).unwrap();

        assert_eq!(nodes_req_payload.pk, node.pk);
    }

    // send_nat_ping_req()
    #[test]
    fn server_send_nat_ping_req_test() {
        let (alice, _precomp, bob_pk, _bob_sk, rx, _addr) = create_node();

        let addr = SocketAddr::V4("127.0.0.1:12345".parse().unwrap());
        let node = PackedNode::new(false, addr, &alice.pk);
        alice.try_add_to_kbucket(&node);

        assert!(alice.send_nat_ping_req(node, bob_pk).wait().is_ok());

        let mut state = alice.state.write();
        let client = state.peers_cache.get_mut(&alice.pk).unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let nat_ping_req = unpack!(packet, DhtPacket::DhtRequest);
        let nat_ping_req_payload = nat_ping_req.get_payload(&alice.sk).unwrap();
        let nat_ping_req_payload = unpack!(nat_ping_req_payload, DhtRequestPayload::NatPingRequest);

        let dur = Duration::from_secs(PING_TIMEOUT);
        assert!(client.check_ping_id(nat_ping_req_payload.id, dur));
    }

    #[test]
    fn server_handle_lan_discovery_test() {
        let (alice, _precomp, bob_pk, bob_sk, rx, addr) = create_node();

        let lan = DhtPacket::LanDiscovery(LanDiscovery { pk: bob_pk });

        assert!(alice.handle_packet((lan, addr)).wait().is_ok());

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let nodes_req = unpack!(packet, DhtPacket::NodesRequest);
        let _nodes_req_payload = nodes_req.get_payload(&bob_sk).unwrap();

        assert_eq!(nodes_req.pk, alice.pk);
    }

    #[test]
    fn server_handle_lan_discovery_for_ourselves_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let lan = DhtPacket::LanDiscovery(LanDiscovery { pk: alice.pk });

        assert!(alice.handle_packet((lan, addr)).wait().is_ok());
    }

    #[test]
    fn server_send_lan_discovery_ipv4_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, mut rx, _addr) = create_node();

        assert!(alice.send_lan_discovery_ipv4().wait().is_ok());

        let ifs = get_if_addrs::get_if_addrs().expect("no network interface");
        let broad_vec: Vec<SocketAddr> = ifs.iter().filter_map(|interface| 
            match interface.addr {
                IfAddr::V4(ref addr) => addr.broadcast,
                _ => None,
            })
            .map(|ipv4|
                SocketAddr::new(IpAddr::V4(ipv4), 33445)
            ).collect();

        for _i in 0..broad_vec.len() + 1 { // `+1` for 255.255.255.255
            let (received, rx1) = rx.into_future().wait().unwrap();
            let (packet, _addr) = received.unwrap();

            let lan_discovery = unpack!(packet, DhtPacket::LanDiscovery);

            assert_eq!(lan_discovery.pk, alice.pk);

            rx = rx1;
        }
    }

    #[test]
    fn server_send_lan_discovery_ipv6_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, mut rx, _addr) = create_node();

        assert!(alice.send_lan_discovery_ipv6().wait().is_ok());

        let ifs = get_if_addrs::get_if_addrs().expect("no network interface");
        let broad_vec: Vec<SocketAddr> = ifs.iter().filter_map(|interface| 
            match interface.addr {
                IfAddr::V4(ref addr) => addr.broadcast,
                _ => None,
            })
            .map(|ipv4|
                SocketAddr::new(IpAddr::V4(ipv4), 33445)
            ).collect();

        for _i in 0..broad_vec.len() + 2 { // `+2` for ::1 and ::ffff:255.255.255.255
            let (received, rx1) = rx.into_future().wait().unwrap();
            let (packet, _addr) = received.unwrap();

            let lan_discovery = unpack!(packet, DhtPacket::LanDiscovery);

            assert_eq!(lan_discovery.pk, alice.pk);

            rx = rx1;
        }
    }

    // remove_timedout_clients(), case of client removed
    #[test]
    fn server_remove_timedout_clients_removed_test() {
        let (alice, _precomp, bob_pk, _bob_sk, _rx, _addr) = create_node();

        let node = PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &bob_pk);

        alice.try_add_to_kbucket(&node);

        alice.send_pings().wait().unwrap();

        let dur = Duration::from_secs(0);
        alice.remove_timedout_clients(dur).wait().unwrap();

        let state = alice.state.read();

        // after client be removed
        assert!(!state.peers_cache.contains_key(&bob_pk));
        // peer should be removed from kbucket
        assert!(!state.kbucket.contains(&bob_pk));
    }

    // remove_timedout_clients(), case of client remained
    #[test]
    fn server_remove_timedout_clients_remained_test() {
        let (alice, _precomp, bob_pk, _bob_sk, _rx, _addr) = create_node();

        let node = PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &bob_pk);

        alice.try_add_to_kbucket(&node);

        alice.send_pings().wait().unwrap();

        let dur = Duration::from_secs(1);
        alice.remove_timedout_clients(dur).wait().unwrap();

        let state = alice.state.read();

        // client should be remained
        assert!(state.peers_cache.contains_key(&bob_pk));
        // peer should be remained in kbucket
        assert!(state.kbucket.contains(&bob_pk));
    }

    #[test]
    fn refresh_onion_key_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, _addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read().clone();
        alice.refresh_onion_key();

        assert!(*alice.onion_symmetric_key.read() != onion_symmetric_key)
    }
}
