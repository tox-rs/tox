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
        }
    }

    /// create new client
    pub fn create_client(&self, pk: PublicKey, peers_cache: &HashMap<PublicKey, Client>) -> Client {
        if let Some(client) = peers_cache.get(&pk) {
            client.clone()
        } else {
            Client::new()
        }
    }
    /// remove timed-out clients, also remove node from kbucket
    pub fn remove_timedout_clients(&self, timeout: Duration) -> IoFuture<()> {
        let mut state = self.state.write();
        let timeout_peers = state.peers_cache.iter()
            .filter(|&(_pk, ref client)| client.last_resp_time.elapsed() > timeout)
            .map(|(pk, _client)| *pk)
            .collect::<Vec<_>>();

        timeout_peers.into_iter().for_each(|pk| state.kbucket.remove(&pk));

        state.peers_cache.retain(|&_pk, ref client|
            client.last_resp_time.elapsed() <= timeout);
        Box::new(future::ok(()))
    }
    /// send PingRequest to all peers in kbucket
    pub fn send_pings(&self) -> IoFuture<()> {
        let mut state = self.state.write();
        let ping_sender = state.kbucket.iter().map(|peer| {
            let mut client = self.create_client(peer.pk, &state.peers_cache);

            let payload = PingRequestPayload {
                id: client.new_ping_id(),
            };
            let ping_req = DhtPacket::PingRequest(PingRequest::new(
                &precompute(&peer.pk, &self.sk),
                &self.pk,
                payload
            ));
            let result = self.send_to(peer.saddr, ping_req);

            state.peers_cache.insert(peer.pk, client);

            result
        });

        let pings_stream = stream::futures_unordered(ping_sender).then(|_| Ok(()));

        Box::new(pings_stream.for_each(|()| Ok(())))
    }
    /// send NodesRequest to random peer every 20 seconds
    pub fn send_nodes_req(&self, friend_pk: PublicKey) -> IoFuture<()> {
        let mut state = self.state.write();
        if let Some(peer) = state.kbucket.get_random_node() {
            let mut client = self.create_client(peer.pk, &state.peers_cache);

            let payload = NodesRequestPayload {
                pk: friend_pk,
                id: client.new_ping_id(),
            };
            let nodes_req = DhtPacket::NodesRequest(NodesRequest::new(
                &precompute(&peer.pk, &self.sk),
                &self.pk,
                payload
            ));
            let result = self.send_to(peer.saddr, nodes_req);

            state.peers_cache.insert(peer.pk, client);

            result
        }
        else {
            return Box::new(future::ok(()));
        }
    }
    /// send NatPingRequests to peers every 3 seconds
    pub fn send_nat_ping_req(&self, peer: PackedNode, friend_pk: PublicKey) -> IoFuture<()> {
        let mut state = self.state.write();

        let mut client = self.create_client(peer.pk, &state.peers_cache);

        let payload = DhtRequestPayload::NatPingRequest(NatPingRequest {
            id: client.new_ping_id(),
        });
        let nat_ping_req = DhtPacket::DhtRequest(DhtRequest::new(
            &precompute(&peer.pk, &self.sk),
            &friend_pk,
            &self.pk,
            payload
        ));
        let result = self.send_to(peer.saddr, nat_ping_req);

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
                // The packet kind of DhtRequest is in encrypted payload,
                // so decrypting is needed first.
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
                        self.handle_nat_ping_req(packet, nat_payload, addr)
                    },
                    DhtRequestPayload::NatPingResponse(nat_payload) => {
                        debug!("Received nat ping response");
                        self.handle_nat_ping_resp(packet, nat_payload)
                    },
                }
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
                error!("send to peer error {:?}", e);
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

        if client.ping_id == payload.id {
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

        if payload.id == 0 {
            return Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "NodesResponse.ping_id == 0"
            )))
        }

        let client = state.peers_cache.get(&packet.pk);
        let client = match client {
            None => {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "get_client() failed in handle_nodes_resp()"
                )))
            },
            Some(client) => client,
        };

        if client.ping_id == payload.id {
            for node in &payload.nodes {
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
    handle received NatPingRequest packet, respond with NatPingResponse
    */
    fn handle_nat_ping_req(&self, packet: DhtRequest, payload: NatPingRequest, addr: SocketAddr) -> IoFuture<()> {
        let state = self.state.read();

        if packet.rpk == self.pk { // the target peer is me
            let resp_payload = DhtRequestPayload::NatPingResponse(NatPingResponse {
                id: payload.id,
            });
            let nat_ping_resp = DhtPacket::DhtRequest(DhtRequest::new(
                &precompute(&packet.spk, &self.sk),
                &packet.spk,
                &self.pk,
                resp_payload
            ));
            self.send_to(addr, nat_ping_resp)
        } else { // search kbucket to find target peer
            if let Some(addr) = state.kbucket.get_node(&packet.rpk) {
                let packet = DhtPacket::DhtRequest(packet);
                self.send_to(addr, packet)
            }
            else { // do nothing
                Box::new( future::ok(()) )
            }
        }
    }

    /**
    handle received NatPingResponse packet, start hole-punching
    */
    fn handle_nat_ping_resp(&self, packet: DhtRequest, payload: NatPingResponse) -> IoFuture<()> {
        let state = self.state.read();
        let client = state.peers_cache.get(&packet.spk);
        let client = match client {
            None => {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "get_client() failed in handle_nat_ping_resp()"
                )))
            },
            Some(client) => client,
        };

        if packet.rpk == self.pk { // the target peer is me
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
            if let Some(addr) = state.kbucket.get_node(&packet.rpk) {
                let packet = DhtPacket::DhtRequest(packet);
                self.send_to(addr, packet)
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
    fn handle_lan_discovery(&self, packet: LanDiscovery, addr: SocketAddr) -> IoFuture<()> {
        // if Lan Discovery packet has my PK, then it is sent by myself.
        if packet.pk == self.pk {
            return Box::new(future::ok(()));
        }
        let mut state = self.state.write();

        let mut client = self.create_client(packet.pk, &state.peers_cache);

        let payload = NodesRequestPayload {
            pk: packet.pk,
            id: client.new_ping_id(),
        };
        let nodes_req = DhtPacket::NodesRequest(NodesRequest::new(
            &precompute(&packet.pk, &self.sk),
            &self.pk,
            payload
        ));
        let result = self.send_to(addr, nodes_req);

        state.peers_cache.insert(packet.pk, client);

        result
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
    pub fn handle_onion_request_0(&self, packet: OnionRequest0, addr: SocketAddr) -> IoFuture<()> {
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
    pub fn handle_onion_request_1(&self, packet: OnionRequest1, addr: SocketAddr) -> IoFuture<()> {
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
    pub fn handle_onion_request_2(&self, packet: OnionRequest2, addr: SocketAddr) -> IoFuture<()> {
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
    handle received OnionResponse3 packet, then create OnionResponse2 packet
    and send it to the next peer which address is stored in encrypted onion return.
    */
    pub fn handle_onion_response_3(&self, packet: OnionResponse3) -> IoFuture<()> {
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
    pub fn handle_onion_response_2(&self, packet: OnionResponse2) -> IoFuture<()> {
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
    pub fn handle_onion_response_1(&self, packet: OnionResponse1) -> IoFuture<()> {
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

    use quickcheck::TestResult;
    use futures::Future;
    use std::net::SocketAddr;
    use toxcore::binary_io::*;

    const ONION_RETURN_1_PAYLOAD_SIZE: usize = ONION_RETURN_1_SIZE - NONCEBYTES;
    const ONION_RETURN_2_PAYLOAD_SIZE: usize = ONION_RETURN_2_SIZE - NONCEBYTES;
    const ONION_RETURN_3_PAYLOAD_SIZE: usize = ONION_RETURN_3_SIZE - NONCEBYTES;

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
        state.kbucket = Kbucket::new(&alice.pk);
    }
    fn clear_peers_cache(alice: &Server) {
        let mut state = alice.state.write();
        state.peers_cache.clear();
    }
    fn add_to_peers_cache(alice: &Server, pk: PublicKey, client: &Client) {
        let mut state = alice.state.write();
        state.peers_cache.insert(pk, client.clone());
    }
    fn create_client(alice: &Server, pk: PublicKey) -> Client {
        let state = alice.state.read();
        alice.create_client(pk, &state.peers_cache)
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
            // Try to handle_packet() without registered client, it fail
            assert!(alice.handle_packet((ping_res.clone(), addr)).wait().is_err());
            // Now, test with client
            let mut client = create_client(&alice, bob_pk);
            client.ping_id = prs.id;
            add_to_peers_cache(&alice, bob_pk, &client);
            assert!(alice.handle_packet((ping_res, addr)).wait().is_ok());

            // handle nodes request from bob
            let nodes_req = DhtPacket::NodesRequest(NodesRequest::new(&precomp, &bob_pk, nrq));
            let packed_node = PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &bob_pk);
            assert!(alice.try_add_to_kbucket(&packed_node));

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
            // Try to handle_packet() without registered client, it fail
            assert!(alice.handle_packet((nodes_res.clone(), addr)).wait().is_err());
            // Now, test with client
            let mut client = create_client(&alice, bob_pk);
            client.ping_id = nrs.id;
            clear_kbucket(&alice);
            add_to_peers_cache(&alice, bob_pk, &client);
            let mut kbuc = Kbucket::new(&alice.pk);
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
            // Try to handle_packet() without registered client, it fail
            assert!(alice.handle_packet((nat_ping_res.clone(), addr)).wait().is_err());
            // Now, test with client
            let mut client = create_client(&alice, bob_pk);
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
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();
        // handle ping request, request from bob peer
        let prq = PingRequestPayload { id: random_u64() };
        let ping_req = DhtPacket::PingRequest(PingRequest::new(&precomp, &bob_pk, prq));
        alice.handle_packet((ping_req, addr)).wait().unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        debug!("received packet {:?}", received.clone().unwrap().1);
        let (packet, _addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, ping_res) = PingResponse::from_bytes(&buf[..size]).unwrap();
        let ping_resp_payload = ping_res.get_payload(&bob_sk).unwrap();
        assert_eq!(ping_resp_payload.id, prq.id);

        // error case: can't decrypt
        let prq = PingRequestPayload { id: random_u64() };
        let ping_req = DhtPacket::PingRequest(PingRequest::new(&precomp, &alice.pk, prq));
        assert!(!alice.handle_packet((ping_req, addr)).wait().is_ok());
    }

    // handle_ping_resp()
    #[test]
    fn server_handle_ping_resp_test() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();
        // handle ping response, request from bob peer
        // success case
        let prs = PingResponsePayload { id: random_u64() };
        let ping_resp = DhtPacket::PingResponse(PingResponse::new(&precomp, &bob_pk, prs));
        let mut client = create_client(&alice, bob_pk);
        client.ping_id = prs.id;
        add_to_peers_cache(&alice, bob_pk, &client);
        assert!(alice.handle_packet((ping_resp, addr)).wait().is_ok());

        // wrong PK, decrypt fail
        let prs = PingResponsePayload { id: random_u64() };
        let ping_resp = DhtPacket::PingResponse(PingResponse::new(&precomp, &alice.pk, prs));
        let mut client = create_client(&alice, bob_pk);
        client.ping_id = prs.id;
        add_to_peers_cache(&alice, bob_pk, &client);
        assert!(alice.handle_packet((ping_resp, addr)).wait().is_err());

        // ping_id = 0, fail
        let prs = PingResponsePayload { id: 0 };
        let ping_resp = DhtPacket::PingResponse(PingResponse::new(&precomp, &bob_pk, prs));
        let mut client = create_client(&alice, bob_pk);
        client.ping_id = 0;
        add_to_peers_cache(&alice, bob_pk, &client);
        assert!(alice.handle_packet((ping_resp, addr)).wait().is_err());

        // incorrect ping_id, fail
        let prs = PingResponsePayload { id: random_u64() };
        let ping_resp = DhtPacket::PingResponse(PingResponse::new(&precomp, &bob_pk, prs));
        let mut client = create_client(&alice, bob_pk);
        client.ping_id = prs.id+1;
        add_to_peers_cache(&alice, bob_pk, &client);
        assert!(alice.handle_packet((ping_resp, addr)).wait().is_err());
    }

    // handle_nodes_req()
    #[test]
    fn server_handle_nodes_req_test() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();
        // success case
        let packed_node = PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &bob_pk);

        assert!(alice.try_add_to_kbucket(&packed_node));

        let nrq = NodesRequestPayload { pk: bob_pk, id: random_u64() };
        let nodes_req = DhtPacket::NodesRequest(NodesRequest::new(&precomp, &bob_pk, nrq));
        alice.handle_packet((nodes_req, addr)).wait().unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        debug!("received packet {:?}", received.clone().unwrap().0);
        let (packet, _addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, nodes_res) = NodesResponse::from_bytes(&buf[..size]).unwrap();
        let nodes_resp_payload = nodes_res.get_payload(&bob_sk).unwrap();
        assert_eq!(nodes_resp_payload.id, nrq.id);

        // error case, can't decrypt
        let nodes_req = DhtPacket::NodesRequest(NodesRequest::new(&precomp, &alice.pk, nrq));
        assert!(alice.handle_packet((nodes_req, addr)).wait().is_err());
    }

    // handle_nodes_resp()
    #[test]
    fn server_handle_nodes_resp_test() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();
        // handle nodes response, request from bob peer
        let nrs = NodesResponsePayload { nodes: vec![
            PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &gen_keypair().0)
        ], id: 38 };

        let nodes_resp = DhtPacket::NodesResponse(NodesResponse::new(&precomp, &bob_pk, nrs.clone()));
        let mut client = create_client(&alice, bob_pk);
        client.ping_id = 38;
        add_to_peers_cache(&alice, bob_pk, &client);
        alice.handle_packet((nodes_resp, addr)).wait().unwrap();
        let mut kbuc = Kbucket::new(&alice.pk);
        for pn in &nrs.nodes {
            kbuc.try_add(pn);
        }

        is_kbucket_eq(&alice, kbuc);

        // error case, can't decrypt
        let nodes_resp = DhtPacket::NodesResponse(NodesResponse::new(&precomp, &alice.pk, nrs.clone()));
        let pk = alice.pk;
        let mut client = create_client(&alice, pk);
        client.ping_id = 38;
        add_to_peers_cache(&alice, pk, &client);
        assert!(alice.handle_packet((nodes_resp, addr)).wait().is_err());

        // ping_id = 0
        let nrs = NodesResponsePayload { nodes: vec![
            PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &gen_keypair().0)
        ], id: 0 };
        let nodes_resp = DhtPacket::NodesResponse(NodesResponse::new(&precomp, &bob_pk, nrs.clone()));
        let mut client = create_client(&alice, bob_pk);
        client.ping_id = 0;
        add_to_peers_cache(&alice, bob_pk, &client);
        assert!(alice.handle_packet((nodes_resp, addr)).wait().is_err());

        // incorrect ping_id
        let nrs = NodesResponsePayload { nodes: vec![
            PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &gen_keypair().0)
                ], id: 38 };
        let nodes_resp = DhtPacket::NodesResponse(NodesResponse::new(&precomp, &bob_pk, nrs.clone()));
        let mut client = create_client(&alice, bob_pk);
        client.ping_id = 38 + 1;
        add_to_peers_cache(&alice, bob_pk, &client);
        assert!(alice.handle_packet((nodes_resp, addr)).wait().is_err());
    }

    // handle nat ping request
    #[test]
    fn server_handle_nat_ping_req_test() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();
        let nat_req = NatPingRequest { id: random_u64() };
        let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
        let dht_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &bob_pk, nat_payload.clone()));
        alice.handle_packet((dht_req, addr)).wait().unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        debug!("received packet {:?}", received.clone().unwrap().1);
        let (packet, _addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, dht_req) = DhtRequest::from_bytes(&buf[..size]).unwrap();
        let dht_payload = dht_req.get_payload(&bob_sk).unwrap();
        let (_, size) = dht_payload.to_bytes((&mut buf, 0)).unwrap();
        let (_, nat_ping_resp_payload) = NatPingResponse::from_bytes(&buf[..size]).unwrap();
        assert_eq!(nat_ping_resp_payload.id, nat_req.id);

        // if receiver' pk != node's pk just returns ok()
        let nat_req = NatPingRequest { id: random_u64() };
        let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
        let dht_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &bob_pk, &bob_pk, nat_payload.clone()));
        assert!(alice.handle_packet((dht_req, addr)).wait().is_ok());

        // if receiver' pk != node's pk and receiver's pk exists in kbucket, returns ok()
        let pn = PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &bob_pk);

        alice.try_add_to_kbucket(&pn);
        let nat_req = NatPingRequest { id: random_u64() };
        let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
        let dht_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &bob_pk, &bob_pk, nat_payload.clone()));
        assert!(alice.handle_packet((dht_req, addr)).wait().is_ok());
    }

    // handle nat ping response
    #[test]
    fn server_handle_nat_ping_resp_test() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();
        // if receiver' pk != node's pk just returns ok()
        let nat_res = NatPingResponse { id: random_u64() };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &bob_pk, &bob_pk, nat_payload.clone()));
        let client = create_client(&alice, bob_pk);
        add_to_peers_cache(&alice, bob_pk, &client);
        assert!(alice.handle_packet((dht_req, addr)).wait().is_ok());
        // if receiver' pk != node's pk and receiver's pk exists in kbucket, returns ok()
        let pn = PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &bob_pk);

        alice.try_add_to_kbucket(&pn);
        let nat_res = NatPingResponse { id: random_u64() };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &bob_pk, &bob_pk, nat_payload.clone()));
        let client = create_client(&alice, bob_pk);
        add_to_peers_cache(&alice, bob_pk, &client);
        assert!(alice.handle_packet((dht_req, addr)).wait().is_ok());
        // success case
        let nat_res = NatPingResponse { id: random_u64() };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &bob_pk, nat_payload.clone()));
        let mut client = create_client(&alice, bob_pk);
        client.ping_id = nat_res.id;
        add_to_peers_cache(&alice, bob_pk, &client);
        assert!(alice.handle_packet((dht_req, addr)).wait().is_ok());
        // error case, incorrect ping_id
        let nat_res = NatPingResponse { id: random_u64() };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &bob_pk, nat_payload.clone()));
        let mut client = create_client(&alice, bob_pk);
        client.ping_id = nat_res.id+1;
        add_to_peers_cache(&alice, bob_pk, &client);
        assert!(alice.handle_packet((dht_req, addr)).wait().is_err());
        // error case, ping_id = 0
        let nat_res = NatPingResponse { id: 0 };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &bob_pk, nat_payload.clone()));
        let mut client = create_client(&alice, bob_pk);
        client.ping_id = 0;
        add_to_peers_cache(&alice, bob_pk, &client);
        assert!(alice.handle_packet((dht_req, addr)).wait().is_err());
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

        let (packet, _rx) = rx.into_future().wait().unwrap();

        let (next, addr_to_send) = match packet {
            Some((DhtPacket::OnionResponse2(next), addr_to_send)) => (next, addr_to_send),
            p => panic!("Expected OnionResponse2 but got {:?}", p)
        };

        assert_eq!(addr_to_send, ip_port.to_saddr());
        assert_eq!(next.payload, payload);
        assert_eq!(next.onion_return, next_onion_return);
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
            payload: payload.clone()
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_err());
    }

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
            payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE] // not encrypted with onion_symmetric_key
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

        let (packet, _rx) = rx.into_future().wait().unwrap();

        let (next, addr_to_send) = match packet {
            Some((DhtPacket::OnionResponse1(next), addr_to_send)) => (next, addr_to_send),
            p => panic!("Expected OnionResponse1 but got {:?}", p)
        };

        assert_eq!(addr_to_send, ip_port.to_saddr());
        assert_eq!(next.payload, payload);
        assert_eq!(next.onion_return, next_onion_return);
    }

    #[test]
    fn server_handle_onion_response_2_invalid_onion_return_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
        };
        let payload = InnerOnionResponse::AnnounceResponse(AnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42, 123]
        });
        let packet = DhtPacket::OnionResponse2(OnionResponse2 {
            onion_return,
            payload: payload.clone()
        });

        assert!(alice.handle_packet((packet, addr)).wait().is_err());
    }

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

        let (packet, _rx) = rx.into_future().wait().unwrap();

        let (next, addr_to_send) = match packet {
            Some((DhtPacket::AnnounceResponse(next), addr_to_send)) => (next, addr_to_send),
            p => panic!("Expected AnnounceResponse but got {:?}", p)
        };

        assert_eq!(addr_to_send, ip_port.to_saddr());
        assert_eq!(next, inner);
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

        let (packet, _rx) = rx.into_future().wait().unwrap();

        let (next, addr_to_send) = match packet {
            Some((DhtPacket::OnionDataResponse(next), addr_to_send)) => (next, addr_to_send),
            p => panic!("Expected OnionDataResponse but got {:?}", p)
        };

        assert_eq!(addr_to_send, ip_port.to_saddr());
        assert_eq!(next, inner);
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
            payload: payload.clone()
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

        let state = alice.state.read();
        rx.take(2).map(|received| {
            let (packet, addr) = received;
            let mut buf = [0; 512];
            let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
            let (_, ping_req) = PingRequest::from_bytes(&buf[..size]).unwrap();
            if addr == SocketAddr::V4("127.0.0.1:33445".parse().unwrap()) {
                let client = state.peers_cache.get(&bob_pk).unwrap();
                let ping_req_payload = ping_req.get_payload(&bob_sk).unwrap();
                assert_eq!(ping_req_payload.id, client.ping_id);
            } else {
                let client = state.peers_cache.get(&ping_pk).unwrap();
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

        let state = alice.state.read();
        let client = state.peers_cache.get(&bob_pk).unwrap();
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

        let state = alice.state.read();
        let client = state.peers_cache.get(&alice.pk).unwrap();
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
        alice.handle_lan_discovery(lan, addr).wait().unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        debug!("received packet {:?}", received.clone().unwrap().0);
        let (packet, _addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, nodes_req) = NodesRequest::from_bytes(&buf[..size]).unwrap();
        let _nodes_req_payload = nodes_req.get_payload(&bob_sk).unwrap();
        assert_eq!(nodes_req.pk, alice.pk);
    }
    #[test]
    fn server_send_lan_discovery_ipv4_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, mut rx, _addr) = create_node();
        alice.send_lan_discovery_ipv6().wait().unwrap();

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
            debug!("received packet {:?}", received.clone().unwrap().1);
            let (packet, _addr) = received.unwrap();
            let mut buf = [0; 512];
            let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
            let (_, lan_discovery) = LanDiscovery::from_bytes(&buf[..size]).unwrap();
            assert_eq!(lan_discovery.pk, alice.pk);
            rx = rx1;
        }
    }
    #[test]
    fn server_send_lan_discovery_ipv6_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, mut rx, _addr) = create_node();
        alice.send_lan_discovery_ipv6().wait().unwrap();

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
            debug!("received packet {:?}", received.clone().unwrap().1);
            let (packet, _addr) = received.unwrap();
            let mut buf = [0; 512];
            let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
            let (_, lan_discovery) = LanDiscovery::from_bytes(&buf[..size]).unwrap();
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
        assert!(state.peers_cache.get(&bob_pk).is_none());
        // peer should be removed from kbucket
        let state = alice.state.read();
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
        assert!(!state.peers_cache.get(&bob_pk).is_none());
        // peer should be remained in kbucket
        let state = alice.state.read();
        assert!(state.kbucket.contains(&bob_pk));
    }
}
