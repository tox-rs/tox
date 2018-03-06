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
This module works as a coordinator of other modules.
*/

use futures::sync::mpsc;
use futures::future;
use tokio_io::IoFuture;

use std::io::{ErrorKind, Error};
use std::net::SocketAddr;
use std::collections::HashMap;

use toxcore::crypto_core::*;
use toxcore::dht::packet::*;
use toxcore::dht::packed_node::*;
use toxcore::dht::kbucket::*;
use toxcore::dht::client::*;
use toxcore::dht::codec::*;

/// Type representing Dht UDP packets.
//pub type DhtUdpPacket = (SocketAddr, DhtPacket);
/// Shorthand for the transmit half of the message channel.
type Tx = mpsc::UnboundedSender<DhtUdpPacket>;

/**
Own DHT node data.

Contains:

- DHT public key
- DHT secret key
- Close List ([`Kbucket`] with nodes close to own DHT public key)
- ping timeout lists ([`TimeoutQueue`])

# Adding node to Close List

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
    /// Close List (contains nodes close to own DHT PK)
    pub kbucket: Kbucket,
    /// tx split of channel to send packet to this peer via udp socket
    pub tx: Tx,
    /// store client object which has send request to peer
    pub peers_cache: HashMap<PublicKey, Client>,
}

impl Server {
    /**
    Create new `Server` instance.

    Note: a new instance generates new DHT public and secret keys.

    DHT `PublicKey` and `SecretKey` are supposed to be ephemeral.
    */
    pub fn new(tx: Tx, pk: PublicKey, sk: SecretKey) -> Server {
        let kbucket = Kbucket::new(KBUCKET_BUCKETS, &pk);

        debug!("Created new Server instance");
        Server {
            sk: sk,
            pk: pk,
            kbucket: kbucket,
            tx: tx,
            peers_cache: HashMap::new(),
        }
    }

    /// create new client
    pub fn create_client(&mut self, addr: &SocketAddr, pk: PublicKey) -> Client {
        let precomputed_key = encrypt_precompute(&pk, &self.sk);
        Client::new(precomputed_key, pk, addr.clone(), self.tx.clone())
    }
    /// get client from cache
    pub fn get_client(&self, pk: &PublicKey) -> Option<Client> {
        // Client entry is inserted before sending *Request.
        if let Some(client) = self.peers_cache.get(pk) {
            Some(client.clone())
        }
        else {
            None
        }
    }
    /**
    Function to handle incoming packets. If there is a response packet,
    send back it to the peer.
    */
    pub fn handle_packet(&mut self, (addr, packet): DhtUdpPacket) -> IoFuture<()>
    {
        match packet {
            DhtPacket::PingRequest(packet) => {
                debug!("Received ping request");
                let client = self.create_client(&addr, packet.pk);
                self.handle_ping_req(client, packet)
            },
            DhtPacket::PingResponse(packet) => {
                debug!("Received ping response");
                let client = self.create_client(&addr, packet.pk);
                self.handle_ping_resp(client, packet)
            },
            DhtPacket::NodesRequest(packet) => {
                debug!("Received NodesRequest");
                let client = self.create_client(&addr, packet.pk);
                self.handle_nodes_req(client, packet)
            },
            DhtPacket::NodesResponse(packet) => {
                debug!("Received NodesResponse");
                let client = self.create_client(&addr, packet.pk);
                self.handle_nodes_resp(client, packet)
            },
            DhtPacket::DhtRequest(dr) => {
                // The packet kind of DhtRequest is in encrypted payload,
                // so decrypting is needed first.
                let payload = dr.get_payload(&self.sk)
                    .map(|p| p)
                    .map_err(|e| {
                        // error!("deserialize DhtRequest payload fail {:?}", e);
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
                        let client = self.create_client(&addr, dr.spk);
                        self.handle_nat_ping_resp(client, dr, pl)
                    },
                    _p => {
                        // error!("received packet are not handled {:?}", p);
                        Box::new( future::err(
                            Error::new(ErrorKind::Other,
                                "received packet are not handled"
                        )))
                    },
                }
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
    fn handle_ping_req(&mut self, client: Client, request: PingRequest) -> IoFuture<()>
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
    fn handle_ping_resp(&mut self, client: Client, request: PingResponse) -> IoFuture<()>
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
                    saddr: client.addr.clone(),
                    pk: request.pk.clone(),
                };
                self.kbucket.try_add(&packed_node);
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
    fn handle_nodes_req(&mut self, client: Client, request: NodesRequest) -> IoFuture<()> {
        if let Ok(payload) = request.get_payload(&self.sk) {
            let close_nodes = self.kbucket.get_closest(&self.pk);
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
    fn handle_nodes_resp(&mut self, client: Client, request: NodesResponse) -> IoFuture<()> {
        if let Ok(payload) = request.get_payload(&self.sk) {
            if payload.id == 0 {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "NodesResponse.ping_id == 0"
                )))
            }
            if client.ping_id == payload.id {
                for node in &payload.nodes {
                    self.kbucket.try_add(node);
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
    pub fn handle_nat_ping_req(&mut self, client: Client, request: DhtRequest, payload: NatPingRequest) -> IoFuture<()> {
        if request.rpk == self.pk { // the target peer is me
            let resp_payload = NatPingResponse {
                id: payload.id,
            };
            client.send_nat_ping_response(&request.spk, resp_payload)
        } else { // search kbucket to find target peer
            if let Some(addr) = self.kbucket.get_node(&request.rpk) {
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
    pub fn handle_nat_ping_resp(&mut self, client: Client, request: DhtRequest, payload: NatPingResponse) -> IoFuture<()> {
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
        } else { // search kbucket to find target peer
            if let Some(addr) = self.kbucket.get_node(&request.rpk) {
                client.send_nat_ping_packet(&addr, request.clone())
            }
            else { // do nothing
                Box::new( future::ok(()) )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::*;

    use quickcheck::TestResult;
    use std::net::SocketAddr;

    fn create_node() -> (Server, PrecomputedKey, PublicKey,
            mpsc::UnboundedReceiver<DhtUdpPacket>, SocketAddr) {
        if !crypto_init() {
            error!("Crypto initialization failed.");
            assert!(false);
        }

        let (pk, sk) = gen_keypair();
        let (tx, rx) = mpsc::unbounded::<DhtUdpPacket>();
        let alice = Server::new(tx, pk, sk);
        let (bob_pk, bob_sk) = gen_keypair();
        let precomp = precompute(&alice.pk, &bob_sk);

        let addr: SocketAddr = "127.0.0.1:12346".parse().unwrap();
        (alice, precomp, bob_pk, rx, addr)
    }
    // new()
    #[test]
    fn server_new_test() {
        if !crypto_init() {
            error!("Crypto initialization failed.");
            assert!(false);
        }

        let (pk, sk) = gen_keypair();
        let tx: Tx = mpsc::unbounded().0;
        let _ = Server::new(tx, pk, sk);
    }
    // create_client()
    quickcheck! {
        fn server_create_client_test(packet: PingRequest) -> TestResult {
            if !crypto_init() {
                error!("Crypto initialization failed.");
                assert!(false);
            }

            let (pk, sk) = gen_keypair();
            let(tx, _) = mpsc::unbounded();
            let mut alice = Server::new(tx, pk, sk);
            let addr1: SocketAddr = "127.0.0.1:12345".parse().unwrap();
            let client1 = alice.create_client(&addr1.clone(), packet.pk.clone());
            // try one more time
            let client2 = alice.create_client(&addr1, packet.pk.clone());
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
        let (mut alice, _precomp, bob_pk, _rx, addr) = create_node();
        let client = alice.create_client(&addr, bob_pk);
        alice.peers_cache.insert(bob_pk, client.clone());
        assert_eq!(client.pk, alice.get_client(&bob_pk).unwrap().pk);
    }
    // handle_packet()
    quickcheck! {
        fn server_handle_packet_test(prq: PingRequestPayload) -> TestResult
                                    // prs: PingResponsePayload,
                                    // nrq: NodesRequestPayload,
                                    // nrs: NodesResponsePayload,
                                    // nat_req: NatPingRequest,
                                    // nat_res: NatPingResponse) -> TestResult
        {
            let (mut alice, precomp, bob_pk, rx, addr) = create_node();
            // handle ping request, request from bob peer
            let ping_req = DhtPacket::PingRequest(PingRequest::new(&precomp, &bob_pk, prq));
            alice.handle_packet((addr, ping_req)).wait().unwrap();
            if let (Some((_addr, packet)), _rx) = rx.into_future().wait().unwrap() {
                debug!("received packet {:?}", packet);
                if let DhtPacket::PingResponse(packet) = packet {
                    let ping_resp_payload = packet.get_payload(&alice.sk).unwrap();
                    assert_eq!(ping_resp_payload.id, prq.id);
                } else {
                    unreachable!("can not occur");
                }
            } else {
                unreachable!("can not occur");
            }

            // handle ping response
            // let ping_res = DhtPacket::PingResponse(PingResponse::new(&precomp, &bob_pk, prs));
            // alice.kbucket = Kbucket::new(KBUCKET_BUCKETS, &alice.pk);
            // let mut client = alice.create_client(&addr, bob_pk);
            // client.ping_id = prs.id;
            // alice.peers_cache.insert(bob_pk.clone(), client);
            // alice.handle_packet((addr, ping_res)).wait().unwrap();
            // assert!(alice.kbucket.contains(&bob_pk));

            // handle nodes request from bob
            // let (tx, rx) = mpsc::unbounded::<DhtUdpPacket>();
            // let node_pk = gen_keypair().0;
            // let packed_node = PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &node_pk);
            // alice.kbucket.try_add(&packed_node);
            // let nodes_req = DhtPacket::NodesRequest(NodesRequest::new(&precomp, &bob_pk, nrq));
            // alice.handle_packet((addr, nodes_req)).wait().unwrap();
            // let rx =
            // if let (Some((_addr, packet)), rx1) = rx.into_future().wait().unwrap() {
            //     debug!("received packet {:?}", packet);
            //     if let DhtPacket::NodesResponse(packet) = packet {
            //         let nodes_resp_payload = packet.get_payload(&alice.sk).unwrap();
            //         assert_eq!(nodes_resp_payload.id, nrq.id);
            //         rx1
            //     } else {
            //         unreachable!("can not occur");
            //     }
            // } else {
            //     unreachable!("can not occur");
            // };

            // handle nodes response
            // let nodes_res = DhtPacket::NodesResponse(NodesResponse::new(&precomp, &bob_pk, nrs.clone()));
            // let mut client = alice.create_client(&addr, bob_pk);
            // client.ping_id = nrs.id;
            // alice.peers_cache.insert(bob_pk.clone(), client);
            // alice.kbucket = Kbucket::new(KBUCKET_BUCKETS, &alice.pk);
            // let mut kbuc = Kbucket::new(KBUCKET_BUCKETS, &alice.pk);
            // for pn in &nrs.nodes {
            //     kbuc.try_add(pn);
            // }
            // alice.handle_packet((addr, nodes_res)).wait().unwrap();
            // assert_eq!(alice.kbucket, kbuc);

            // handle nat ping request
            // let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
            // let nat_ping_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &bob_pk, nat_payload.clone()));
            // alice.handle_packet((addr, nat_ping_req)).wait().unwrap();
            // if let (Some((_addr, packet)), _rx1) = rx.into_future().wait().unwrap() {
            //     debug!("received packet {:?}", packet);
            //     if let DhtPacket::DhtRequest(packet) = packet {
            //         if let DhtRequestPayload::NatPingResponse(nat_ping_resp_payload) = packet.get_payload(&alice.sk).unwrap() {
            //             assert_eq!(nat_ping_resp_payload.id, nat_req.id);
            //         } else {
            //             unreachable!("can not occur");
            //         }
            //     } else {
            //         unreachable!("can not occur");
            //     }
            // } else {
            //     unreachable!("can not occur");
            // }

            // let nat_ping_req = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &alice.pk, nat_payload));
            // assert!(!alice.handle_packet((addr, nat_ping_req)).wait().is_ok());

            // handle nat ping response
            // let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
            // let nat_ping_res = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &bob_pk, nat_payload.clone()));
            // let mut client = alice.create_client(&addr, bob_pk);
            // client.ping_id = nat_res.id;
            // alice.peers_cache.insert(bob_pk.clone(), client);
            // assert!(alice.handle_packet((addr, nat_ping_res)).wait().is_ok());

            // let nat_ping_res = DhtPacket::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &alice.pk, nat_payload));
            // assert!(!alice.handle_packet((addr, nat_ping_res)).wait().is_ok());

            TestResult::passed()
        }
    }

    // handle_ping_req()
    #[test]
    fn server_handle_ping_req_test() {
        let (mut alice, precomp, bob_pk, rx, addr) = create_node();
        // handle ping request, request from bob peer
        let prq = PingRequestPayload { id: random_u64() };
        let ping_req = PingRequest::new(&precomp, &bob_pk, prq);
        let client = alice.create_client(&addr, bob_pk);
        alice.handle_ping_req(client, ping_req).wait().unwrap();
        if let (Some((_addr, packet)), _rx1) = rx.into_future().wait().unwrap() {
            debug!("received packet {:?}", packet);
            if let DhtPacket::PingResponse(packet) = packet {
                let ping_resp_payload = packet.get_payload(&alice.sk).unwrap();
                assert_eq!(ping_resp_payload.id, prq.id);
            } else {
                unreachable!("can not occur");
            }
        } else {
            unreachable!("can not occur");
        }
        let prq = PingRequestPayload { id: random_u64() };
        let ping_req = PingRequest::new(&precomp, &alice.pk, prq);
        let pk = alice.pk.clone();
        let client = alice.create_client(&addr, pk);
        assert!(!alice.handle_ping_req(client, ping_req).wait().is_ok());
    }

    // handle_ping_resp()
    #[test]
    fn server_handle_ping_resp_test() {
        let (mut alice, precomp, bob_pk, _rx, addr) = create_node();
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
        assert!(!alice.handle_ping_resp(client, ping_resp).wait().is_ok());

        let prs = PingResponsePayload { id: random_u64() };
        let ping_resp = PingResponse::new(&precomp, &bob_pk, prs);
        let mut client = alice.create_client(&addr, bob_pk);
        client.ping_id = 0;
        assert!(!alice.handle_ping_resp(client.clone(), ping_resp.clone()).wait().is_ok());
        client.ping_id = prs.id + 1;
        assert!(!alice.handle_ping_resp(client, ping_resp).wait().is_ok());
    }

    // handle_nodes_req()
    #[test]
    fn server_handle_nodes_req_test() {
        let (mut alice, precomp, bob_pk, rx, addr) = create_node();
        // handle nodes request, request from bob peer
        let node_pk = gen_keypair().0;
        let packed_node = PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &node_pk);
        alice.kbucket.try_add(&packed_node);
        let nrq = NodesRequestPayload { pk: node_pk, id: random_u64() };
        let nodes_req = NodesRequest::new(&precomp, &bob_pk, nrq.clone());
        let client = alice.create_client(&addr, bob_pk);
        alice.handle_nodes_req(client, nodes_req).wait().unwrap();
        if let (Some((_addr, packet)), _rx1) = rx.into_future().wait().unwrap() {
            debug!("received packet {:?}", packet);
            if let DhtPacket::NodesResponse(packet) = packet {
                let nodes_resp_payload = packet.get_payload(&alice.sk).unwrap();
                assert_eq!(nodes_resp_payload.id, nrq.id);
            } else {
                unreachable!("can not occur")
            }
        } else {
            unreachable!("can not occur");
        }
        let nodes_req = NodesRequest::new(&precomp, &alice.pk, nrq);
        let pk = alice.pk.clone();
        let client = alice.create_client(&addr, pk);
        assert!(!alice.handle_nodes_req(client, nodes_req).wait().is_ok());
    }

    // handle_nodes_resp()
    #[test]
    fn server_handle_nodes_resp_test() {
        let (mut alice, precomp, bob_pk, _rx, addr) = create_node();
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
        assert_eq!(alice.kbucket, kbuc);

        let nodes_resp = NodesResponse::new(&precomp, &alice.pk, nrs.clone());
        let pk = alice.pk.clone();
        let mut client = alice.create_client(&addr, pk);
        client.ping_id = 38;
        assert!(!alice.handle_nodes_resp(client, nodes_resp).wait().is_ok());

        let nodes_resp = NodesResponse::new(&precomp, &bob_pk, nrs.clone());
        let mut client = alice.create_client(&addr, bob_pk);
        client.ping_id = 0;
        assert!(!alice.handle_nodes_resp(client.clone(), nodes_resp.clone()).wait().is_ok());
        client.ping_id = 38 + 1;
        assert!(!alice.handle_nodes_resp(client, nodes_resp).wait().is_ok());
    }

    // handle nat ping request
    #[test]
    fn server_handle_nat_ping_req_test() {
        let (mut alice, precomp, bob_pk, rx, addr) = create_node();
        let nat_req = NatPingRequest { id: random_u64() };
        let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
        let dht_req = DhtRequest::new(&precomp, &alice.pk, &bob_pk, nat_payload.clone());
        let client = alice.create_client(&addr.clone(), bob_pk);
        alice.handle_nat_ping_req(client, dht_req, nat_req).wait().unwrap();
        if let (Some((_addr, packet)), _rx1) = rx.into_future().wait().unwrap() {
            debug!("received packet {:?}", packet);
            if let DhtPacket::DhtRequest(packet) = packet {
                if let DhtRequestPayload::NatPingResponse(nat_ping_resp_payload) = packet.get_payload(&alice.sk).unwrap() {
                    assert_eq!(nat_ping_resp_payload.id, nat_req.id);
                } else {
                    unreachable!("can not occur");
                }
            } else {
                unreachable!("can not occur");
            }
        } else {
            unreachable!("can not occur");
        }

        let dht_req = DhtRequest::new(&precomp, &alice.pk, &alice.pk, nat_payload.clone());
        let pk = alice.pk.clone();
        let client = alice.create_client(&addr, pk);
        assert!(!alice.handle_nat_ping_req(client, dht_req, nat_req).wait().is_ok());
    }

    // handle nat ping response
    #[test]
    fn server_handle_nat_ping_resp_test() {
        let (mut alice, precomp, bob_pk, _rx, addr) = create_node();
        let nat_res = NatPingResponse { id: random_u64() };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtRequest::new(&precomp, &alice.pk, &bob_pk, nat_payload.clone());
        let mut client = alice.create_client(&addr.clone(), bob_pk);
        client.ping_id = nat_res.id;
        assert!(alice.handle_nat_ping_resp(client.clone(), dht_req.clone(), nat_res.clone()).wait().is_ok());
        client.ping_id = nat_res.id + 1;
        assert!(!alice.handle_nat_ping_resp(client.clone(), dht_req.clone(), nat_res.clone()).wait().is_ok());
        client.ping_id = 0;
        assert!(!alice.handle_nat_ping_resp(client, dht_req, nat_res).wait().is_ok());
    }
}
