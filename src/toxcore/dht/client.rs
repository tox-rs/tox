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
The object of this struct is an object per a peer.
*/

use futures::{Sink, Future};
use futures::sync::mpsc;
use tokio_io::IoFuture;

//use std::collections::VecDeque;
use std::io::{ErrorKind, Error};
use std::net::SocketAddr;

use toxcore::crypto_core::*;
use toxcore::dht::packet::*;

/// Shorthand for the transmit half of the message channel.
type Tx = mpsc::UnboundedSender<(DhtPacket, SocketAddr)>;

/// peer info.
#[derive(Clone, Debug)]
pub struct Client {
    /// Public key of peer
    pub pk: PublicKey,
    /// socket address of peer
    pub addr: SocketAddr,
    /// last sent ping_id to check PingResponse is correct
    pub ping_id: u64,
    /// precomputed key for this peer
    pub precomputed_key: PrecomputedKey,
    /// shaed mpsc tx part
    pub tx: Tx,
}

impl Client {
    /// create Client object
    pub fn new(precomputed_key: PrecomputedKey, pk: PublicKey, addr: SocketAddr, tx: Tx) -> Client {
        Client {
            pk: pk,
            addr: addr,
            precomputed_key: precomputed_key,
            ping_id: 0,
            tx: tx,
        }
    }
    /// actual send method
    pub fn send_to(&self, addr: SocketAddr, packet: DhtPacket) -> IoFuture<()> {
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
    fn send(&self, packet: DhtPacket) -> IoFuture<()> {
        self.send_to(self.addr.clone(), packet)
    }
    /// respond with PingResponse to peer
    pub fn send_ping_response(&self, resp_payload: PingResponsePayload) -> IoFuture<()> {
        let ping_resp = DhtPacket::PingResponse(PingResponse::new(&self.precomputed_key.clone(), &self.pk, resp_payload));
        debug!("PingResp made {:?}", ping_resp);
        self.send(ping_resp)
    }
    /// respond with NodesResponse to peer
    pub fn send_nodes_response(&self, resp_payload: NodesResponsePayload) -> IoFuture<()> {
        let nodes_resp = DhtPacket::NodesResponse(NodesResponse::new(&self.precomputed_key.clone(), &self.pk, resp_payload));
        debug!("NodesResp made {:?}", nodes_resp);
        self.send(nodes_resp)
    }
    /// respond with NatPingResponse to peer
    pub fn send_nat_ping_response(&self, rpk: &PublicKey, resp_payload: NatPingResponse) -> IoFuture<()> {
        let payload = DhtRequestPayload::NatPingResponse(resp_payload);
        let nat_ping_resp = DhtPacket::DhtRequest(DhtRequest::new(&self.precomputed_key.clone(), rpk, &self.pk, payload));
        self.send(nat_ping_resp)
    }
    /// send NatPingRequest/NatPingResponse to target peer
    pub fn send_nat_ping_packet(&self, addr: &SocketAddr, request: DhtRequest) -> IoFuture<()> {
        let packet = DhtPacket::DhtRequest(request);
        self.send_to(*addr, packet)
    }
    /// create and send PingRequest packet
    pub fn send_ping_request(&mut self) -> IoFuture<()> {
        let payload = PingRequestPayload{ id: random_u64(), };
        self.ping_id = payload.id;
        let ping_req = DhtPacket::PingRequest(PingRequest::new(&self.precomputed_key.clone(), &self.pk, payload));
        self.send(ping_req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::*;

    use std::net::SocketAddr;
    use toxcore::dht::packed_node::*;
    use toxcore::binary_io::*;

    fn create_client() -> (Client, SecretKey, mpsc::UnboundedReceiver<(DhtPacket, SocketAddr)>) {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let (tx, rx) = mpsc::unbounded();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();
        let precomp = precompute(&alice_pk, &bob_sk);
        let client = Client::new(precomp, bob_pk, addr, tx);
        (client, alice_sk, rx)
    }
    // send()
    #[test]
    fn client_send_test() {
        let (client, _sk, rx) = create_client();
        let payload = PingRequestPayload { id: random_u64() };
        let packet = DhtPacket::PingRequest(PingRequest::new(&client.precomputed_key.clone(), &client.pk, payload));
        client.send(packet.clone()).wait().unwrap();
        let (received, rx) = rx.into_future().wait().unwrap();
        debug!("received packet {:?}", received.clone().unwrap().0);
        let (received_packet, _addr) = received.unwrap();
        assert_eq!(packet, received_packet);

        drop(rx);
        assert!(!client.send(packet).wait().is_ok());
    }
    // send_to()
    #[test]
    fn client_send_to_test() {
        let (client, _sk, rx) = create_client();
        let payload = PingRequestPayload { id: random_u64() };
        let packet = DhtPacket::PingRequest(PingRequest::new(&client.precomputed_key.clone(), &client.pk, payload));
        client.send_to(client.addr, packet.clone()).wait().unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        debug!("received packet {:?}", received.clone().unwrap().0);
        let (received_packet, _addr) = received.unwrap();
        assert_eq!(packet, received_packet);
    }
    // send_ping_response()
    #[test]
    fn client_send_ping_response_test() {
        let (client, sk, rx) = create_client();
        let payload = PingResponsePayload { id: random_u64() };
        client.send_ping_response(payload).wait().unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        debug!("received packet {:?}", received.clone().unwrap().0);
        let (packet, _addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, ping_res) = PingResponse::from_bytes(&buf[..size]).unwrap();
        let ping_resp_payload = ping_res.get_payload(&sk).unwrap();
        assert_eq!(ping_resp_payload.id, payload.id);
    }
    // send_nodes_response()
    #[test]
    fn client_send_nodes_response_test() {
        let (client, sk, rx) = create_client();
        let payload = NodesResponsePayload { nodes: vec![
            PackedNode::new(false, SocketAddr::V4("127.0.0.1:12345".parse().unwrap()), &gen_keypair().0)
        ], id: 38 };
        client.send_nodes_response(payload.clone()).wait().unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        debug!("received packet {:?}", received.clone().unwrap().1);
        let (packet, _addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, node_res) = NodesResponse::from_bytes(&buf[..size]).unwrap();
        let nodes_resp_payload = node_res.get_payload(&sk).unwrap();
        assert_eq!(nodes_resp_payload.id, payload.id);
        assert_eq!(nodes_resp_payload.nodes, payload.nodes);
    }
    // send_nat_ping_response()
    #[test]
    fn client_send_nat_ping_response_test() {
        let (client, sk, rx) = create_client();
        let payload = NatPingResponse { id: random_u64() };
        client.send_nat_ping_response(&client.pk, payload).wait().unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        debug!("received packet {:?}", received.clone().unwrap().1);
        let (packet, _addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, dht_req) = DhtRequest::from_bytes(&buf[..size]).unwrap();
        let dht_payload = dht_req.get_payload(&sk).unwrap();
        let (_, size) = dht_payload.to_bytes((&mut buf, 0)).unwrap();
        let (_, nat_ping_resp_payload) = NatPingResponse::from_bytes(&buf[..size]).unwrap();
        assert_eq!(nat_ping_resp_payload.id, payload.id);
    }
    // send_nat_ping_packet()
    #[test]
    fn client_send_nat_ping_packet_test() {
        let (client, sk, rx) = create_client();
        let nat_res = NatPingResponse { id: random_u64() };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtRequest::new(&client.precomputed_key, &client.pk, &client.pk, nat_payload.clone());
        client.send_nat_ping_packet(&client.addr, dht_req).wait().unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        debug!("received packet {:?}", received.clone().unwrap().1);
        let (packet, _addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, dht_req) = DhtRequest::from_bytes(&buf[..size]).unwrap();
        let dht_payload = dht_req.get_payload(&sk).unwrap();
        let (_, size) = dht_payload.to_bytes((&mut buf, 0)).unwrap();
        let (_, nat_ping_resp_payload) = NatPingResponse::from_bytes(&buf[..size]).unwrap();
        assert_eq!(nat_ping_resp_payload.id, nat_res.id);
    }
    // send_ping_request()
    #[test]
    fn client_send_ping_request_test() {
        let (mut client, sk, rx) = create_client();
        client.send_ping_request().wait().unwrap();
        let (received, _rx) = rx.into_future().wait().unwrap();
        debug!("received packet {:?}", received.clone().unwrap().1);
        let (packet, _addr) = received.unwrap();
        let mut buf = [0; 512];
        let (_, size) = packet.to_bytes((&mut buf, 0)).unwrap();
        let (_, ping_req) = PingRequest::from_bytes(&buf[..size]).unwrap();
        let ping_req_payload = ping_req.get_payload(&sk).unwrap();
        assert_eq!(ping_req_payload.id, client.ping_id);
    }
}
