/*
    Copyright © 2017 Zetok Zalbavar <zetok@openmailbox.org>

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


//! Functionality needed to work as a DHT node.
//!
//! Made on top of `dht` and `network` modules.


use futures::*;
use futures::sink;
use tokio_core::net::{UdpCodec, UdpFramed};
use tokio_proto::multiplex::RequestId;

use std::io::{self, ErrorKind};
use std::net::SocketAddr;

use toxcore::binary_io::{FromBytes, ToBytes};
use toxcore::crypto_core::*;
use toxcore::dht::*;


/**
Own DHT node data.

Contains:

- DHT public key
- DHT secret key
- `Kbucket` with nodes close to own DHT public key
- sent `PingReq` IDs
*/
pub struct DhtNode {
    dht_secret_key: Box<SecretKey>,
    dht_public_key: Box<PublicKey>,
    /// contains nodes close to own DHT PK
    kbucket: Box<Kbucket>,
    /// track sent ping requests
    ping_req: Box<Vec<RequestId>>,


    // TODO: track sent GetNodes request IDs?
    // TODO: have a table with precomputed keys for all known NetNodes?
}


impl DhtNode {
    /** Create new `DhtNode` instance.

    Note: a new instance generates new DHT public and secret keys.

    DHT PublicKey and SecretKey are supposed to be ephemeral.
    */
    pub fn new() -> io::Result<Self> {
        if !crypto_init() {
            return Err(io::Error::new(ErrorKind::Other,
                       "Crypto initialization failed."));
        }

        let (pk, sk) = gen_keypair();
        let kbucket = Kbucket::new(KBUCKET_BUCKETS, &pk);

        debug!("Created new DhtNode instance");

        Ok(DhtNode {
            dht_secret_key: Box::new(sk),
            dht_public_key: Box::new(pk),
            kbucket: Box::new(kbucket),
            ping_req: Box::new(Vec::new()),
        })
    }


    /** Try to add nodes to [Kbucket](../dht/struct.Kbucket.html).

    Wrapper around Kbucket's method.
    */
    pub fn try_add(&mut self, node: &PackedNode) -> bool {
        self.kbucket.try_add(node)
    }

    /**
    Create a [`DhtPacket`](../dht/struct.DhtPacket.html) to peer with `peer_pk`
    `PublicKey` containing a [`GetNodes`](../dht/struct.GetNodes.html) request
    for nodes close to own DHT `PublicKey`.
    */
    fn create_getn(&self, peer_pk: &PublicKey) -> DhtPacket {
        // request for nodes that are close to our own DHT PK
        let getn_req = &GetNodes::new(&self.dht_public_key);
        let shared_secret = &encrypt_precompute(peer_pk, &self.dht_secret_key);
        let nonce = &gen_nonce();
        DhtPacket::new(shared_secret,
                       &self.dht_public_key,
                       nonce,
                       getn_req)
    }

    /**
    Request nodes from a peer. Peer might or might not even reply.

    Creates a future for sending request for nodes. Upon future completion

    */
    // TODO: track requests ?
    pub fn request_nodes(&self,
                         sink: UdpFramed<ToxCodec>,
                         peer: &PackedNode)
        -> sink::Send<UdpFramed<ToxCodec>>
    {
        let request = self.create_getn(peer.pk());
        sink.send((peer.socket_addr(), request))
    }

    /**
    Create a [`DhtPacket`](../dht/struct.DhtPacket.html) to peer with `peer_pk`
    `PublicKey` containing [`SendNodes`](../dht/struct.SendNodes.html)
    response.

    Returns `None` if own `Kbucket` is empty.
    */
    fn create_sendn(&self, peer_pk: &PublicKey, request: &GetNodes)
        -> Option<DhtPacket>
    {
        let sendn = match request.response(&*self.kbucket) {
            Some(s) => s,
            None => return None,
        };
        let shared_secret = &encrypt_precompute(peer_pk, &self.dht_secret_key);
        let nonce = &gen_nonce();
        Some(DhtPacket::new(shared_secret,
                            &self.dht_public_key,
                            nonce,
                            &sendn))
    }

    /**
    Send nodes close to requested PK.

    Can fail (return `None`) if Kbucket is empty.
    */
    pub fn send_nodes(&self,
                      sink: UdpFramed<ToxCodec>,
                      peer: &PackedNode,
                      request: &GetNodes)
        -> Option<sink::Send<UdpFramed<ToxCodec>>>
    {
        self.create_sendn(peer.pk(), request)
            .map(|sn| sink.send((peer.socket_addr(), sn)))
    }
}

/// Struct to use for {de-,}serializing Tox UDP packets.
// TODO: move elsewhere(?)
// TODO: rename? or implement UdpCodec for something else (enum)
pub struct ToxCodec;

impl UdpCodec for ToxCodec {
    // TODO: make `In`/`Out` support more than just DhtPacket
    //       (by using enum or Trait: FromBytes + ToBytes ?)
    type In = (SocketAddr, DhtPacket);
    type Out = (SocketAddr, DhtPacket);

    fn decode(&mut self, src: &SocketAddr, buf: &[u8]) -> io::Result<Self::In> {
        match DhtPacket::from_bytes(buf) {
            Some(k) => Ok((*src, k)),
            None => Err(io::Error::new(ErrorKind::InvalidData,
                "not a supported Tox DHT packet")),
        }
    }

    fn encode(&mut self, (addr, dp): Self::Out, into: &mut Vec<u8>) -> SocketAddr {
        into.extend(dp.to_bytes());
        addr
    }
}




#[cfg(test)]
mod test {
    use futures::future::*;
    use tokio_core::reactor::{Core, Timeout};
    use tokio_core::net::UdpCodec;

    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::time::Duration;

    use toxcore::binary_io::*;
    use toxcore::crypto_core::*;
    use toxcore::dht::*;
    use toxcore::network::*;
    use toxcore::dht_node::DhtNode;
    use toxcore::dht_node::ToxCodec;
    use toxcore::packet_kind::PacketKind;

    use quickcheck::{quickcheck, TestResult};

    /// Bind to this IpAddr.
    // NOTE: apparently using `0.0.0.0`/`::` is not allowed on CIs like
    //       appveyor / travis
    const SOCKET_ADDR: &'static str = "127.0.0.1";

    /// Provide:
    ///   - mut core ($c)
    ///   - handle ($h)
    ///   - mut DhtNode $name
    ///   - socket $name_socket
    macro_rules! node_socket {
        ($c:ident, $h:ident, $($name:ident, $name_socket:ident),+) => (
            let mut $c = Core::new().unwrap();
            let $h = $c.handle();
            $(
                #[allow(unused_mut)]
                // `allow` doesn't work here, regardless of whether it's
                // located above the statement, macro, or the test fn :/
                // lets hope that one day compiler will make things work
                let mut $name = DhtNode::new().unwrap();
                let $name_socket = bind_udp(SOCKET_ADDR.parse().unwrap(),
                                            // make port range sufficiently big
                                            2048..65000,
                                            &$h)
                    .expect("failed to bind to socket");
            )+
        )
    }

    /// Add timeout to the future, and panic upon timing out.
    ///
    /// If not specified, default timeout = 5s.
    macro_rules! add_timeout {
        ($f:expr, $handle:expr) => (
            add_timeout!($f, $handle, 5)
        );

        ($f:expr, $handle:expr, $seconds:expr) => (
            $f.map(Ok)
              .select(
                Timeout::new(Duration::from_secs($seconds), $handle)
                    .unwrap()
                    .map(Err))
              .then(|res| {
                  match res {
                      Ok((Err(()), _received)) =>
                              panic!("timed out"),
                      Err((e, _other)) => panic!("{}", e),
                      Ok((f, _timeout)) => f,
                  }
              })
        );
    }


    #[test]
    fn dht_node_new() {
        let _ = DhtNode::new().unwrap();
    }

    #[test]
    fn dht_node_try_add_to_empty() {
        fn with_nodes(pns: Vec<PackedNode>) {
            let mut dhtn = DhtNode::new().unwrap();
            let mut kbuc = Kbucket::new(KBUCKET_BUCKETS, &dhtn.dht_public_key);

            for pn in &pns {
                assert_eq!(dhtn.try_add(pn), kbuc.try_add(pn));
                assert_eq!(kbuc, *dhtn.kbucket);
            }
        }
        quickcheck(with_nodes as fn(Vec<PackedNode>));
    }

    #[test]
    fn dht_node_create_getn_test() {
        let node = DhtNode::new().unwrap();
        let (peer_pk, peer_sk) = gen_keypair();
        let packet1 = node.create_getn(&peer_pk);
        assert_eq!(*node.dht_public_key, packet1.sender_pk);
        assert_eq!(PacketKind::GetN, packet1.kind());

        let payload1: GetNodes = packet1.get_packet(&peer_sk)
            .expect("failed to get payload1");
        assert_eq!(*node.dht_public_key, payload1.pk);

        let packet2 = node.create_getn(&peer_pk);
        assert_ne!(packet1, packet2);

        let payload2: GetNodes = packet2.get_packet(&peer_sk)
            .expect("failed to get payload2");
        assert_ne!(payload1.id, payload2.id);
    }

    #[test]
    fn dht_node_create_sendn_test() {
        fn with_pns(pns: Vec<PackedNode>) -> TestResult {
            if pns.is_empty() { return TestResult::discard() }

            let node1 = DhtNode::new().unwrap();
            let mut node2 = DhtNode::new().unwrap();
            let req = node1.create_getn(&node2.dht_public_key);

            let req_payload: GetNodes = req.get_packet(&node2.dht_secret_key)
                .expect("failed to get req_payload");

            // errors with an empty kbucket
            let error = node2.create_sendn(&node1.dht_public_key, &req_payload);
            assert_eq!(None, error);

            for pn in &pns {
                drop(node2.try_add(pn));
            }

            let resp1 = node2.create_sendn(&node1.dht_public_key, &req_payload)
                .expect("failed to create response1");
            let resp2 = node2.create_sendn(&node1.dht_public_key, &req_payload)
                .expect("failed to create response2");

            assert_eq!(resp1.sender_pk, *node2.dht_public_key);
            assert_eq!(PacketKind::SendN, resp1.kind());
            // encrypted payload differs due to different nonce
            assert_ne!(resp1, resp2);

            let resp1_payload: SendNodes = resp1
                .get_packet(&node1.dht_secret_key)
                .expect("failed to get payload1");
            let resp2_payload: SendNodes = resp2
                .get_packet(&node1.dht_secret_key)
                .expect("failed to get payload2");
            assert_eq!(resp1_payload, resp2_payload);
            assert!(!resp1_payload.nodes.is_empty());

            TestResult::passed()
        }
        quickcheck(with_pns as fn(Vec<PackedNode>) -> TestResult);

    }

    #[test]
    fn dht_node_request_nodes_test() {
        node_socket!(core, handle,
            server, server_socket,
            client, client_socket);

        let server_node = PackedNode::new(true,
            server_socket.local_addr().unwrap(),
            &server.dht_public_key);

        let mut recv_buf = [0; MAX_UDP_PACKET_SIZE];

        let client_framed = client_socket.framed(ToxCodec);
        let client_request = client.request_nodes(client_framed, &server_node);

        let future_recv = server_socket.recv_dgram(&mut recv_buf[..]);
        let future_recv = add_timeout!(future_recv, &handle);
        handle.spawn(client_request.then(|_| ok(())));

        let received = core.run(future_recv).unwrap();
        let (_server_socket, recv_buf, size, _saddr) = received;
        assert!(size != 0);

        let recv_packet = DhtPacket::from_bytes(&recv_buf[..size]).unwrap();
        let payload: GetNodes = recv_packet
            .get_packet(&server.dht_secret_key)
            .expect("Failed to decrypt payload");

        assert_eq!(payload.pk, *client.dht_public_key);
    }

    #[test]
    fn dht_node_send_nodes() {
        fn with_nodes(pns: Vec<PackedNode>, gn: GetNodes) -> TestResult {
            if pns.is_empty() { return TestResult::discard() }

            node_socket!(core, handle,
                server, server_socket,
                client, client_socket);

            let client_node = PackedNode::new(true,
                client_socket.local_addr()
                    .expect("failed to get saddr"),
                &client.dht_public_key);

            for pn in &pns {
                drop(server.try_add(pn));
            }

            let server_framed = server_socket.framed(ToxCodec);
            let server_response = server.send_nodes(
                server_framed,
                &client_node,
                &gn);

            let mut recv_buf = [0; MAX_UDP_PACKET_SIZE];
            let future_recv = client_socket.recv_dgram(&mut recv_buf[..]);
            let future_recv = add_timeout!(future_recv, &handle);
            handle.spawn(server_response.then(|_| ok(())));

            let received = core.run(future_recv).unwrap();
            let (_client_socket, recv_buf, size, _saddr) = received;
            assert!(size != 0);

            let _recv_packet = DhtPacket::from_bytes(&recv_buf[..size])
                .expect("failed to parse as DhtPacket");

            TestResult::passed()
        }
        quickcheck(with_nodes as fn(Vec<PackedNode>, GetNodes) -> TestResult);
    }


    // ToxCodec::

    // ToxCodec::decode()

    #[test]
    fn tox_codec_decode_test() {
        fn with_dp(dp: DhtPacket, kind: u8) -> TestResult {
            // need an invalid PacketKind for DhtPacket
            if kind <= PacketKind::SendN as u8 {
                return TestResult::discard()
            }

            // TODO: random SocketAddr
            let addr = SocketAddr::V4("0.1.2.3:4".parse().unwrap());
            let mut tc = ToxCodec;

            let mut bytes = dp.to_bytes();

            let (decoded_a, decoded_dp) = tc.decode(&addr, &bytes)
                .unwrap();

            assert_eq!(addr, decoded_a);
            assert_eq!(dp, decoded_dp);

            // make it error
            bytes[0] = kind;
            let error = tc.decode(&addr, &bytes).unwrap_err();
            assert_eq!(ErrorKind::InvalidData, error.kind());

            TestResult::passed()
        }
        quickcheck(with_dp as fn(DhtPacket, u8) -> TestResult);
    }

    // ToxCodec::encode()

    #[test]
    fn tox_codec_encode_test() {
        fn with_dp(dp: DhtPacket) {
            // TODO: random SocketAddr
            let addr = SocketAddr::V4("5.6.7.8:9".parse().unwrap());
            let mut buf = Vec::new();
            let mut tc = ToxCodec;

            let socket = tc.encode((addr, dp.clone()), &mut buf);
            assert_eq!(addr, socket);
            assert_eq!(buf, dp.to_bytes());
        }
        quickcheck(with_dp as fn(DhtPacket));
    }
}
