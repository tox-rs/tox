/*
    Copyright © 2017 Zetok Zalbavar <zexavexxe@gmail.com>

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
    `PublicKey` containing a [`PingReq`](../dht/struct.PingReq.html) request.
    */
    fn create_ping_req(&self, peer_pk: &PublicKey) -> DhtPacket {
        let ping = PingReq::new();
        // TODO: precompute shared key to calculate it 1 time
        let shared_secret = &encrypt_precompute(peer_pk, &self.dht_secret_key);
        let nonce = &gen_nonce();
        DhtPacket::new(shared_secret,
                       &self.dht_public_key,
                       nonce,
                       &ping)
    }

    /**
    Request ping response from a peer. Peer might or might not even reply.

    Creates a future for sending request for ping.
    */
    // TODO: track requests
    pub fn request_ping(&self,
                         sink: UdpFramed<ToxCodec>,
                         peer_addr: SocketAddr,
                         peer_pk: &PublicKey)
        -> sink::Send<UdpFramed<ToxCodec>>
    {
        let request = self.create_ping_req(peer_pk);
        sink.send((peer_addr, request))
    }

    /**
    Create a [`DhtPacket`] encapsulating [ping response] to given ping
    request.

    [`DhtPacket`]: ../dht/struct.DhtPacket.html
    [ping response]: ../dht/struct.PingResp.html
    */
    pub fn respond_ping(&self,
                        sink: UdpFramed<ToxCodec>,
                        peer_addr: SocketAddr,
                        request: &DhtPacket)
        -> Option<sink::Send<UdpFramed<ToxCodec>>>
    {
        // TODO: precompute shared key to calculate it 1 time
        let precomp = encrypt_precompute(&request.sender_pk,
                                         &self.dht_secret_key);
        request.ping_resp(&self.dht_secret_key,
                          &precomp,
                          &self.dht_public_key)
            .map(|p| sink.send((peer_addr, p)))
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

    Creates a future for sending request for nodes.
    */
    // TODO: track requests ?
    pub fn request_nodes(&self,
                         sink: UdpFramed<ToxCodec>,
                         peer_addr: SocketAddr,
                         peer_pk: &PublicKey)
        -> sink::Send<UdpFramed<ToxCodec>>
    {
        let request = self.create_getn(peer_pk);
        sink.send((peer_addr, request))
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
                      peer_addr: SocketAddr,
                      peer_pk: &PublicKey,
                      request: &GetNodes)
        -> Option<sink::Send<UdpFramed<ToxCodec>>>
    {
        self.create_sendn(peer_pk, request)
            .map(|sn| sink.send((peer_addr, sn)))
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
                // fixed on latest nightly, remove comment once minimal
                // supported rustc will no longer complain about it
                // rust bug: https://github.com/rust-lang/rust/issues/40491
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

    /**
    Verify that given `$packet` can't be parsed as packet type `$kind`
    using secret key `$sk`.
    */
    macro_rules! cant_parse_as_packet {
        ($packet:expr, $sk:expr, $($kind:ty)+) => ($(
            assert!($packet.get_packet::<$kind>(&$sk).is_none());
        )+)
    }

    // DhtNode::

    // DhtNode::new()

    #[test]
    fn dht_node_new() {
        let _ = DhtNode::new().unwrap();
    }

    // DhtNode::try_add()

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

    // DhtNode::create_ping_req()

    #[test]
    fn dht_node_create_ping_req_test() {
        let alice = DhtNode::new().unwrap();
        let (bob_pk, bob_sk) = gen_keypair();
        let (_, eve_sk) = gen_keypair();
        let packet1 = alice.create_ping_req(&bob_pk);
        assert_eq!(*alice.dht_public_key, packet1.sender_pk);
        assert_eq!(PacketKind::PingReq, packet1.kind());

        let packet2 = alice.create_ping_req(&bob_pk);
        assert_ne!(packet1, packet2);

        // eve can't decrypt it
        assert_eq!(None, packet1.get_packet::<PingReq>(&eve_sk));

        let payload1: PingReq = packet1.get_packet(&bob_sk)
            .expect("failed to get payload1");
        let payload2: PingReq = packet2.get_packet(&bob_sk)
            .expect("failed to get payload2");
        assert_ne!(payload1.id(), payload2.id());

        // wrong packet kind
        cant_parse_as_packet!(packet1, bob_sk,
            PingResp GetNodes SendNodes);
    }


    // DhtNode::request_ping()

    #[test]
    fn dht_node_request_ping_test() {
        // bob creates & sends PingReq to alice
        // received PingReq has to be succesfully decrypted
        node_socket!(core, handle,
            alice, alice_socket,
            bob, bob_socket);
        let alice_addr = alice_socket.local_addr().unwrap();

        let mut recv_buf = [0; MAX_UDP_PACKET_SIZE];

        let bob_framed = bob_socket.framed(ToxCodec);
        let bob_request = bob.request_ping(bob_framed, alice_addr,
            &alice.dht_public_key);

        let future_recv = alice_socket.recv_dgram(&mut recv_buf[..]);
        let future_recv = add_timeout!(future_recv, &handle);
        handle.spawn(bob_request.then(|_| ok(())));

        let received = core.run(future_recv).unwrap();
        let (_alice_socket, recv_buf, size, _saddr) = received;
        assert!(size != 0);

        let recv_packet = DhtPacket::from_bytes(&recv_buf[..size]).unwrap();
        let payload: PingReq = recv_packet
            .get_packet(&alice.dht_secret_key)
            .expect("Failed to decrypt payload");

        assert_eq!(PacketKind::PingReq, payload.kind());
    }

    // DhtNode::respond_ping()

    quickcheck! {
        fn dht_node_respond_ping_test(req: PingReq) -> () {
            // bob creates a DhtPacket with PingReq, and alice
            // sends a response to it
            // response has to be successfully decrypted by alice
            // response can't be decrypted by eve
            node_socket!(core, handle,
                alice, alice_socket,
                bob, bob_socket);
            let (_, eve_sk) = gen_keypair();

            let precomp = encrypt_precompute(&alice.dht_public_key,
                                             &bob.dht_secret_key);
            let nonce = gen_nonce();
            let bob_ping = DhtPacket::new(&precomp,
                                          &bob.dht_public_key,
                                          &nonce,
                                          &req);

            let alice_framed = alice_socket.framed(ToxCodec);
            let alice_send = alice.respond_ping(
                alice_framed,
                bob_socket.local_addr().unwrap(),
                &bob_ping);

            let mut recv_buf = [0; MAX_UDP_PACKET_SIZE];
            let future_recv = bob_socket.recv_dgram(&mut recv_buf[..]);
            let future_recv = add_timeout!(future_recv, &handle);
            handle.spawn(alice_send.then(|_| ok(())));

            let received = core.run(future_recv).unwrap();
            let (_bob_socket, recv_buf, size, _saddr) = received;
            assert!(size != 0);
            assert_eq!(size, bob_ping.to_bytes().len());

            let recv_packet = DhtPacket::from_bytes(&recv_buf[..size])
                .expect("failed to parse as DhtPacket");
            assert_eq!(PacketKind::PingResp, recv_packet.kind());

            // eve can't decrypt it
            assert_eq!(None, recv_packet.get_packet::<PingResp>(&eve_sk));

            let payload: PingResp = recv_packet
                .get_packet(&bob.dht_secret_key)
                .expect("Failed to decrypt payload");

            assert_eq!(PacketKind::PingResp, payload.kind());
            assert_eq!(req.id(), payload.id());

            // wrong packet kind
            cant_parse_as_packet!(recv_packet, bob.dht_secret_key,
                PingReq GetNodes SendNodes);
        }
    }

    // DhtNode::create_getn()

    #[test]
    fn dht_node_create_getn_test() {
        // alice sends GetNodes request to bob
        // bob has to successfully decrypt the request
        // eve can't decrypt the request
        let alice = DhtNode::new().unwrap();
        let (bob_pk, bob_sk) = gen_keypair();
        let (_, eve_sk) = gen_keypair();
        let packet1 = alice.create_getn(&bob_pk);
        assert_eq!(*alice.dht_public_key, packet1.sender_pk);
        assert_eq!(PacketKind::GetN, packet1.kind());

        // eve can't decrypt
        assert_eq!(None, packet1.get_packet::<GetNodes>(&eve_sk));

        let payload1: GetNodes = packet1.get_packet(&bob_sk)
            .expect("failed to get payload1");
        assert_eq!(*alice.dht_public_key, payload1.pk);

        let packet2 = alice.create_getn(&bob_pk);
        assert_ne!(packet1, packet2);

        let payload2: GetNodes = packet2.get_packet(&bob_sk)
            .expect("failed to get payload2");
        assert_ne!(payload1.id, payload2.id);

        // wrong packet kind
        cant_parse_as_packet!(packet1, bob_sk, SendNodes);
    }

    // DhtNode::request_nodes()

    #[test]
    fn dht_node_request_nodes_test() {
        // bob sends via Sink GetNodes request to alice
        // alice has to successfully decrypt & parse it
        node_socket!(core, handle,
            alice, alice_socket,
            bob, bob_socket);
        let alice_addr = alice_socket.local_addr().unwrap();

        let mut recv_buf = [0; MAX_UDP_PACKET_SIZE];

        let bob_framed = bob_socket.framed(ToxCodec);
        let bob_request = bob.request_nodes(bob_framed, alice_addr,
            &alice.dht_public_key);

        let future_recv = alice_socket.recv_dgram(&mut recv_buf[..]);
        let future_recv = add_timeout!(future_recv, &handle);
        handle.spawn(bob_request.then(|_| ok(())));

        let received = core.run(future_recv).unwrap();
        let (_alice_socket, recv_buf, size, _saddr) = received;
        assert!(size != 0);

        let recv_packet = DhtPacket::from_bytes(&recv_buf[..size]).unwrap();
        let payload: GetNodes = recv_packet
            .get_packet(&alice.dht_secret_key)
            .expect("Failed to decrypt payload");

        assert_eq!(payload.pk, *bob.dht_public_key);
    }

    // DhtNode::create_sendn()

    quickcheck! {
        fn dht_node_create_sendn_test(pns: Vec<PackedNode>) -> TestResult {
            if pns.is_empty() { return TestResult::discard() }

            // alice creates GetNodes request
            // bob has to respond to it with SendNodes
            // alice has to be able to decrypt response
            // alice has to be able to successfully add received nodes
            // eve can't decrypt response

            let mut alice = DhtNode::new().unwrap();
            let mut bob = DhtNode::new().unwrap();
            let (_, eve_sk) = gen_keypair();
            let req = alice.create_getn(&bob.dht_public_key);

            let req_payload: GetNodes = req.get_packet(&bob.dht_secret_key)
                .expect("failed to get req_payload");

            // errors with an empty kbucket
            let error = bob.create_sendn(&alice.dht_public_key, &req_payload);
            assert_eq!(None, error);

            for pn in &pns {
                bob.try_add(pn);
            }

            let resp1 = bob.create_sendn(&alice.dht_public_key, &req_payload)
                .expect("failed to create response1");
            let resp2 = bob.create_sendn(&alice.dht_public_key, &req_payload)
                .expect("failed to create response2");

            assert_eq!(resp1.sender_pk, *bob.dht_public_key);
            assert_eq!(PacketKind::SendN, resp1.kind());
            // encrypted payload differs due to different nonce
            assert_ne!(resp1, resp2);

            // eve can't decrypt
            assert_eq!(None, resp1.get_packet::<SendNodes>(&eve_sk));

            let resp1_payload: SendNodes = resp1
                .get_packet(&alice.dht_secret_key)
                .expect("failed to get payload1");
            let resp2_payload: SendNodes = resp2
                .get_packet(&alice.dht_secret_key)
                .expect("failed to get payload2");
            assert_eq!(resp1_payload, resp2_payload);
            assert!(!resp1_payload.nodes.is_empty());

            for node in &resp1_payload.nodes {
                // has to succeed, since nodes in response have to differ
                assert!(alice.try_add(node));
            }

            TestResult::passed()
        }
    }

    // DhtNode::send_nodes()

    #[test]
    quickcheck! {
        fn dht_node_send_nodes(pns: Vec<PackedNode>, gn: GetNodes)
            -> TestResult
        {
            if pns.is_empty() { return TestResult::discard() }

            // alice sends SendNodes response to random GetNodes request
            // to bob

            node_socket!(core, handle,
                alice, alice_socket,
                bob, bob_socket);

            let bob_node = PackedNode::new(true,
                bob_socket.local_addr()
                    .expect("failed to get saddr"),
                &bob.dht_public_key);

            for pn in &pns {
                drop(alice.try_add(pn));
            }

            let alice_framed = alice_socket.framed(ToxCodec);
            let alice_response = alice.send_nodes(
                alice_framed,
                bob_socket.local_addr().unwrap(),
                &bob.dht_public_key,
                &gn);

            let mut recv_buf = [0; MAX_UDP_PACKET_SIZE];
            let future_recv = bob_socket.recv_dgram(&mut recv_buf[..]);
            let future_recv = add_timeout!(future_recv, &handle);
            handle.spawn(alice_response.then(|_| ok(())));

            let received = core.run(future_recv).unwrap();
            let (_bob_socket, recv_buf, size, _saddr) = received;
            assert!(size != 0);

            let _recv_packet = DhtPacket::from_bytes(&recv_buf[..size])
                .expect("failed to parse as DhtPacket");

            TestResult::passed()
        }
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
