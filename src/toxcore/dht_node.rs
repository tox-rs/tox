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


/*!
Functionality needed to work as a DHT node.

Made on top of `dht` and `network` modules.
*/
// TODO: expand doc


use futures::*;
use futures::sink;
use futures::stream::*;
use futures::sync::mpsc;
use tokio_core::net::{UdpCodec, UdpFramed};
use tokio_core::reactor::Core;
use tokio_proto::multiplex::RequestId;

use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::thread;

use toxcore::binary_io::{FromBytes, ToBytes};
use toxcore::crypto_core::*;
use toxcore::dht::*;


/// Type for sending `SplitSink` with `ToxCodec`.
// FIXME: docs
// TODO: rename
pub type ToxSplitSink = SplitSink<UdpFramed<ToxCodec>>;

/// Type for receiving `SplitStream` with `ToxCodec`.
// FIXME: docs
// TODO: rename
pub type ToxSplitStream = SplitStream<UdpFramed<ToxCodec>>;

/// Type representing future `Send` via `SplitSink`.
// FIXME: docs
// TODO: rename
pub type SendSink = sink::Send<SplitSink<UdpFramed<ToxCodec>>>;

/// Type representing recived packets.
// TODO: change DhtPacket to and enum with all possible packets
pub type ToxUdpPacket = (SocketAddr, DhtPacket);


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
    /**
    Create new `DhtNode` instance.

    Note: a new instance generates new DHT public and secret keys.

    DHT `PublicKey` and `SecretKey` are supposed to be ephemeral.
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
    Reference to own DHT `PublicKey`.
    */
    fn pk(&self) -> &PublicKey {
        &self.dht_public_key
    }

    /**
    Reference to own DHT `SecretKey`.
    */
    fn sk(&self) -> &SecretKey {
        &self.dht_secret_key
    }

    /**
    Try to add nodes from a [`DhtPacket`] that claims to contain
    [`SendNodes`] packet.

    [`DhtPacket`]: (../dht/struct.DhtPacket.html)
    [`SendNodes`]: (../dht/struct.SendNodes.html)
    */
    pub fn try_add_nodes(&mut self, packet: &DhtPacket) {
        match packet.get_packet::<SendNodes>(self.sk()) {
            Some(sn) => {
                trace!("Adding nodes from SendNodes to DhtNode's Kbucket");
                for node in &sn.nodes {
                    self.try_add(node);
                }
            },
            None =>
                error!("Wrong DhtPacket; should have contained SendNodes"),
        }
    }

    /**
    Create a [`DhtPacket`](../dht/struct.DhtPacket.html) to peer with `peer_pk`
    `PublicKey` containing a [`PingReq`](../dht/struct.PingReq.html) request.
    */
    fn create_ping_req(&self, peer_pk: &PublicKey) -> DhtPacket {
        let ping = PingReq::new();
        // TODO: precompute shared key to calculate it 1 time
        let shared_secret = &encrypt_precompute(peer_pk, self.sk());
        let nonce = &gen_nonce();
        DhtPacket::new(shared_secret, self.pk(), nonce, &ping)
    }

    /**
    Request ping response from a peer. Peer might or might not even reply.

    Creates a future for sending request for ping.
    */
    // TODO: track requests
    pub fn request_ping(&self,
                         sink: ToxSplitSink,
                         peer_addr: SocketAddr,
                         peer_pk: &PublicKey)
        -> SendSink
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
                        sink: ToxSplitSink,
                        peer_addr: SocketAddr,
                        request: &DhtPacket)
        -> Option<SendSink>
    {
        // TODO: precompute shared key to calculate it 1 time
        let precomp = encrypt_precompute(&request.sender_pk, self.sk());
        request.ping_resp(self.sk(), &precomp, self.pk())
            .map(|p| sink.send((peer_addr, p)))
    }

    /**
    Create a [`DhtPacket`](../dht/struct.DhtPacket.html) to peer with `peer_pk`
    `PublicKey` containing a [`GetNodes`](../dht/struct.GetNodes.html) request
    for nodes close to own DHT `PublicKey`.
    */
    fn create_getn(&self, peer_pk: &PublicKey) -> DhtPacket {
        // request for nodes that are close to our own DHT PK
        let getn_req = &GetNodes::new(self.pk());
        let shared_secret = &encrypt_precompute(peer_pk, self.sk());
        let nonce = &gen_nonce();
        DhtPacket::new(shared_secret, self.pk(), nonce, getn_req)
    }

    /**
    Request nodes from a peer. Peer might or might not even reply.

    Creates a future for sending request for nodes.
    */
    // TODO: track requests
    pub fn request_nodes(&self,
                         sink: ToxSplitSink,
                         peer_addr: SocketAddr,
                         peer_pk: &PublicKey)
        -> SendSink
    {
        let request = self.create_getn(peer_pk);
        sink.send((peer_addr, request))
    }

    /**
    Create a [`DhtPacket`]  to peer with `peer_pk` `PublicKey`
    containing [`SendNodes`] response.

    Returns `None` if own `Kbucket` is empty or supplied `DhtPacket`
    doesn't contain [`GetNodes`] request.

    [`DhtPacket`]: ../dht/struct.DhtPacket.html
    [`GetNodes`]: ../dht/struct.GetNodes.html
    [`SendNodes`]: ../dht/struct.SendNodes.html
    */
    fn create_sendn(&self, request: &DhtPacket)
        -> Option<DhtPacket>
    {
        // TODO: precompute shared key to calculate it 1 time
        let getn = match request.get_packet::<GetNodes>(self.sk()) {
            Some(g) => g,
            None => return None,
        };
        let sendn = match getn.response(&*self.kbucket) {
            Some(s) => s,
            None => return None,
        };
        let shared_secret = &encrypt_precompute(&request.sender_pk, self.sk());
        let nonce = &gen_nonce();
        Some(DhtPacket::new(shared_secret, self.pk(), nonce, &sendn))
    }

    /**
    Send nodes in response to [`GetNodes`] request contained in
    [`DhtPacket`].

    Can fail (return `None`) if Kbucket is empty or `DhtPacket` doesn't
    contain `GetNodes` request.

    [`DhtPacket`]: ../dht/struct.DhtPacket.html
    [`GetNodes`]: ../dht/struct.GetNodes.html
    */
    pub fn send_nodes(&self,
                      sink: ToxSplitSink,
                      peer_addr: SocketAddr,
                      request: &DhtPacket)
        -> Option<SendSink>
    {
        self.create_sendn(request)
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
    type In = ToxUdpPacket;
    type Out = ToxUdpPacket;

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


/**
Spawn a thread that will start receiving packets from [`ToxSplitStream`].

[`ToxSplitStream`]: ./type.ToxSplitStream.html
*/
// TODO: move to network.rs ?
pub fn receive_packets(stream: ToxSplitStream)
    -> mpsc::Receiver<ToxUdpPacket>
{
    let (tx, rx) = mpsc::channel(2048);
    thread::spawn(move || {
        // can this fail to unwrap?
        let mut core = Core::new().unwrap();
        let handle = core.handle();

        let f = stream.for_each(|recv| {
            let tx = tx.clone();
            let send_one = tx.send(recv).then(|_| Ok(()));
            handle.spawn(send_one);
            Ok(())
        });

        core.run(f).unwrap();
    });

    rx
}



#[cfg(test)]
mod test {
    use futures::*;
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
    use toxcore::dht_node::*;
    use toxcore::packet_kind::PacketKind;

    use quickcheck::{quickcheck, TestResult};

    /// Bind to this IpAddr.
    // NOTE: apparently using `0.0.0.0`/`::` is not allowed on CIs like
    //       appveyor / travis
    const SOCKET_ADDR: &'static str = "127.0.0.1";

    /// Provide:
    ///   - mut core ($c)
    ///   - handle ($h)
    macro_rules! create_core {
        ($c:ident, $h:ident) => (
            let mut $c = Core::new().unwrap();
            let $h = $c.handle();
        )
    }

    /// Accept:
    ///   - handle ($h)
    /// Provide:
    ///   - [mut] DhtNode $name
    ///   - socket $name_socket
    macro_rules! node_socket {
        ($h:ident, mut $name:ident, $name_socket:ident) => (
            let mut $name = DhtNode::new().unwrap();
            let $name_socket = bind_udp(SOCKET_ADDR.parse().unwrap(),
                                        // make port range sufficiently big
                                        2048..65000,
                                        &$h)
                .expect("failed to bind to socket");
        );
        ($($h:ident, $name:ident, $name_socket:ident),+) => ($(
            let $name = DhtNode::new().unwrap();
            let $name_socket = bind_udp(SOCKET_ADDR.parse().unwrap(),
                                        // make port range sufficiently big
                                        2048..65000,
                                        &$h)
                .expect("failed to bind to socket");
        )+);
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
            let mut kbuc = Kbucket::new(KBUCKET_BUCKETS, dhtn.pk());

            for pn in &pns {
                assert_eq!(dhtn.try_add(pn), kbuc.try_add(pn));
                assert_eq!(kbuc, *dhtn.kbucket);
            }
        }
        quickcheck(with_nodes as fn(Vec<PackedNode>));
    }


    // DhtNode::pk()

    #[test]
    fn dht_node_pk_test() {
        let dn = DhtNode::new().unwrap();
        assert_eq!(&*dn.dht_public_key, dn.pk());
    }

    // DhtNode::pk()

    #[test]
    fn dht_node_sk_test() {
        let dn = DhtNode::new().unwrap();
        assert_eq!(&*dn.dht_secret_key, dn.sk());
    }

    // DhtNode::try_add_nodes()

    quickcheck! {
        // TODO: silence unnecessary `error!` messages by disabling
        //       quickcheck's `use_logging` feature?
        fn dht_node_try_add_nodes_test(sn: SendNodes,
                                       gn: GetNodes,
                                       pq: PingReq,
                                       pr: PingResp)
            -> ()
        {
            // bob creates a DhtPacket to alice that contains SendNodes
            // alice adds the nodes

            let mut alice = DhtNode::new().unwrap();
            let (bob_pk, bob_sk) = gen_keypair();
            let precomp = precompute(alice.pk(), &bob_sk);
            let nonce = gen_nonce();
            macro_rules! try_add_with {
                ($($kind:expr)+) => ($(
                    alice.try_add_nodes(&DhtPacket::new(&precomp,
                                                        &bob_pk,
                                                        &nonce,
                                                        &$kind));
                )+)
            }
            // also try to add nodes from a DhtPacket that don't contain
            // SendNodes
            try_add_with!(sn /* and invalid ones */ gn pq pr);

            // verify that alice's kbucket's contents are the same as
            // stand-alone kbucket
            let mut kbuc = Kbucket::new(KBUCKET_BUCKETS, alice.pk());
            for pn in &sn.nodes {
                kbuc.try_add(pn);
            }
            assert_eq!(kbuc, *alice.kbucket);
        }
    }

    // DhtNode::create_ping_req()

    #[test]
    fn dht_node_create_ping_req_test() {
        let alice = DhtNode::new().unwrap();
        let (bob_pk, bob_sk) = gen_keypair();
        let (_, eve_sk) = gen_keypair();
        let packet1 = alice.create_ping_req(&bob_pk);
        assert_eq!(alice.pk(), &packet1.sender_pk);
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
        create_core!(core, handle);
        node_socket!(handle, alice, alice_socket,
                     handle, bob, bob_socket);
        let alice_addr = alice_socket.local_addr().unwrap();

        let mut recv_buf = [0; MAX_UDP_PACKET_SIZE];

        let (bob_sink, _) = bob_socket.framed(ToxCodec).split();
        let bob_request = bob.request_ping(bob_sink, alice_addr, alice.pk());

        let future_recv = alice_socket.recv_dgram(&mut recv_buf[..]);
        let future_recv = add_timeout!(future_recv, &handle);
        handle.spawn(bob_request.then(|_| ok(())));

        let received = core.run(future_recv).unwrap();
        let (_alice_socket, recv_buf, size, _saddr) = received;
        assert!(size != 0);

        let recv_packet = DhtPacket::from_bytes(&recv_buf[..size]).unwrap();
        let payload: PingReq = recv_packet
            .get_packet(alice.sk())
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
            create_core!(core, handle);
            node_socket!(handle, alice, alice_socket,
                         handle, bob, bob_socket);
            let (_, eve_sk) = gen_keypair();

            let precomp = encrypt_precompute(alice.pk(), bob.sk());
            let nonce = gen_nonce();
            let bob_ping = DhtPacket::new(&precomp, bob.pk(), &nonce, &req);

            let (alice_sink, _) = alice_socket.framed(ToxCodec).split();
            let alice_send = alice.respond_ping(
                alice_sink,
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
                .get_packet(bob.sk())
                .expect("Failed to decrypt payload");

            assert_eq!(PacketKind::PingResp, payload.kind());
            assert_eq!(req.id(), payload.id());

            // wrong packet kind
            cant_parse_as_packet!(recv_packet, bob.sk(),
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
        assert_eq!(alice.pk(), &packet1.sender_pk);
        assert_eq!(PacketKind::GetN, packet1.kind());

        // eve can't decrypt
        assert_eq!(None, packet1.get_packet::<GetNodes>(&eve_sk));

        let payload1: GetNodes = packet1.get_packet(&bob_sk)
            .expect("failed to get payload1");
        assert_eq!(alice.pk(), &payload1.pk);

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
        create_core!(core, handle);
        node_socket!(handle, alice, alice_socket,
                     handle, bob, bob_socket);
        let alice_addr = alice_socket.local_addr().unwrap();

        let mut recv_buf = [0; MAX_UDP_PACKET_SIZE];

        let (bob_sink, _) = bob_socket.framed(ToxCodec).split();
        let bob_request = bob.request_nodes(bob_sink, alice_addr, alice.pk());

        let future_recv = alice_socket.recv_dgram(&mut recv_buf[..]);
        let future_recv = add_timeout!(future_recv, &handle);
        handle.spawn(bob_request.then(|_| ok(())));

        let received = core.run(future_recv).unwrap();
        let (_alice_socket, recv_buf, size, _saddr) = received;
        assert!(size != 0);

        let recv_packet = DhtPacket::from_bytes(&recv_buf[..size]).unwrap();
        let payload: GetNodes = recv_packet
            .get_packet(alice.sk())
            .expect("Failed to decrypt payload");

        assert_eq!(&payload.pk, bob.pk());
    }

    // DhtNode::create_sendn()

    quickcheck! {
        fn dht_node_create_sendn_test(pns: Vec<PackedNode>) -> TestResult {
            if pns.is_empty() { return TestResult::discard() }

            // alice creates DhtPacket containing GetNodes request
            // bob has to respond to it with SendNodes
            // alice has to be able to decrypt response
            // alice has to be able to successfully add received nodes
            // eve can't decrypt response

            let mut alice = DhtNode::new().unwrap();
            let mut bob = DhtNode::new().unwrap();
            let (_, eve_sk) = gen_keypair();
            let req = alice.create_getn(bob.pk());

            // errors with an empty kbucket
            let error = bob.create_sendn(&req);
            assert_eq!(None, error);

            for pn in &pns {
                bob.try_add(pn);
            }

            let resp1 = bob.create_sendn(&req)
                .expect("failed to create response1");
            let resp2 = bob.create_sendn(&req)
                .expect("failed to create response2");

            assert_eq!(resp1.sender_pk, *bob.pk());
            assert_eq!(PacketKind::SendN, resp1.kind());
            // encrypted payload differs due to different nonce
            assert_ne!(resp1, resp2);

            // eve can't decrypt
            assert_eq!(None, resp1.get_packet::<SendNodes>(&eve_sk));

            let resp1_payload: SendNodes = resp1
                .get_packet(alice.sk())
                .expect("failed to get payload1");
            let resp2_payload: SendNodes = resp2
                .get_packet(alice.sk())
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
        fn dht_node_send_nodes(pns: Vec<PackedNode>) -> TestResult {
            if pns.is_empty() { return TestResult::discard() }

            // alice sends SendNodes response to random GetNodes request
            // to bob

            create_core!(core, handle);
            node_socket!(handle, mut alice, alice_socket);
            node_socket!(handle, bob, bob_socket);

            for pn in &pns {
                drop(alice.try_add(pn));
            }

            let getn = bob.create_getn(alice.pk());

            let (alice_sink, _) = alice_socket.framed(ToxCodec).split();
            let alice_response = alice.send_nodes(
                alice_sink,
                bob_socket.local_addr().unwrap(),
                &getn);

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


    // receive_packets()

    quickcheck! {
        fn receive_packets_test(dps: Vec<DhtPacket>) -> TestResult {
            if dps.is_empty() { return TestResult::discard() }
            // alice sends packets to bob
            create_core!(core, handle);
            node_socket!(handle, _alice, a_socket);
            node_socket!(handle, _bob, b_socket);

            let a_addr = a_socket.local_addr().unwrap();
            let b_addr = b_socket.local_addr().unwrap();
            let (_sink, stream) = b_socket.framed(ToxCodec).split();

            // start receiving packets
            let to_receive = receive_packets(stream);

            let mut a_socket = a_socket;
            for dp in &dps {
                let send = a_socket.send_dgram(dp.to_bytes(), b_addr);
                let (s, _) = core.run(send).unwrap();
                a_socket = s;
            }

            let f_recv = to_receive.take(dps.len() as u64).collect();
            let received = core.run(f_recv).unwrap();

            for (n, &(ref addr, ref packet)) in received.iter().enumerate() {
                assert_eq!(a_addr, *addr);
                assert_eq!(dps[n], *packet);
            }

            TestResult::passed()
        }
    }
}
