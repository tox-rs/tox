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

use futures::*;
use futures::sink;
use futures::stream::*;
use futures::sync::mpsc;
use tokio_core::reactor::Core;
use tokio_proto::multiplex::RequestId;
use tokio_core::net::UdpFramed;

use std::collections::VecDeque;
use std::io::{self, ErrorKind, Error};
use std::net::SocketAddr;
use std::thread;

use toxcore::crypto_core::*;
use toxcore::dht_new::packet::*;
use toxcore::dht_new::codec::*;
use toxcore::dht_new::packed_node::*;
use toxcore::dht_new::kbucket::*;
use toxcore::dht_new::dht_impl::*;
use toxcore::timeout::*;
use toxcore::dht_new::packet_kind::*;

/// Type for sending `SplitSink` with `DhtCodec`.
// FIXME: docs
// TODO: rename
pub type DhtSplitSink = SplitSink<UdpFramed<DhtCodec>>;

/// Type for receiving `SplitStream` with `DhtCodec`.
// FIXME: docs
// TODO: rename
pub type DhtSplitStream = SplitStream<UdpFramed<DhtCodec>>;

/// Type representing future `Send` via `SplitSink`.
// FIXME: docs
// TODO: rename
pub type SendSink = sink::Send<SplitSink<UdpFramed<DhtCodec>>>;

// /// Type representing Tox UDP packets.
// TODO: change DhtPacket to and enum with all possible packets
// pub type DhtUdpPacket = (SocketAddr, DhtPacketBase);

// /// Type representing received Tox UDP packets.
// TODO: change DhtPacket to and enum with all possible packets
//pub type ToxRecvUdpPacket = (SocketAddr, Option<DhtPacket>);

/**
Spawn a thread that will start receiving packets from [`DhtSplitStream`].

[`DhtSplitStream`]: ./type.DhtSplitStream.html
*/
// TODO: move to network.rs ?
pub fn receive_packets(stream: DhtSplitStream)
    -> mpsc::Receiver<DhtUdpPacket>
{
    let (tx, rx) = mpsc::channel(2048);
    thread::spawn(move || {
        // can this fail to unwrap?
        let mut core = Core::new().unwrap();
        let handle = core.handle();

        let f = stream.for_each(|(src, p)| {
            if let Some(packet) = p {
                let tx = tx.clone();
                let send_one = tx.send((src, packet)).then(|_| Ok(()));
                handle.spawn(send_one);
            }
            Ok(())
        });

        core.run(f).unwrap();
    });

    rx
}

/**
Spawn a thread that will start sending packets via [`DhtSplitSink`].

Send all packets that need to be sent via returned `Sender`.

[`DhtSplitSink`]: ./type.DhtSplitSink.html
*/
// TODO: move to network.rs ?
pub fn send_packets(sink: DhtSplitSink)
    -> mpsc::Sender<DhtUdpPacket>
{
    let (tx, rx) = mpsc::channel(2048);
    thread::spawn(move || {
        // can this fail to unwrap?
        let mut core = Core::new().unwrap();

        let f = sink.send_all(rx.map_err(|_| {
            // needed only to satisfy Sink::send_all() error constraints
            io::Error::new(ErrorKind::Other, "")
        }));
        drop(core.run(f));
    });

    tx
}

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
a [`GetNodes`] request is sent to it in order to check whether it's
online. If the node responds correctly within [`PING_TIMEOUT`], it's
removed from temporary list and added to the Close List.

[`GetNodes`]: ../dht/struct.GetNodes.html
[`Kbucket`]: ../dht/struct.Kbucket.html
[`Kbucket::can_add()`]: ../dht/struct.Kbucket.html#method.can_add
[`PackedNode`]: ../dht/struct.PackedNode.html
[`PING_TIMEOUT`]: ../timeout/constant.PING_TIMEOUT.html
[`TimeoutQueue`]: ../timeout/struct.TimeoutQueue.html
*/
#[derive(Clone, Eq, Debug, PartialEq)]
pub struct DhtNode {
    /// secret key
    pub sk: Box<SecretKey>,
    /// public key
    pub pk: Box<PublicKey>,
    /// Close List (contains nodes close to own DHT PK)
    pub kbucket: Box<Kbucket>,
    getn_timeout: TimeoutQueue,
    /// timeouts for requests that check whether a node is online before
    /// adding it to the Close List
    // TODO: rename
    to_close_tout: TimeoutQueue,
    /// list of nodes that are checked for being online before adding
    /// to the Close List
    // TODO: rename
    to_close_nodes: VecDeque<PackedNode>,
    // TODO: add a "verify" TimeoutQueue to check if nodes are online
    //       before adding them to the kbucket

    // TODO: track sent ping request IDs
    // TODO: have a table with precomputed keys for all known nodes?
    //       (use lru-cache for storing last used 1024?)
    /// symmetric keys cache
    pub precomputed_cache: PrecomputedKeys,
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
            sk: Box::new(sk),
            pk: Box::new(pk),
            kbucket: Box::new(kbucket),
            getn_timeout: Default::default(),
            to_close_tout: Default::default(),
            to_close_nodes: Default::default(),
            // Should it Boxed?
            precomputed_cache: PrecomputedKeys::new(),
        })
    }

    /**
    Function to handle incoming packets. If there is a response packet,
    `Some(DhtBase)` is returned.
    */
    pub fn handle_packet(&mut self, packet: &DhtBase)
        -> Option<DhtBase>
    {
        match packet {
            &DhtBase::DhtPacket(ref dp) => {
                match dp.packet_kind {
                    PacketKind::PingRequest => {
                        debug!("Received ping request");
                        self.create_ping_resp(packet)
                    },
                    PacketKind::GetNodes => {
                        debug!("Received GetN request");
                        self.create_sendn(packet)
                    },
                    PacketKind::SendNodes => {
                        debug!("Received SendN packet");
                        self.handle_packet_sendn(packet);
                        None
                    },
                    // TODO: handle other kinds of packets
                    p => {
                        debug!("Received unhandled packet kind: {:?}", p);
                        None
                    },
                }
            },
            // DhtRequest is not yet.
            &DhtBase::DhtRequest(_) => {
                None
            },
        }
    }

    /**
    Handle [`DhtBase`] that claims to contain [`SendNodes`] packet.

    Packet is dropped if:

    - it doesn't contain [`SendNodes`]
    - it's not a response to a [`GetNodes`] request (invalid ID)

    [`DhtBase`]: ../dht/enum.DhtBase.html
    [`DhtPacket`]: ../dht/struct.DhtPacket.html
    [`GetNodes`]: ../dht/struct.GetNodes.html
    [`SendNodes`]: ../dht/struct.SendNodes.html
    */
    fn handle_packet_sendn(&mut self, packet: &DhtBase) {
        if let &DhtBase::DhtPacket(ref dp) = packet {
            let rlt = dp.get_payload(&self.sk)
            .and_then(|psn| {
                if let Some(DhtPacketPayload::SendNodes(sn)) = psn {
                    if self.getn_timeout.remove(sn.id) {
                        debug!("Received SendN is a valid response");
                        // received SendNodes packet is a response to our request
                        trace!("Adding nodes from SendNodes to DhtNode's Kbucket");
                        for node in &sn.nodes {
                            self.kbucket.try_add(node);
                        }
                    }
                    Ok(())
                } else { Ok(())}
            })
            .map_err(|_| {
                error!("Wrong DhtPacket; should have contained SendNodes");
            });
            rlt.unwrap_or(())
        }
        else {
            ;
        }
    }

    /**
    Remove nodes that have crossed `secs` timeout threshold.
    */
    // TODO: test
    // TODO: add fn for ping/getn req timeouts with hardcoded consts?
    pub fn remove_timed_out(&mut self, secs: u64) {
        for pk in self.getn_timeout.get_timed_out(secs) {
            debug!("Removing timed out node");
            self.kbucket.remove(&pk);
        }
    }

    /**
    Create a [`DhtPacket`] to peer with `peer_pk` `PublicKey` containing
    a [`PingReq`] request.

    [`DhtPacket`]: ../dht/struct.DhtPacket.html
    [`PingReq`]: ../dht/struct.PingReq.html
    */
    pub fn create_ping_req(&mut self, peer_pk: &PublicKey) -> DhtPacket {
        let ping = DhtPacketPayload::PingRequest(PingRequest { id: random_u64() });
        let shared_key = self.precomputed_cache.get_symmetric_key((&self.sk, peer_pk)).expect("symmetric key gens fail");
        DhtPacket::new(&shared_key, &self.pk, ping)
    }

    /**
    Create a [`DhtUdpPacket`] with request for ping response from a peer.

    [`DhtUdpPacket`] is to be passed to `Sender` created by
    [`send_packets()`].

    [`send_packets()`]: ./fn.send_packets.html
    [`DhtUdpPacket`]: ./type.DhtUdpPacket.html
    */
    // TODO: track requests
    pub fn request_ping(&mut self, peer: &PackedNode) -> DhtUdpPacket {
        let request = self.create_ping_req(&peer.pk);
        (peer.socket_addr(), DhtBase::DhtPacket(request))
    }

    /**
    Create DHT Packet with [`Ping`](./struct.Ping.html) response to `Ping`
    request that packet contained.

    Nonce for the response is automatically generated.
    */
    // Because UDP codec and tokio use DhtBase for send/receive packet, 
    // this function returns DhtBase type object
    pub fn ping_response(&self, dp: &DhtPacket,
                     secret_key: &SecretKey,
                     symmetric_key: &PrecomputedKey,
                     own_public_key: &PublicKey) -> Option<DhtBase> {

        debug!(target: "DhtPacket", "Creating Ping response from Ping request that DHT packet contained.");
        trace!(target: "DhtPacket", "With args: DhtPacket: {:?}, own_pk: {:?}", dp, own_public_key);

        if dp.packet_kind != PacketKind::PingRequest {
            return None
        }

        if let Ok(Some(DhtPacketPayload::PingRequest(packet))) = dp.get_payload(secret_key) {
            let resp = DhtPacketPayload::PingResponse(PingResponse::from(packet));
            Some(DhtBase::DhtPacket(DhtPacket::new(symmetric_key, own_public_key, resp)))
        }
        else {
            None
        }
    }

    /**
    Create a [`DhtPacket`] in response to [`DhtPacket`] containing
    [`PingReq`] packet.

    Returns `None` if [`DhtPacket`] is not a [`PingReq`].

    [`DhtPacket`]: ../dht/struct.DhtPacket.html
    [`PingReq`]: ../dht/struct.PingReq.html
    */
    pub fn create_ping_resp(&mut self, request: &DhtBase)
        -> Option<DhtBase>
    {
        if let &DhtBase::DhtPacket(ref dp) = request {
        // TODO: precompute shared key to calculate it 1 time
            let shared_key = self.precomputed_cache.get_symmetric_key((&self.sk, &dp.pk)).expect("Key HashMap error");
            self.ping_response(dp, &self.sk, &shared_key, &self.pk)
        }
        else {
            None
        }
    }

    /**
    Create a future sending [`DhtPacket`] that encapsulates
    [ping response] to supplied ping request.

    [`DhtPacket`]: ../dht/struct.DhtPacket.html
    [ping response]: ../dht/struct.PingResp.html
    */
    // TODO: change to return Option<ToxUdpPakcet>
    pub fn respond_ping(&mut self,
                        sink: DhtSplitSink,
                        peer_addr: SocketAddr,
                        request: &DhtBase)
        -> Option<SendSink>
    {
        self.create_ping_resp(request)
            .map(|p| sink.send((peer_addr, p)))
    }

    /**
    Create a [`DhtPacket`] to peer's `PublicKey` containing
    a [`GetNodes`] request for nodes close to own DHT `PublicKey`.

    `RequestId` is to be used for tracking node timeouts.

    [`DhtPacket`]: ../dht/struct.DhtPacket.html
    [`GetNodes`]: ../dht/struct.GetNodes.html
    */
    pub fn create_getn(&mut self, peer_pk: &PublicKey)
        -> (RequestId, DhtBase) {
        // request for nodes that are close to our own DHT PK
        let req = GetNodes{ pk: *&*self.pk, id: random_u64() };
        let shared_key = self.precomputed_cache.get_symmetric_key((&self.sk, peer_pk)).unwrap();
        (req.id, DhtBase::DhtPacket(DhtPacket::new(&shared_key, &self.pk, DhtPacketPayload::GetNodes(req))))
    }

    /**
    Create a [`DhtUdpPacket`] with request for nodes from a peer.

    [`DhtUdpPacket`] is to be passed to `Sender` created by
    [`send_packets()`].

    `RequestId` is to be used for tracking node timeouts.

    [`send_packets()`]: ./fn.send_packets.html
    [`DhtUdpPacket`]: ./type.DhtUdpPacket.html
    */
    pub fn request_nodes(&mut self, peer: &PackedNode)
        -> (RequestId, DhtUdpPacket)
    {
        let (id, request) = self.create_getn(&peer.pk);
        (id, (peer.socket_addr(), request))
    }

    /**
    Create [`DhtUdpPacket`]s with request for nodes from every peer in
    the Close List.

    [`DhtUdpPacket`]s are to be passed to `Sender` created by
    [`send_packets()`].

    **Adds request to response timeout queue.**

    **Note**: returned `Vec` can be empty if there are no known nodes.

    [`send_packets()`]: ./fn.send_packets.html
    [`DhtUdpPacket`]: ./type.DhtUdpPacket.html
    */
    pub fn request_nodes_close(&mut self) -> Vec<DhtUdpPacket> {
        self.kbucket.iter()
            // copy, collect & iter again to work around borrow checker
            .cloned()
            .collect::<Vec<PackedNode>>()
            .iter()
            .map(|pn| {
                let (id, packet) = self.request_nodes(pn);
                // add to timeout queue
                self.getn_timeout.add(&pn.pk, id);
                packet
            })
            .collect()
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
    pub fn create_sendn(&mut self, request: &DhtBase)
        -> Option<DhtBase>
    {
        if let &DhtBase::DhtPacket(ref dp) = request {
            let rlt = dp.get_payload(&self.sk)
            .and_then(|psn| {
                if let Some(DhtPacketPayload::GetNodes(ref getn)) = psn {
                    if let Some(sendn) = getn.response(&*self.kbucket) {
                        let shared_key = self.precomputed_cache.get_symmetric_key((&self.sk, &dp.pk)).expect("Keys HashMap error");
                        Ok(Some(DhtBase::DhtPacket(DhtPacket::new(&shared_key, &self.pk, sendn))))
                    } else { Err(Error::new(ErrorKind::Other, "SendNodes creation error")) }
                } else { Err(Error::new(ErrorKind::Other, "get_payload call error")) }
            })
            .map_err(|_| ());
            rlt.unwrap_or(None)
        } else {
            None
        }
    }

    /**
    Send nodes in response to [`GetNodes`] request contained in
    [`DhtPacket`].

    Can fail (return `None`) if Kbucket is empty or `DhtPacket` doesn't
    contain `GetNodes` request.

    [`DhtPacket`]: ../dht/struct.DhtPacket.html
    [`GetNodes`]: ../dht/struct.GetNodes.html
    */
    pub fn send_nodes(&mut self,
                      sink: DhtSplitSink,
                      peer_addr: SocketAddr,
                      request: &DhtBase)
        -> Option<SendSink>
    {
        self.create_sendn(request)
            .map(|sn| sink.send((peer_addr, sn)))
    }
}

#[cfg(test)]
mod test {
    use futures::*;
    use futures::future::*;
    use tokio_core::reactor::{Core, Timeout};
    use tokio_core::net::UdpCodec;

    use std::net::SocketAddr;
    use std::time::Duration;

    use toxcore::dht_new::binary_io::*;
    use toxcore::crypto_core::*;
    use toxcore::network::*;
    use toxcore::dht_new::dht_node::*;
    use toxcore::dht_new::packet_kind::PacketKind;

    use quickcheck::{quickcheck, TestResult};

    /// Bind to this IpAddr.
    // NOTE: apparently using `0.0.0.0`/`::` is not allowed on CIs like
    //       appveyor / travis
    const SOCKET_ADDR: &str = "127.0.0.1";

    /// Provide:
    ///   - mut core ($c)
    ///   - handle ($h)
    macro_rules! create_core {
        ($c:ident, $h:ident) => (
            let $c = Core::new().unwrap();
            let $h = $c.handle();
        );

        (mut $c:ident, $h:ident) => (
            let mut $c = Core::new().unwrap();
            let $h = $c.handle();
        );
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
                                        2048..65_000,
                                        &$h)
                .expect("failed to bind to socket");
        );
        ($($h:ident, $name:ident, $name_socket:ident),+) => ($(
            let $name = DhtNode::new().unwrap();
            let $name_socket = bind_udp(SOCKET_ADDR.parse().unwrap(),
                                        // make port range sufficiently big
                                        2048..65_000,
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
            let mut kbuc = Kbucket::new(KBUCKET_BUCKETS, &dhtn.pk);

            for pn in &pns {
                assert_eq!(dhtn.kbucket.try_add(pn), kbuc.try_add(pn));
                assert_eq!(kbuc, *dhtn.kbucket);
            }
        }
        quickcheck(with_nodes as fn(Vec<PackedNode>));
    }

    // DhtNode::create_ping_req()

    #[test]
    fn dht_node_create_ping_req_test() {
        let mut alice = DhtNode::new().unwrap();
        let (bob_pk, bob_sk) = gen_keypair();
        let (_, eve_sk) = gen_keypair();
        let packet1 = alice.create_ping_req(&bob_pk);
        assert_eq!(&*alice.pk, &packet1.pk);
        assert_eq!(PacketKind::PingRequest, packet1.packet_kind);

        let packet2 = alice.create_ping_req(&bob_pk);
        assert_ne!(packet1, packet2);

        // eve can't decrypt it
        assert_eq!(None, packet1.get_payload(&eve_sk).unwrap_or(None));

        if let DhtPacketPayload::PingRequest(payload1) = packet1.get_payload(&bob_sk)
            .expect("failed to get payload1").unwrap() {
            if let DhtPacketPayload::PingRequest(payload2) = packet2.get_payload(&bob_sk)
            .expect("failed to get payload2").unwrap() {
                assert_ne!(payload1.id, payload2.id);
            } else { panic!("Can not occur"); }
        } else { panic!("Can not occur"); }
    }

    // DhtNode::request_ping()

    #[test]
    fn dht_node_request_ping_test() {
        // bob creates & sends PingReq to alice
        // received PingReq has to be succesfully decrypted
        create_core!(core, handle);
        node_socket!(handle, alice, alice_socket);
        let mut bob = DhtNode::new().unwrap();
        let alice_addr = alice_socket.local_addr().unwrap();
        let alice_pn = PackedNode::new(true, alice_addr, &alice.pk);

        if let (dest_addr, DhtBase::DhtPacket(bob_request)) = bob.request_ping(&alice_pn) {
            assert_eq!(alice_addr, dest_addr);

            let payload = bob_request
                .get_payload(&alice.sk)
                .expect("Failed to decrypt payload").unwrap();

            assert_eq!(PacketKind::PingRequest, payload.kind());
        } else { panic!("Can not occur"); }

    }

    // DhtNode::create_ping_resp()

    quickcheck! {
        fn dht_node_create_ping_resp_test(req: PingRequest) -> () {
            // alice creates DhtPacket containing PingReq request
            // bob has to respond to it with PingResp
            // alice has to be able to decrypt response
            // eve can't decrypt response

            let mut alice = DhtNode::new().unwrap();
            let mut bob = DhtNode::new().unwrap();
            let (_, eve_sk) = gen_keypair();
            let precomp = encrypt_precompute(&bob.pk, &alice.sk);
            let dreq = DhtPacketPayload::PingRequest(req);
            let a_ping = DhtBase::DhtPacket(DhtPacket::new(&precomp, &alice.pk, dreq));

            if let DhtBase::DhtPacket(resp1) = bob.create_ping_resp(&a_ping)
                .expect("failed to create ping resp1") {
                if let DhtBase::DhtPacket(resp2) = bob.create_ping_resp(&a_ping)
                    .expect("failed to create ping resp2") {

                    assert_eq!(&resp1.pk, &*bob.pk);
                    assert_eq!(PacketKind::PingResponse, resp1.packet_kind);
                    // encrypted payload differs due to different nonce
                    assert_ne!(resp1, resp2);

                    // eve can't decrypt
                    assert_eq!(None, resp1.get_payload(&eve_sk).ok().unwrap_or(None));

                    let resp1_payload = resp1
                        .get_payload(&alice.sk).unwrap().unwrap();
                    let resp2_payload = resp2
                        .get_payload(&alice.sk).unwrap().unwrap();
                    assert_eq!(resp1_payload, resp2_payload);
                    if let DhtPacketPayload::PingResponse(target_resp) = resp1_payload {
                        assert_eq!(req.id, target_resp.id);
                        assert_eq!(PacketKind::PingResponse, resp1_payload.kind());

                        // can't create response from DhtPacket containing PingResp
                        assert!(alice.create_ping_resp(&DhtBase::DhtPacket(resp1)).is_none());
                    } else { panic!("can not occur")}
                } else { panic!("can not occur")}
            } else { panic!("can not occur")}
        }
    }

    // DhtNode::respond_ping()

    quickcheck! {
        fn dht_node_respond_ping_test(req: PingRequest) -> () {
            // bob creates a DhtPacket with PingReq, and alice
            // sends a response to it
            // response has to be successfully decrypted by alice
            // response can't be decrypted by eve
            create_core!(mut core, handle);
            node_socket!(handle, mut alice, alice_socket);
            node_socket!(handle, mut bob, bob_socket);
            let (_, eve_sk) = gen_keypair();

            let precomp = encrypt_precompute(&alice.pk, &bob.sk);
            let dreq = DhtPacketPayload::PingRequest(req);
            let bob_ping = DhtPacket::new(&precomp, &bob.pk, dreq);

            let (alice_sink, _) = alice_socket.framed(DhtCodec).split();
            let alice_send = alice.respond_ping(
                alice_sink,
                bob_socket.local_addr().unwrap(),
                &DhtBase::DhtPacket(bob_ping.clone()));

            let mut recv_buf = [0; MAX_UDP_PACKET_SIZE];
            let future_recv = bob_socket.recv_dgram(&mut recv_buf[..]);
            let future_recv = add_timeout!(future_recv, &handle);
            handle.spawn(alice_send.then(|_| ok(())));

            let received = core.run(future_recv).unwrap();
            let (_bob_socket, recv_buf, size, _saddr) = received;
            assert!(size != 0);
            let mut buf = [0; 512];
            assert_eq!(size, bob_ping.to_bytes((&mut buf, 0)).unwrap().1);

            let recv_packet = DhtPacket::from_bytes(&recv_buf[..size]).unwrap().1;
            assert_eq!(PacketKind::PingResponse, recv_packet.packet_kind);

            // eve can't decrypt it
            assert_eq!(None, recv_packet.get_payload(&eve_sk).unwrap_or(None));

            if let DhtPacketPayload::PingResponse(_payload) = recv_packet
                .get_payload(&bob.sk).unwrap().unwrap() {
                    ;
            } else { panic!("can not occur")}
            bob.pk = alice.pk;  // to remove compile time warning
        }
    }

    // DhtNode::create_getn()

    #[test]
    fn dht_node_create_getn_test() {
        // alice sends GetNodes request to bob
        // bob has to successfully decrypt the request
        // eve can't decrypt the request
        let mut alice = DhtNode::new().unwrap();
        let (bob_pk, bob_sk) = gen_keypair();
        let (_, eve_sk) = gen_keypair();
        if let (req_id1, DhtBase::DhtPacket(packet1)) = alice.create_getn(&bob_pk) {
            assert_eq!(&*alice.pk, &packet1.pk);
            assert_eq!(PacketKind::GetNodes, packet1.packet_kind);

            // eve can't decrypt
            assert_eq!(None, packet1.get_payload(&eve_sk).unwrap_or(None));

            if let DhtPacketPayload::GetNodes(payload1) = packet1.get_payload(&bob_sk)
                .expect("failed to get payload1").unwrap() {
                assert_eq!(&*alice.pk, &payload1.pk);
                assert_eq!(req_id1, payload1.id);

                if let (_req_id2, DhtBase::DhtPacket(packet2)) = alice.create_getn(&bob_pk) {
                    assert_ne!(&packet1, &packet2);

                    if let DhtPacketPayload::GetNodes(payload2) = packet2.get_payload(&bob_sk)
                        .expect("failed to get payload2").unwrap() {
                        assert_ne!(payload1.id, payload2.id);
                    } else { panic!("can not occur")}
                } else { panic!("can not occur")}
            } else { panic!("can not occur")}
        } else { panic!("can not occur")}
    }

    // DhtNode::request_nodes()

    #[test]
    fn dht_node_request_nodes_test() {
        // bob creates a ToxUdpPacket with GetNodes request to alice
        // alice has to successfully decrypt & parse it
        create_core!(core, handle);
        node_socket!(handle, alice, alice_socket);
        let mut bob = DhtNode::new().unwrap();
        let alice_addr = alice_socket.local_addr().unwrap();
        let alice_pn = PackedNode::new(true, alice_addr, &alice.pk);

        if let (id, (dest_addr, DhtBase::DhtPacket(bob_request))) = bob.request_nodes(&alice_pn) {
            assert_eq!(alice_addr, dest_addr);

            if let DhtPacketPayload::GetNodes(payload) = bob_request
                .get_payload(&alice.sk)
                .expect("Failed to decrypt payload")
                .unwrap() {

                assert_eq!(&payload.pk, &*bob.pk);
                assert_eq!(payload.id, id);
            } else { panic!("can not occur")}
        } else { panic!("can not occur")}
    }

    // DhtNode::request_nodes_close()

    quickcheck! {
        fn dht_node_request_nodes_close_test(pns: Vec<PackedNode>)
            -> TestResult
        {
            if pns.is_empty() { return TestResult::discard() }

            let mut dnode = DhtNode::new().unwrap();
            for pn in &pns {
                dnode.kbucket.try_add(pn);
            }

            let requests = dnode.request_nodes_close();

            for (n, node) in dnode.kbucket.iter().enumerate() {
                // each request creates a response timeout
                assert_eq!(dnode.getn_timeout.get(n).unwrap().pk(),
                           &node.pk);
                let (req_addr, ref _req_packet) = requests[n];
                assert_eq!(node.socket_addr(), req_addr);
            }

            TestResult::passed()
        }
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
            let (_id, req) = alice.create_getn(&bob.pk);

            // errors with an empty kbucket
            let error = bob.create_sendn(&req);
            assert_eq!(None, error);

            for pn in &pns {
                bob.kbucket.try_add(pn);
            }

            let pk = bob.pk.clone();
            let nonce = gen_nonce();

            if let DhtBase::DhtPacket(resp1) = bob.create_sendn(&req)
                .unwrap_or(DhtBase::DhtPacket(DhtPacket{packet_kind: PacketKind::PingRequest, pk: *pk, nonce: nonce, payload: vec![0x00]})) {
                if let DhtBase::DhtPacket(resp2) = bob.create_sendn(&req)
                    .unwrap_or(DhtBase::DhtPacket(DhtPacket{packet_kind: PacketKind::PingRequest, pk: *pk, nonce: nonce, payload: vec![0x00]})) {

                    assert_eq!(&resp1.pk, &*bob.pk);
                    assert_eq!(PacketKind::SendNodes, resp1.packet_kind);
                    // encrypted payload differs due to different nonce
                    assert_ne!(resp1, resp2);

                    // eve can't decrypt
                    assert_eq!(None, resp1.get_payload(&eve_sk).unwrap_or(None));

                    if let DhtPacketPayload::SendNodes(resp1_payload) = resp1
                        .get_payload(&alice.sk)
                        .unwrap_or(Some(DhtPacketPayload::PingRequest(PingRequest{id: 0x00}))).unwrap_or(DhtPacketPayload::PingRequest(PingRequest{id: 0x00})) {
                        if let DhtPacketPayload::SendNodes(resp2_payload) = resp2
                            .get_payload(&alice.sk)
                            .unwrap_or(Some(DhtPacketPayload::PingRequest(PingRequest{id: 0x00}))).unwrap_or(DhtPacketPayload::PingRequest(PingRequest{id: 0x00})) {
                            assert_eq!(resp1_payload, resp2_payload);
                            assert!(!resp1_payload.nodes.is_empty());

                            for node in &resp1_payload.nodes {
                                // has to succeed, since nodes in response have to differ
                                assert!(alice.kbucket.try_add(node));
                            }
                        } else { panic!("can not occur")}
                    } else { panic!("can not occur")}
                } else { panic!("can not occur")}
            } else { panic!("can not occur")}

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

            create_core!(mut core, handle);
            node_socket!(handle, mut alice, alice_socket);
            node_socket!(handle, mut bob, bob_socket);

            for pn in &pns {
                alice.kbucket.try_add(pn);
            }

            let (_id, getn) = bob.create_getn(&alice.pk);

            let (alice_sink, _) = alice_socket.framed(DhtCodec).split();
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

            let _recv_packet = DhtPacket::from_bytes(&recv_buf[..size]);

            TestResult::passed()
        }
    }

    // DhtNode::handle_packet_sendn()

    quickcheck! {
        fn dht_node_handle_packet_sendn_test(sn: SendNodes,
                                             gn: GetNodes,
                                             pq: PingRequest,
                                             pr: PingResponse)
            -> ()
        {
            // bob creates a DhtPacket to alice that contains SendNodes
            // alice adds the nodes

            let dpq = DhtPacketPayload::PingRequest(pq);
            let dpr = DhtPacketPayload::PingResponse(pr);
            let dgn = DhtPacketPayload::GetNodes(gn);
            let dsn = DhtPacketPayload::SendNodes(sn.clone());

            let mut alice = DhtNode::new().unwrap();
            let (bob_pk, bob_sk) = gen_keypair();
            let precomp = precompute(&alice.pk, &bob_sk);
            macro_rules! try_add_with {
                ($($kind:expr)+) => ($(
                    alice.handle_packet_sendn(&DhtBase::DhtPacket(DhtPacket::new(&precomp,
                                                              &bob_pk,
                                                              $kind)));
                )+)
            }
            // also try to add nodes from a DhtPacket that don't contain
            // SendNodes
            try_add_with!(dsn.clone() /* and invalid ones */ dgn dpq dpr);

            // since alice doesn't have stored ID for SendNodes response,
            // packet is supposed to be ignored
            assert!(alice.kbucket.is_empty());

            // add needed packet ID to alice's timeout table
            alice.getn_timeout.add(&bob_pk, sn.id);
            // now nodes from SendNodes can be processed
            try_add_with!(dsn);

            // verify that alice's kbucket's contents are the same as
            // stand-alone kbucket
            let mut kbuc = Kbucket::new(KBUCKET_BUCKETS, &alice.pk);
            for pn in &sn.nodes {
                kbuc.try_add(pn);
            }
            assert_eq!(kbuc, *alice.kbucket);
        }
    }

    // DhtNode::handle_packet()

    quickcheck! {
        fn dht_node_handle_packet(pq: PingRequest,
                                  pr: PingResponse,
                                  gn: GetNodes,
                                  sn: SendNodes)
            -> ()
        {
            let alice = DhtNode::new().unwrap();
            let mut bob = DhtNode::new().unwrap();
            let precom = precompute(&bob.pk, &alice.sk);

            let dpq = DhtPacketPayload::PingRequest(pq);
            let dpr = DhtPacketPayload::PingResponse(pr);
            let dgn = DhtPacketPayload::GetNodes(gn);
            let dsn = DhtPacketPayload::SendNodes(sn.clone());
            
            // test with

            {
                // PingReq
                let dp = DhtBase::DhtPacket(DhtPacket::new(&precom, &alice.pk, dpq));
                assert_eq!(bob.create_ping_resp(&dp).unwrap().kind(),
                           bob.handle_packet(&dp).unwrap().kind());
            }

            {
                // PingResp
                let dp = DhtBase::DhtPacket(DhtPacket::new(&precom, &alice.pk, dpr));
                assert_eq!(None, bob.handle_packet(&dp));
            }

            {
                // GetNodes with an empty kbucket
                let dp = DhtBase::DhtPacket(DhtPacket::new(&precom, &alice.pk, dgn.clone()));
                assert_eq!(None, bob.handle_packet(&dp));
            }

            {
                // SendNodes
                let dp = DhtBase::DhtPacket(DhtPacket::new(&precom, &alice.pk, dsn));
                assert_eq!(None, bob.handle_packet(&dp));
                // bob doesn't have request ID, thus packet is dropped
                assert!(bob.kbucket.is_empty());
                // add request ID, so that nods could be processed
                bob.getn_timeout.add(&alice.pk, sn.id);
                assert_eq!(None, bob.handle_packet(&dp));
                assert!(!bob.kbucket.is_empty());
            }

            {
                // GetNodes with something in kbucket
                let dp = DhtBase::DhtPacket(DhtPacket::new(&precom, &alice.pk, dgn));
                assert_eq!(bob.create_sendn(&dp).unwrap().kind(),
                           bob.handle_packet(&dp).unwrap().kind());
            }
        }
    }


    // DhtCodec::

    // DhtCodec::decode()

    #[test]
    fn tox_codec_decode_test() {
        fn with_dp(dp: DhtBase) -> TestResult {
            // TODO: random SocketAddr
            let addr = SocketAddr::V4("0.1.2.3:4".parse().unwrap());
            let mut tc = DhtCodec;

            let mut buf = [0; 512];
            let (_, size) = dp.to_bytes((&mut buf, 0)).unwrap();
            let bytes = &buf[..size];

            let (decoded_a, decoded_dp) = tc.decode(&addr, &bytes)
                .unwrap();
            // it did have correct packet
            let decoded_dp = decoded_dp.unwrap();

            assert_eq!(addr, decoded_a);
            assert_eq!(dp, decoded_dp);

            // make it error
            let mut buf_err = buf.clone();
            buf_err[0] = 0x40;
            let bytes_err = &mut buf_err[..size];
            let (r_addr, none) = tc.decode(&addr, &bytes_err).unwrap_or((addr, None));
            assert_eq!(addr, r_addr);
            assert!(none.is_none());

            TestResult::passed()
        }
        quickcheck(with_dp as fn(DhtBase) -> TestResult);
    }

    // DhtCodec::encode()

    #[test]
    fn dht_codec_encode_test() {
        fn with_dp(dp: DhtBase) {
            // TODO: random SocketAddr
            let addr = SocketAddr::V4("5.6.7.8:9".parse().unwrap());
            let mut buf = Vec::new();
            let mut tc = DhtCodec;

            let socket = tc.encode((addr, dp.clone()), &mut buf);
            assert_eq!(addr, socket);
            let mut to_buf = [0; 512];
            let (_, size) = dp.to_bytes((&mut to_buf, 0)).unwrap();
            assert_eq!(buf, to_buf[..size].to_vec());
        }
        quickcheck(with_dp as fn(DhtBase));
    }


    // receive_packets()

    quickcheck! {
        fn dht_receive_packets_test(dps: Vec<DhtBase>) -> TestResult {
            if dps.is_empty() { return TestResult::discard() }
            // Send & receive packet create threads.
            // And processing each packet in Vec<DhtBase> also create thread.
            // Aribtrary Generator make much test data, so it result in shortage of OS resources.
            // To prevent this problem, limited number of test data are used.
            static mut COUNT: u16 = 0;
            unsafe {
                COUNT += 1;
                if COUNT > 100 || dps.len() > 20 {
                    return TestResult::discard()
                }
            }
            // alice sends packets to bob
            create_core!(mut core, handle);
            node_socket!(handle, _alice, a_socket);
            node_socket!(handle, _bob, b_socket);

            let a_addr = a_socket.local_addr().expect("local sender socket create error");
            let b_addr = b_socket.local_addr().expect("local receiver socket create error");
            let (_sink, stream) = b_socket.framed(DhtCodec).split();

            // start receiving packets
            let to_receive = receive_packets(stream);

            let mut a_socket = a_socket;
            for dp in &dps {
                let mut buf = [0; MAX_DHT_PACKET_SIZE];
                let (_, size) = dp.to_bytes((&mut buf, 0)).expect("to_bytes fail on DhtBase {:?}, dp");
                let send = a_socket.send_dgram(&buf[..size], b_addr);
                let (s, _) = core.run(send).expect("send error");
                a_socket = s;
            }

            let f_recv = to_receive.take(dps.len() as u64).collect();
            let received = core.run(f_recv).expect("receive error");

            for (n, &(ref addr, ref packet)) in received.iter().enumerate() {
                assert_eq!(a_addr, *addr);
                assert_eq!(dps[n], *packet);
            }

            TestResult::passed()
        }
    }

    // send_packets()

    quickcheck! {
        fn dht_send_packets_test(dps: Vec<DhtBase>) -> TestResult {
            if dps.is_empty() { return TestResult::discard() }
            // Send & receive packet create threads.
            // And processing each packet in Vec<DhtBase> also create thread.
            // Aribtrary Generator make much test data, so it result in shortage of OS resources.
            // To prevent this problem, limited number of test data are used.
            static mut COUNT: u16 = 0;
            unsafe {
                COUNT += 1;
                if COUNT > 100 || dps.len() > 20 {
                    return TestResult::discard()
                }
            }
            // alice sends packets to bob
            create_core!(mut core, handle);
            node_socket!(handle, _alice, a_socket);
            node_socket!(handle, _bob, b_socket);

            let a_addr = a_socket.local_addr().expect("sender socket create error");
            let b_addr = b_socket.local_addr().expect("receiver socket create error");
            let (sink, _stream) = a_socket.framed(DhtCodec).split();
            let (_sink, stream) = b_socket.framed(DhtCodec).split();

            // start receiving/sending packets
            let receiver = receive_packets(stream);
            let sender = send_packets(sink);

            let dps_send = dps.clone();
            for dp in dps_send {
                let tx = sender.clone();
                let send = tx.send((b_addr, dp)).then(|_| Ok(()));
                handle.spawn(send);
            }

            let f_recv = receiver.take(dps.len() as u64).collect();
            let received = core.run(f_recv).expect("receive error");

            for (n, &(ref addr, ref packet)) in received.iter().enumerate() {
                assert_eq!(a_addr, *addr);
                assert_eq!(dps[n], *packet);
            }

            TestResult::passed()
        }
    }
}
