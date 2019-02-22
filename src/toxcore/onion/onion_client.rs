//! Onion client implementation.

use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use failure::Fail;
use futures::{Future, Stream, future, stream};
use futures::future::Either;
use futures::sync::mpsc;
use parking_lot::RwLock;
use tokio::timer::Interval;

use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packed_node::PackedNode;
use crate::toxcore::dht::packet::*;
use crate::toxcore::dht::server::{Server as DhtServer};
use crate::toxcore::dht::kbucket::*;
use crate::toxcore::io_tokio::*;
use crate::toxcore::ip_port::*;
use crate::toxcore::onion::onion_announce::initial_ping_id;
use crate::toxcore::onion::onion_path::*;
use crate::toxcore::onion::packet::*;
use crate::toxcore::onion::paths_pool::*;
use crate::toxcore::onion::request_queue::RequestQueue;
use crate::toxcore::packed_node::*;
use crate::toxcore::tcp::client::{Connections as TcpConnections};
use crate::toxcore::time::*;

/// Shorthand for the transmit half of the message channel for sending DHT
/// `PublicKey` when it gets known. The first key is a long term key, the second
/// key is a DHT key.
type DhtPkTx = mpsc::UnboundedSender<(PublicKey, PublicKey)>;

/// Number of friend's close nodes to store.
const MAX_ONION_FRIEND_NODES: u8 = 8;

/// Number of nodes to announce ourselves to.
const MAX_ONION_ANNOUNCE_NODES: u8 = 12;

/// Timeout for onion announce packets.
const ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many attempts to reach a node we should make.
const ONION_NODE_MAX_PINGS: u32 = 3;

/// How often to ping a node (announce or friend searching).
const ONION_NODE_PING_INTERVAL: u64 = 15;

/// After this time since last unsuccessful ping (and when ping attempts are
/// exhausted) node is considered timed out.
const ONION_NODE_TIMEOUT: u64 = ONION_NODE_PING_INTERVAL;

/// After this interval since creation node is considered stable.
const TIME_TO_STABLE: u64 = ONION_NODE_PING_INTERVAL * 6;

/// The interval in seconds at which to tell our friends our DHT `PublicKey`
/// via onion.
const ONION_DHTPK_SEND_INTERVAL: u64 = 30;

/// The interval in seconds at which to tell our friends our DHT `PublicKey`
/// via DHT request.
const DHT_DHTPK_SEND_INTERVAL: u64 = 20;

const MIN_NODE_PING_TIME: u64 = 10;

#[derive(Clone, Debug)]
struct OnionFriend {
    /// Friend's long term `PublicKey`.
    real_pk: PublicKey,
    /// Friend's DHT `PublicKey` if it's known.
    dht_pk: Option<PublicKey>,
    /// Temporary `PublicKey` that should be used to encrypt search requests for
    /// this friend.
    temporary_pk: PublicKey,
    /// Temporary `SecretKey` that should be used to encrypt search requests for
    /// this friend.
    temporary_sk: SecretKey,
    /// List of nodes close to friend's long term `PublicKey`.
    close_nodes: Kbucket<OnionNode>,
    /// `no_reply` from last DHT `PublicKey` announce packet used to prevent
    /// reply attacks.
    last_no_reply: u64,
    /// Time when our DHT `PublicKey` was sent to this friend via onion last
    /// time.
    last_dht_pk_onion_sent: Option<Instant>,
    /// Time when our DHT `PublicKey` was sent to this friend via DHT request
    /// last time.
    last_dht_pk_dht_sent: Option<Instant>,
}

impl OnionFriend {
    /// Create new `OnionFriend`.
    pub fn new(real_pk: PublicKey) -> Self {
        let (temporary_pk, temporary_sk) = gen_keypair();
        OnionFriend {
            real_pk,
            dht_pk: None,
            temporary_pk,
            temporary_sk,
            close_nodes: Kbucket::new(MAX_ONION_FRIEND_NODES),
            last_no_reply: 0,
            last_dht_pk_onion_sent: None,
            last_dht_pk_dht_sent: None,
        }
    }
}

#[derive(Clone, Debug)]
struct OnionNode {
    /// Node's `PublicKey`.
    pk: PublicKey,
    /// Node's IP address.
    saddr: SocketAddr,
    /// Path used to send packets to this node.
    path_id: OnionPathId,
    /// Ping id that should be used to announce to this node.
    ping_id: Option<sha256::Digest>,
    /// Data `PublicKey` that should be used to send data packets to our friend
    /// through this node.
    data_pk: Option<PublicKey>,
    /// Number of announce requests sent to this node without any response.
    /// Resets to 0 after receiving a response.
    unsuccessful_pings: u32,
    /// Time when this node was added to close nodes list.
    added_time: Instant,
    /// Time when the last announce packet was sent to this node.
    ping_time: Instant,
    /// Announce status from last response from this node.
    announce_status: AnnounceStatus,
}

impl HasPK for OnionNode {
    fn pk(&self) -> PublicKey {
        self.pk
    }
}

impl KbucketNode for OnionNode {
    type NewNode = OnionNode;
    type CheckNode = PackedNode;

    fn is_outdated(&self, other: &PackedNode) -> bool {
        self.saddr != other.saddr
    }
    fn update(&mut self, other: &OnionNode) {
        self.saddr = other.saddr;
        self.path_id = other.path_id;
        self.ping_id = other.ping_id.or(self.ping_id);
        self.data_pk = other.data_pk.or(self.data_pk);
        self.announce_status = other.announce_status;
    }
    fn is_evictable(&self) -> bool {
        self.is_timed_out()
    }
}

impl OnionNode {
    /// Check if the next ping attempt is the last one.
    pub fn is_last_ping_attempt(&self) -> bool {
        self.unsuccessful_pings == ONION_NODE_MAX_PINGS - 1
    }

    /// Check if ping attempts to this node are exhausted.
    pub fn is_ping_attempts_exhausted(&self) -> bool {
        self.unsuccessful_pings >= ONION_NODE_MAX_PINGS
    }

    /// Check if this node is timed out.
    pub fn is_timed_out(&self) -> bool {
        self.is_ping_attempts_exhausted() &&
            clock_elapsed(self.ping_time) >= Duration::from_secs(ONION_NODE_TIMEOUT)
    }

    /// Node is considered stable after `TIME_TO_STABLE` seconds since it was
    /// added to a close list.
    pub fn is_stable(&self) -> bool {
        clock_elapsed(self.added_time) >= Duration::from_secs(TIME_TO_STABLE)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AnnounceRequestData {
    /// `PublicKey` of node to which we sent a packet.
    pk: PublicKey,
    /// IP address of node to which we sent a packet.
    saddr: SocketAddr,
    /// Path used to send announce request packet.
    path_id: OnionPathId,
    /// Friend's long term `PublicKey` if announce request was searching
    /// request.
    friend_pk: Option<PublicKey>,
}

/// Announce packet data that doesn't depend on destination node.
#[derive(Clone, Debug, Eq, PartialEq)]
struct AnnouncePacketData<'a> {
    /// `SecretKey` used to encrypt and decrypt announce packets.
    packet_sk: &'a SecretKey,
    /// `PublicKey` used to encrypt and decrypt announce packets.
    packet_pk: PublicKey,
    /// Key that should be used to search close nodes.
    search_pk: PublicKey,
    /// `PublicKey` key that should be used to send data packets to us.
    data_pk: Option<PublicKey>,
}

impl<'a> AnnouncePacketData<'a> {
    /// Create `InnerOnionAnnounceRequest`.
    pub fn request(&self, node_pk: &PublicKey, ping_id: Option<sha256::Digest>, request_id: u64) -> InnerOnionAnnounceRequest {
        let payload = OnionAnnounceRequestPayload {
            ping_id: ping_id.unwrap_or_else(initial_ping_id),
            search_pk: self.search_pk,
            data_pk: self.data_pk.unwrap_or(PublicKey([0; 32])),
            sendback_data: request_id,
        };
        InnerOnionAnnounceRequest::new(
            &precompute(node_pk, self.packet_sk),
            &self.packet_pk,
            &payload
        )
    }
}

/// Onion client state.
#[derive(Clone, Debug)]
struct OnionClientState {
    /// Pool of random onion paths.
    paths_pool: PathsPool,
    /// List of nodes we announce ourselves to.
    announce_list: Kbucket<OnionNode>,
    /// Struct that stores and manages requests IDs and timeouts.
    announce_requests: RequestQueue<AnnounceRequestData>,
    /// List of friends we are looking for.
    friends: HashMap<PublicKey, OnionFriend>,
}

impl OnionClientState {
    pub fn new() -> Self {
        OnionClientState {
            paths_pool: PathsPool::new(),
            announce_list: Kbucket::new(MAX_ONION_ANNOUNCE_NODES),
            announce_requests: RequestQueue::new(ANNOUNCE_TIMEOUT),
            friends: HashMap::new(),
        }
    }
}

/// Onion client that is responsible for announcing our DHT `PublicKey` to our
/// friends and looking for their DHT `PublicKey`s.
#[derive(Clone)]
pub struct OnionClient {
    /// DHT server instance.
    dht: DhtServer,
    /// TCP connections instance.
    tcp_connections: TcpConnections,
    /// Sink to send DHT `PublicKey` when it gets known. The first key is a long
    /// term key, the second key is a DHT key.
    dht_pk_tx: DhtPkTx,
    /// Our long term `SecretKey`.
    real_sk: SecretKey,
    /// Our long term `PublicKey`.
    real_pk: PublicKey,
    /// `SecretKey` for data packets that we can accept.
    data_sk: SecretKey,
    /// `PublicKey` that should be used to encrypt data packets that we can
    /// accept.
    data_pk: PublicKey,
    /// Onion client state.
    state: Arc<RwLock<OnionClientState>>, // TODO: mutex?
}

impl OnionClient {
    /// Create new `OnionClient`.
    pub fn new(
        dht: DhtServer,
        tcp_connections: TcpConnections,
        dht_pk_tx: DhtPkTx,
        real_sk: SecretKey,
        real_pk: PublicKey
    ) -> Self {
        let (data_pk, data_sk) = gen_keypair();
        OnionClient {
            dht,
            tcp_connections,
            dht_pk_tx,
            real_sk,
            real_pk,
            data_sk,
            data_pk,
            state: Arc::new(RwLock::new(OnionClientState::new())),
        }
    }

    fn is_redundant_ping(pk: PublicKey, search_pk: PublicKey, request_queue: &RequestQueue<AnnounceRequestData>) -> bool {
        let check_pks = |data: &AnnounceRequestData| -> bool {
            if let Some(friend_pk) = data.friend_pk {
                data.pk == pk && search_pk == friend_pk
            } else {
                data.pk == pk
            }
        };
        let request = request_queue.find(check_pks);
        if let Some((ping_time, _request_data)) = request {
            clock_elapsed(*ping_time) < Duration::from_secs(MIN_NODE_PING_TIME)
        } else {
            false
        }
    }

    /// Handle `OnionAnnounceResponse` packet.
    pub fn handle_announce_response(&self, packet: &OnionAnnounceResponse, _addr: SocketAddr) -> Box<Future<Item = (), Error = Error> + Send> {
        let state = &mut *self.state.write();

        let announce_data = if let Some(announce_data) = state.announce_requests.check_ping_id(packet.sendback_data) {
            announce_data
        } else {
            return Box::new(future::err(Error::new(ErrorKind::Other, "handle_announce_response: invalid request id")))
        };

        // Assign variables depending on response type (was it announcing or searching request)
        let (nodes_list, announce_packet_data) = if let Some(ref friend_pk) = announce_data.friend_pk {
            if let Some(friend) = state.friends.get_mut(friend_pk) {
                let announce_packet_data = AnnouncePacketData {
                    packet_sk: &friend.temporary_sk,
                    packet_pk: friend.temporary_pk,
                    search_pk: friend.real_pk,
                    data_pk: None,
                };
                (&mut friend.close_nodes, announce_packet_data)
            } else {
                return Box::new(future::err(Error::new(ErrorKind::Other, "handle_announce_response: no friend with such pk")))
            }
        } else {
            let announce_packet_data = AnnouncePacketData {
                packet_sk: &self.real_sk,
                packet_pk: self.real_pk,
                search_pk: self.real_pk,
                data_pk: Some(self.data_pk),
            };
            (&mut state.announce_list, announce_packet_data)
        };

        let payload = match packet.get_payload(&precompute(&announce_data.pk, announce_packet_data.packet_sk)) {
            Ok(payload) => payload,
            Err(e) => return Box::new(future::err(Error::new(ErrorKind::Other, e.compat())))
        };

        trace!("OnionAnnounceResponse status: {:?}, data: {:?}", payload.announce_status, announce_data);

        state.paths_pool.set_timeouts(announce_data.path_id, announce_data.friend_pk.is_some());

        let (ping_id, data_pk) = if payload.announce_status == AnnounceStatus::Found {
            (None, Some(digest_as_pk(payload.ping_id_or_pk)))
        } else {
            (Some(payload.ping_id_or_pk), None)
        };

        let now = clock_now();
        nodes_list.try_add(&announce_packet_data.search_pk, OnionNode {
            pk: announce_data.pk,
            saddr: announce_data.saddr,
            path_id: announce_data.path_id,
            ping_id,
            data_pk,
            unsuccessful_pings: 0,
            added_time: now,
            ping_time: now,
            announce_status: payload.announce_status,
        }, /* evict */ true);

        state.paths_pool.path_nodes.put(PackedNode::new(announce_data.saddr, &announce_data.pk));

        let mut futures = Vec::with_capacity(payload.nodes.len());

        for node in &payload.nodes {
            if !nodes_list.can_add(&announce_packet_data.search_pk, &node, /* evict */ true) {
                continue;
            }

            // To prevent to send redundant ping packet.
            if OnionClient::is_redundant_ping(node.pk, announce_packet_data.search_pk, &state.announce_requests) {
                continue;
            }

            let path = if let Some(path) = state.paths_pool.random_path(announce_data.friend_pk.is_some()) {
                path
            } else {
                continue
            };

            let request_id = state.announce_requests.new_ping_id(AnnounceRequestData {
                pk: node.pk,
                saddr: node.saddr,
                path_id: path.id(),
                friend_pk: announce_data.friend_pk,
            });

            let inner_announce_request = announce_packet_data.request(&node.pk, None, request_id);
            let onion_request = path.create_onion_request(node.saddr, InnerOnionRequest::InnerOnionAnnounceRequest(inner_announce_request));

            futures.push(send_to(&self.dht.tx, (Packet::OnionRequest0(onion_request), path.nodes[0].saddr)));
        }

        Box::new(future::join_all(futures)
            .map(|_| ())
            .map_err(|e| Error::new(ErrorKind::Other, e)))
    }

    /// Handle DHT `PublicKey` announce from both onion and DHT.
    pub fn handle_dht_pk_announce(&self, friend_pk: PublicKey, dht_pk_announce: DhtPkAnnouncePayload) -> Box<Future<Item = (), Error = Error> + Send> {
        let mut state = self.state.write();

        let friend = match state.friends.get_mut(&friend_pk) {
            Some(friend) => friend,
            None => return Box::new(future::err(Error::new(ErrorKind::Other, "handle_dht_pk_announce: no friend with such pk")))
        };

        if dht_pk_announce.no_reply <= friend.last_no_reply {
            return Box::new(future::err(Error::new(ErrorKind::Other, "handle_dht_pk_announce: invalid no_reply")))
        }

        friend.last_no_reply = dht_pk_announce.no_reply;
        friend.dht_pk = Some(dht_pk_announce.dht_pk);
        // last_seen?

        let dht_pk_future = send_to(&self.dht_pk_tx, (friend_pk, dht_pk_announce.dht_pk));

        let futures = dht_pk_announce.nodes.into_iter().map(|node| match node.ip_port.protocol {
            ProtocolType::UDP => {
                let packed_node = PackedNode::new(node.ip_port.to_saddr(), &node.pk);
                Either::A(self.dht.ping_node(&packed_node).map_err(|e| Error::new(ErrorKind::Other, e.compat())))
            },
            ProtocolType::TCP => {
                Either::B(self.tcp_connections.add_relay_connection(node.ip_port.to_saddr(), node.pk, friend_pk))
            }
        }).collect::<Vec<_>>();

        Box::new(dht_pk_future
            .map_err(|e| Error::new(ErrorKind::Other, e))
            .join(future::join_all(futures).map(|_| ()))
            .map(|_| ()))
    }

    /// Handle `OnionDataResponse` packet.
    pub fn handle_data_response(&self, packet: &OnionDataResponse) -> Box<Future<Item = (), Error = Error> + Send> {
        let payload = match packet.get_payload(&precompute(&packet.temporary_pk, &self.data_sk)) {
            Ok(payload) => payload,
            Err(e) => return Box::new(future::err(Error::new(ErrorKind::Other, e.compat())))
        };
        let iner_payload = match payload.get_payload(&packet.nonce, &precompute(&payload.real_pk, &self.real_sk)) {
            Ok(payload) => payload,
            Err(e) => return Box::new(future::err(Error::new(ErrorKind::Other, e.compat())))
        };
        match iner_payload {
            OnionDataResponseInnerPayload::DhtPkAnnounce(dht_pk_announce) => self.handle_dht_pk_announce(payload.real_pk, dht_pk_announce)
        }
    }

    /// Add new node to random nodes pool to use them to build random paths.
    pub fn add_path_node(&self, node: PackedNode) {
        let mut state = self.state.write();

        state.paths_pool.path_nodes.put(node);
    }

    /// Add new node to random nodes pool to use them to build random paths.
    pub fn add_friend(&self, real_pk: PublicKey) {
        let mut state = self.state.write();

        state.friends.insert(real_pk, OnionFriend::new(real_pk));
    }

    fn ping_close_nodes(
        close_nodes: &mut Kbucket<OnionNode>,
        paths_pool: &mut PathsPool,
        announce_requests: &mut RequestQueue<AnnounceRequestData>,
        announce_packet_data: AnnouncePacketData,
        friend_pk: Option<PublicKey>
    ) -> Vec<(Packet, SocketAddr)> {
        let mut packets = Vec::new();

        let mut good_nodes_count = 0;

        for node in close_nodes.iter_mut() {
            if !node.is_timed_out() {
                good_nodes_count += 1;
            }

            if node.is_ping_attempts_exhausted() {
                continue;
            }

            // TODO: smart interval calculation?
            if clock_elapsed(node.ping_time) >= Duration::from_secs(ONION_NODE_PING_INTERVAL) {
                // Last chance for a long-lived node
                let path = if node.is_last_ping_attempt() && node.is_stable() {
                    paths_pool.random_path(friend_pk.is_some())
                } else {
                    paths_pool.get_path(node.path_id, friend_pk.is_some())
                };

                let path = if let Some(path) = path {
                    path
                } else {
                    continue
                };

                node.unsuccessful_pings += 1;
                node.ping_time = clock_now();

                let request_id = announce_requests.new_ping_id(AnnounceRequestData {
                    pk: node.pk,
                    saddr: node.saddr,
                    path_id: path.id(),
                    friend_pk,
                });

                let inner_announce_request = announce_packet_data.request(&node.pk, node.ping_id, request_id);
                let onion_request = path.create_onion_request(node.saddr, InnerOnionRequest::InnerOnionAnnounceRequest(inner_announce_request));

                packets.push((Packet::OnionRequest0(onion_request), path.nodes[0].saddr));
            }
        }

        if good_nodes_count <= random_limit_usize(close_nodes.capacity()) {
            for _ in 0 .. close_nodes.capacity() / 2 {
                let node = if let Some(node) = paths_pool.path_nodes.rand() {
                    node
                } else {
                    break
                };

                let path = if let Some(path) = paths_pool.random_path(friend_pk.is_some()) {
                    path
                } else {
                    break
                };

                let request_id = announce_requests.new_ping_id(AnnounceRequestData {
                    pk: node.pk,
                    saddr: node.saddr,
                    path_id: path.id(),
                    friend_pk,
                });

                let inner_announce_request = announce_packet_data.request(&node.pk, None, request_id);
                let onion_request = path.create_onion_request(node.saddr, InnerOnionRequest::InnerOnionAnnounceRequest(inner_announce_request));

                packets.push((Packet::OnionRequest0(onion_request), path.nodes[0].saddr));
            }
        }

        packets
    }

    fn announce_loop(&self, state: &mut OnionClientState) -> Box<Future<Item = (), Error = Error> + Send> {
        let announce_packet_data = AnnouncePacketData {
            packet_sk: &self.real_sk,
            packet_pk: self.real_pk,
            search_pk: self.real_pk,
            data_pk: Some(self.data_pk),
        };

        let packets = OnionClient::ping_close_nodes(
            &mut state.announce_list,
            &mut state.paths_pool,
            &mut state.announce_requests,
            announce_packet_data,
            None,
        );

        Box::new(
            send_all_to(&self.dht.tx, stream::iter_ok(packets))
                .map_err(|e| Error::new(ErrorKind::Other, e.compat()))
        )
    }

    /// Get nodes to include to DHT `PublicKey` announcement packet.
    fn dht_pk_nodes(&self) -> Vec<TcpUdpPackedNode> {
        let relays = self.tcp_connections.get_relays(2);
        let close_nodes: Vec<PackedNode> = self.dht.get_closest(&self.dht.pk, 4 - relays.len() as u8, true).into();
        relays.into_iter().map(|node| TcpUdpPackedNode {
            pk: node.pk,
            ip_port: IpPort::from_tcp_saddr(node.saddr),
        }).chain(close_nodes.into_iter().map(|node| TcpUdpPackedNode {
            pk: node.pk,
            ip_port: IpPort::from_udp_saddr(node.saddr),
        })).collect()
    }

    fn friends_loop(&self, state: &mut OnionClientState) -> Box<Future<Item = (), Error = Error> + Send> {
        let mut packets = Vec::new();

        for friend in state.friends.values_mut() {
            // TODO: if is_online

            let announce_packet_data = AnnouncePacketData {
                packet_sk: &friend.temporary_sk,
                packet_pk: friend.temporary_pk,
                search_pk: friend.real_pk,
                data_pk: None,
            };

            let friend_packets = OnionClient::ping_close_nodes(
                &mut friend.close_nodes,
                &mut state.paths_pool,
                &mut state.announce_requests,
                announce_packet_data,
                Some(friend.real_pk),
            );

            packets.extend(friend_packets);

            // Send DHT PublicKey via onion request
            if friend.last_dht_pk_onion_sent.map_or(true, |time| clock_elapsed(time) > Duration::from_secs(ONION_DHTPK_SEND_INTERVAL)) {
                let dht_pk_announce = DhtPkAnnouncePayload::new(self.dht.pk, self.dht_pk_nodes());
                let inner_payload = OnionDataResponseInnerPayload::DhtPkAnnounce(dht_pk_announce);
                let nonce = gen_nonce();
                let payload = OnionDataResponsePayload::new(&precompute(&friend.real_pk, &self.real_sk), self.real_pk, &nonce, &inner_payload);

                let packets_len = packets.len();

                for node in friend.close_nodes.iter() {
                    if node.is_timed_out() {
                        continue;
                    }

                    let data_pk = if let Some(data_pk) = node.data_pk {
                        data_pk
                    } else {
                        continue
                    };

                    let path = state.paths_pool.get_path(node.path_id, true);

                    let path = if let Some(path) = path {
                        path
                    } else {
                        continue
                    };

                    let (temporary_pk, temporary_sk) = gen_keypair();
                    let inner_data_request = InnerOnionDataRequest::new(&precompute(&data_pk, &temporary_sk), friend.real_pk, temporary_pk, nonce, &payload);

                    let onion_request = path.create_onion_request(node.saddr, InnerOnionRequest::InnerOnionDataRequest(inner_data_request));

                    packets.push((Packet::OnionRequest0(onion_request), path.nodes[0].saddr));
                }

                if packets.len() != packets_len {
                    friend.last_dht_pk_onion_sent = Some(clock_now());
                }
            }

            // Send DHT PublicKey via DHT request
            if let Some(friend_dht_pk) = friend.dht_pk {
                if friend.last_dht_pk_dht_sent.map_or(true, |time| clock_elapsed(time) > Duration::from_secs(DHT_DHTPK_SEND_INTERVAL)) {
                    let dht_pk_announce_payload = DhtPkAnnouncePayload::new(self.dht.pk, self.dht_pk_nodes());
                    let dht_pk_announce = DhtPkAnnounce::new(&precompute(&friend.real_pk, &self.real_sk), self.real_pk, &dht_pk_announce_payload);
                    let payload = DhtRequestPayload::DhtPkAnnounce(dht_pk_announce);
                    let packet = DhtRequest::new(&precompute(&friend_dht_pk, &self.dht.sk), &friend_dht_pk, &self.dht.pk, &payload);
                    let packet = Packet::DhtRequest(packet);

                    let nodes = self.dht.get_closest(&friend_dht_pk, 8, false);

                    if !nodes.is_empty() {
                        friend.last_dht_pk_dht_sent = Some(clock_now());
                    }

                    packets.extend(nodes.iter().map(|node| (packet.clone(), node.saddr)));
                }
            }
        }

        Box::new(
            send_all_to(&self.dht.tx, stream::iter_ok(packets))
                .map_err(|e| Error::new(ErrorKind::Other, e.compat()))
        )
    }

    /// Run periodical announcements and friends searching.
    pub fn run(self) -> impl Future<Item = (), Error = Error> + Send {
        let interval = Duration::from_secs(1);
        let wakeups = Interval::new(Instant::now(), interval);
        wakeups
            .map_err(|e| Error::new(ErrorKind::Other, e))
            .for_each(move |_instant| {
                trace!("Onion client sender wake up");
                let mut state = self.state.write();
                let announce_future = self.announce_loop(&mut state);
                let friends_future = self.friends_loop(&mut state);
                announce_future.join(friends_future).map(|_| ())
            })
    }
}
