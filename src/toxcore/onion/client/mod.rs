//! Onion client implementation.

mod errors;
mod nodes_pool;
mod onion_path;
mod paths_pool;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use failure::Fail;
use futures::{Future, FutureExt, TryFutureExt, StreamExt, TryStreamExt, SinkExt, future};
use futures::future::Either;
use futures::channel::mpsc;
use parking_lot::Mutex;

use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::ip_port::IsGlobal;
use crate::toxcore::dht::packed_node::PackedNode;
use crate::toxcore::dht::packet::*;
use crate::toxcore::dht::request_queue::RequestQueue;
use crate::toxcore::dht::server::{Server as DhtServer};
use crate::toxcore::dht::kbucket::*;
use crate::toxcore::ip_port::*;
use crate::toxcore::onion::client::errors::*;
use crate::toxcore::onion::client::onion_path::*;
use crate::toxcore::onion::client::paths_pool::*;
use crate::toxcore::onion::onion_announce::initial_ping_id;
use crate::toxcore::onion::packet::*;
use crate::toxcore::packed_node::*;
use crate::toxcore::tcp::client::{Connections as TcpConnections};
use crate::toxcore::time::*;
use crate::toxcore::io_tokio::*;

/// Shorthand for the transmit half of the message channel for sending DHT
/// `PublicKey` when it gets known. The first key is a long term key, the second
/// key is a DHT key.
type DhtPkTx = mpsc::UnboundedSender<(PublicKey, PublicKey)>;

/// Shorthand for the transmit half of the message channel for sending friend
/// requests when we get them. The key is a long term key.
type FriendRequestTx = mpsc::UnboundedSender<(PublicKey, FriendRequest)>;

/// Number of friend's close nodes to store.
const MAX_ONION_FRIEND_NODES: u8 = 8;

/// Number of nodes to announce ourselves to.
const MAX_ONION_ANNOUNCE_NODES: u8 = 12;

/// Timeout for onion announce packets.
const ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many attempts to reach a node we should make.
const ONION_NODE_MAX_PINGS: u32 = 3;

/// How often to ping a node (announce or friend searching).
const ONION_NODE_PING_INTERVAL: Duration = Duration::from_secs(15);

/// How often we should announce ourselves to a node we are not announced to.
const ANNOUNCE_INTERVAL_NOT_ANNOUNCED: Duration = Duration::from_secs(3);

/// How often we should announce ourselves to a node we are announced to.
const ANNOUNCE_INTERVAL_ANNOUNCED: Duration = ONION_NODE_PING_INTERVAL;

/// How often we should announce ourselves to a node we are announced to when
/// it's considered stable.
const ANNOUNCE_INTERVAL_STABLE: Duration = Duration::from_secs(ONION_NODE_PING_INTERVAL.as_secs() * 8);

/// How often we should search a friend.
const ANNOUNCE_FRIEND: Duration = Duration::from_secs(ONION_NODE_PING_INTERVAL.as_secs() * 6);

/// How often we should search a friend right after it was added to the friends
/// list.
const ANNOUNCE_FRIEND_BEGINNING: Duration = Duration::from_secs(3);

/// After this amount of searches we switch from `ANNOUNCE_FRIEND_BEGINNING`
/// to `ANNOUNCE_FRIEND` interval.
const SEARCH_COUNT_FRIEND_ANNOUNCE_BEGINNING: u32 = 17;

/// Longer we didn't see a friend less often we will look for him. This const
/// defines proportion between the search interval and the time we didn't see a
/// friend.
const ONION_FRIEND_BACKOFF_FACTOR: u32 = 4;

/// Maximum interval for friends searching.
const ONION_FRIEND_MAX_PING_INTERVAL: Duration =
    Duration::from_secs(MAX_ONION_FRIEND_NODES as u64 * 60 * 5);

/// After this time since last unsuccessful ping (and when ping attempts are
/// exhausted) node is considered timed out.
const ONION_NODE_TIMEOUT: Duration = ONION_NODE_PING_INTERVAL;

/// After this interval since creation node is considered stable.
pub(crate) const TIME_TO_STABLE: Duration = Duration::from_secs(ONION_NODE_PING_INTERVAL.as_secs() * 6);

/// The interval of time at which to tell our friends our DHT `PublicKey`
/// via onion.
const ONION_DHTPK_SEND_INTERVAL: Duration = Duration::from_secs(30);

/// The interval of time at which to tell our friends our DHT `PublicKey`
/// via DHT request.
const DHT_DHTPK_SEND_INTERVAL: Duration = Duration::from_secs(20);

/// Minimum interval for sending requests to received in `OnionAnnounceResponse`
/// packet nodes.
const MIN_NODE_PING_TIME: Duration = Duration::from_secs(10);

/// Friend related data stored in the onion client.
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
    /// How many times we sent search requests to friend's close nodes.
    search_count: u32,
    /// Time when this friend was seen online last time
    last_seen: Option<Instant>,
    /// Whether we connected to this friend.
    connected: bool,
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
            search_count: 0,
            last_seen: None,
            connected: false,
        }
    }
}

/// Type for onion close nodes.
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
    /// Time when we received the last response from this node.
    response_time: Instant,
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
        assert_eq!(self.pk, other.pk);
        self.saddr != other.saddr
    }
    fn update(&mut self, other: &OnionNode) {
        assert_eq!(self.pk, other.pk);
        self.saddr = other.saddr;
        self.path_id = other.path_id;
        self.ping_id = other.ping_id.or(self.ping_id);
        self.data_pk = other.data_pk.or(self.data_pk);
        self.unsuccessful_pings = 0;
        self.response_time = clock_now();
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
        self.is_ping_attempts_exhausted() && clock_elapsed(self.ping_time) >= ONION_NODE_TIMEOUT
    }

    /// Node is considered stable after `TIME_TO_STABLE` since it was
    /// added to a close list if it responses to our requests.
    pub fn is_stable(&self) -> bool {
        clock_elapsed(self.added_time) >= TIME_TO_STABLE &&
            (self.unsuccessful_pings == 0 || clock_elapsed(self.ping_time) < ONION_NODE_TIMEOUT)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AnnounceRequestData {
    /// `PublicKey` of the node to which we sent a packet.
    pk: PublicKey,
    /// IP address of the node to which we sent a packet.
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
    /// Create `InnerOnionAnnounceRequest`. The request is a search request if
    /// pind_id is 0 and an announce request otherwise.
    fn request(&self, node_pk: &PublicKey, ping_id: Option<sha256::Digest>, request_id: u64) -> InnerOnionAnnounceRequest {
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
    /// Create `InnerOnionAnnounceRequest` for a search request.
    pub fn search_request(&self, node_pk: &PublicKey, request_id: u64) -> InnerOnionAnnounceRequest {
        self.request(node_pk, None, request_id)
    }
    /// Create `InnerOnionAnnounceRequest` for an announce request.
    pub fn announce_request(&self, node_pk: &PublicKey, ping_id: sha256::Digest, request_id: u64) -> InnerOnionAnnounceRequest {
        self.request(node_pk, Some(ping_id), request_id)
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
    /// Sink to send DHT `PublicKey` when it gets known. The first key is a long
    /// term key, the second key is a DHT key.
    dht_pk_tx: Option<DhtPkTx>,
    /// Sink to send friend requests when we get them. The key is a long term
    /// key.
    friend_request_tx: Option<FriendRequestTx>,
}

impl OnionClientState {
    pub fn new() -> Self {
        OnionClientState {
            paths_pool: PathsPool::new(),
            announce_list: Kbucket::new(MAX_ONION_ANNOUNCE_NODES),
            announce_requests: RequestQueue::new(ANNOUNCE_TIMEOUT),
            friends: HashMap::new(),
            dht_pk_tx: None,
            friend_request_tx: None,
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
    state: Arc<Mutex<OnionClientState>>,
}

impl OnionClient {
    /// Create new `OnionClient`.
    pub fn new(
        dht: DhtServer,
        tcp_connections: TcpConnections,
        real_sk: SecretKey,
        real_pk: PublicKey
    ) -> Self {
        let (data_pk, data_sk) = gen_keypair();
        OnionClient {
            dht,
            tcp_connections,
            real_sk,
            real_pk,
            data_sk,
            data_pk,
            state: Arc::new(Mutex::new(OnionClientState::new())),
        }
    }

    /// Set sink to send DHT `PublicKey` when it gets known.
    pub fn set_dht_pk_sink(&self, dht_pk_tx: DhtPkTx) {
        self.state.lock().dht_pk_tx = Some(dht_pk_tx);
    }

    /// Set sink to receive `FriendRequest`s.
    pub fn set_friend_request_sink(&self, friend_request_sink: FriendRequestTx) {
        self.state.lock().friend_request_tx = Some(friend_request_sink)
    }

    /// Check if a node was pinged recently.
    fn is_pinged_recently(&self, pk: PublicKey, search_pk: PublicKey, request_queue: &RequestQueue<AnnounceRequestData>) -> bool {
        let check_pks = |data: &AnnounceRequestData| -> bool {
            let request_search_pk = if let Some(friend_pk) = data.friend_pk {
                friend_pk
            } else {
                self.real_pk
            };
            data.pk == pk && search_pk == request_search_pk
        };
        request_queue.get_values()
            .any(|(ping_time, request_data)| check_pks(request_data) &&
                clock_elapsed(ping_time) < MIN_NODE_PING_TIME)
    }

    /// Send onion request via TCP or UDP depending on path.
    fn send_onion_request(&self, path: OnionPath, inner_onion_request: InnerOnionRequest, saddr: SocketAddr)
        -> impl Future<Output = Result<(), mpsc::SendError>> + Send {
        match path.path_type {
            OnionPathType::TCP => {
                let onion_request = path.create_tcp_onion_request(saddr, inner_onion_request);
                // TODO: can we handle errors better? Right now we can try send a
                // request to a non-existent or suspended node which returns an error
                Either::Left(
                    self.tcp_connections.send_onion(path.nodes[0].public_key, onion_request)
                        .then(future::ok)
                        .map_ok(drop)
                )
            },
            OnionPathType::UDP => {
                let onion_request =
                    path.create_udp_onion_request(saddr, inner_onion_request);
                let mut tx = self.dht.tx.clone();

                Either::Right(async move {
                    tx.send((
                        Packet::OnionRequest0(onion_request),
                        path.nodes[0].saddr
                    )).await
                })
            },
        }
    }

    /// Handle `OnionAnnounceResponse` packet.
    pub fn handle_announce_response(&self, packet: &OnionAnnounceResponse, is_global: bool) -> impl Future<Output = Result<(), HandleAnnounceResponseError>> + Send {
        let state = &mut *self.state.lock();

        let announce_data = if let Some(announce_data) = state.announce_requests.check_ping_id(packet.sendback_data, |_| true) {
            announce_data
        } else {
            return Either::Left(future::err(HandleAnnounceResponseErrorKind::InvalidRequestId.into()))
        };

        // Assign variables depending on response type (was it announcing or searching request)
        let (nodes_list, last_seen, announce_packet_data) = if let Some(ref friend_pk) = announce_data.friend_pk {
            if let Some(friend) = state.friends.get_mut(friend_pk) {
                let announce_packet_data = AnnouncePacketData {
                    packet_sk: &friend.temporary_sk,
                    packet_pk: friend.temporary_pk,
                    search_pk: friend.real_pk,
                    data_pk: None,
                };
                (&mut friend.close_nodes, Some(&mut friend.last_seen), announce_packet_data)
            } else {
                return Either::Left(future::err(HandleAnnounceResponseErrorKind::NoFriendWithPk.into()))
            }
        } else {
            let announce_packet_data = AnnouncePacketData {
                packet_sk: &self.real_sk,
                packet_pk: self.real_pk,
                search_pk: self.real_pk,
                data_pk: Some(self.data_pk),
            };
            (&mut state.announce_list, None, announce_packet_data)
        };

        let payload = match packet.get_payload(&precompute(&announce_data.pk, announce_packet_data.packet_sk)) {
            Ok(payload) => payload,
            Err(e) => return Either::Left(future::err(e.context(HandleAnnounceResponseErrorKind::InvalidPayload).into()))
        };

        trace!("OnionAnnounceResponse status: {:?}, data: {:?}", payload.announce_status, announce_data);

        if announce_data.friend_pk.is_some() && payload.announce_status == AnnounceStatus::Announced ||
            announce_data.friend_pk.is_none() && payload.announce_status == AnnounceStatus::Found {
            return Either::Left(future::err(HandleAnnounceResponseErrorKind::InvalidAnnounceStatus.into()));
        }

        state.paths_pool.set_timeouts(announce_data.path_id, announce_data.friend_pk.is_some());

        if payload.announce_status == AnnounceStatus::Found {
            if let Some(last_seen) = last_seen {
                *last_seen = Some(clock_now());
            }
        }

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
            response_time: now,
            announce_status: payload.announce_status,
        }, /* evict */ true);

        state.paths_pool.path_nodes.put(PackedNode::new(announce_data.saddr, &announce_data.pk));

        let mut futures = Vec::with_capacity(payload.nodes.len());

        for node in &payload.nodes {
            // skip LAN nodes if the packet wasn't received from LAN
            if !IsGlobal::is_global(&node.ip()) && is_global {
                continue;
            }

            // do not ping nodes that was pinged recently
            if self.is_pinged_recently(node.pk, announce_packet_data.search_pk, &state.announce_requests) {
                continue;
            }

            if !nodes_list.can_add(&announce_packet_data.search_pk, &node, /* evict */ true) {
                continue;
            }

            let path = if let Some(path) = state.paths_pool.random_path(&self.dht, &self.tcp_connections, announce_data.friend_pk.is_some()) {
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

            let inner_announce_request = announce_packet_data.search_request(&node.pk, request_id);
            futures.push(self.send_onion_request(path, InnerOnionRequest::InnerOnionAnnounceRequest(inner_announce_request), node.saddr));
        }

        Either::Right(future::try_join_all(futures)
            .map_ok(drop)
            .map_err(|e| e.context(HandleAnnounceResponseErrorKind::SendTo).into()))
    }

    /// Handle DHT `PublicKey` announce from both onion and DHT.
    pub fn handle_dht_pk_announce(&self, friend_pk: PublicKey, dht_pk_announce: DhtPkAnnouncePayload) -> impl Future<Output = Result<(), HandleDhtPkAnnounceError>> + Send {
        let mut state = self.state.lock();

        let friend = match state.friends.get_mut(&friend_pk) {
            Some(friend) => friend,
            None => return Either::Left(future::err(HandleDhtPkAnnounceErrorKind::NoFriendWithPk.into()))
        };

        if dht_pk_announce.no_reply <= friend.last_no_reply {
            return Either::Left(future::err(HandleDhtPkAnnounceErrorKind::InvalidNoReply.into()))
        }

        friend.last_no_reply = dht_pk_announce.no_reply;
        friend.dht_pk = Some(dht_pk_announce.dht_pk);
        friend.last_seen = Some(clock_now());

        let tx = state.dht_pk_tx.clone();
        let dht_pk = dht_pk_announce.dht_pk;
        let dht_pk_future = maybe_send_unbounded(tx, (friend_pk, dht_pk))
            .map_err(|e| e.context(HandleDhtPkAnnounceErrorKind::SendTo).into());

        let friend_dht_pk = dht_pk_announce.dht_pk;
        let futures = dht_pk_announce.nodes.into_iter().map(|node| match node.ip_port.protocol {
            ProtocolType::UDP => {
                let packed_node = PackedNode::new(node.ip_port.to_saddr(), &node.pk);
                Either::Left(self.dht.ping_node(&packed_node)
                    .map_err(|e| e.context(HandleDhtPkAnnounceErrorKind::PingNode).into()))
            },
            ProtocolType::TCP => {
                Either::Right(self.tcp_connections.add_relay_connection(node.ip_port.to_saddr(), node.pk, friend_dht_pk)
                    .map_err(|e| e.context(HandleDhtPkAnnounceErrorKind::AddRelay).into()))
            }
        }).collect::<Vec<_>>();

        Either::Right(
            future::try_join(
                dht_pk_future,
                future::try_join_all(futures).map_ok(drop)
            )
            .map_ok(drop)
        )
    }

    /// Handle `OnionDataResponse` packet.
    pub fn handle_data_response(&self, packet: &OnionDataResponse) -> impl Future<Output = Result<(), HandleDataResponseError>> + Send {
        let payload = match packet.get_payload(&precompute(&packet.temporary_pk, &self.data_sk)) {
            Ok(payload) => payload,
            Err(e) => return Either::Left(future::err(e.context(HandleDataResponseErrorKind::InvalidPayload).into()))
        };
        let iner_payload = match payload.get_payload(&packet.nonce, &precompute(&payload.real_pk, &self.real_sk)) {
            Ok(payload) => payload,
            Err(e) => return Either::Left(future::err(e.context(HandleDataResponseErrorKind::InvalidInnerPayload).into()))
        };
        let future = match iner_payload {
            OnionDataResponseInnerPayload::DhtPkAnnounce(dht_pk_announce) =>
                Either::Left(self.handle_dht_pk_announce(payload.real_pk, dht_pk_announce)
                    .map_err(|e| e.context(HandleDataResponseErrorKind::DhtPkAnnounce).into())),
            OnionDataResponseInnerPayload::FriendRequest(friend_request) => {
                let tx = self.state.lock().friend_request_tx.clone();
                Either::Right(
                    maybe_send_unbounded(tx, (payload.real_pk, friend_request))
                        .map_err(|e|
                            e.context(HandleDataResponseErrorKind::FriendRequest).into()
                        )
                )
            }
        };
        Either::Right(future)
    }

    /// Add new node to random nodes pool to use them to build random paths.
    pub fn add_path_node(&self, node: PackedNode) {
        let mut state = self.state.lock();

        state.paths_pool.path_nodes.put(node);
    }

    /// Add a friend to start looking for its DHT `PublicKey`.
    pub fn add_friend(&self, real_pk: PublicKey) {
        let mut state = self.state.lock();

        state.friends.insert(real_pk, OnionFriend::new(real_pk));
    }

    /// Remove a friend and stop looking for him.
    pub fn remove_friend(&self, real_pk: PublicKey) {
        let mut state = self.state.lock();

        state.friends.remove(&real_pk);
    }

    /// Set connection status of a friend. If he's connected we can stop looking
    /// for his DHT `PublicKey`.
    pub fn set_friend_connected(&self, real_pk: PublicKey, connected: bool) {
        let mut state = self.state.lock();

        if let Some(friend) = state.friends.get_mut(&real_pk) {
            if friend.connected && !connected {
                friend.last_seen = Some(clock_now());
                friend.search_count = 0;
                // reset no_reply for the case when a friend will try to connect
                // from a different device with different clock
                friend.last_no_reply = 0;
            }
            friend.connected = connected;
        }
    }

    /// Set friend's DHT `PublicKey` when it gets known somewhere else.
    pub fn set_friend_dht_pk(&self, real_pk: PublicKey, dht_pk: PublicKey) {
        let mut state = self.state.lock();

        if let Some(friend) = state.friends.get_mut(&real_pk) {
            friend.dht_pk = Some(dht_pk);
        }
    }

    /// Generic function for sending search and announce requests to close nodes.
    fn ping_close_nodes(
        &self,
        close_nodes: &mut Kbucket<OnionNode>,
        paths_pool: &mut PathsPool,
        announce_requests: &mut RequestQueue<AnnounceRequestData>,
        announce_packet_data: AnnouncePacketData,
        friend_pk: Option<PublicKey>,
        interval: Option<Duration>
    ) -> (impl Future<Output = Result<(), mpsc::SendError>> + Send, bool) {
        let capacity = close_nodes.capacity();
        let ping_random = close_nodes.iter().all(|node|
            clock_elapsed(node.ping_time) >= ONION_NODE_PING_INTERVAL &&
                // ensure we get a response from some node roughly once per interval / capacity
                interval.map_or(true, |interval| clock_elapsed(node.response_time) >= interval / capacity as u32)
        );
        let mut futures = Vec::new();
        let mut good_nodes_count = 0;
        for node in close_nodes.iter_mut() {
            if !node.is_timed_out() {
                good_nodes_count += 1;
            }

            if node.is_ping_attempts_exhausted() {
                continue;
            }

            let interval = if let Some(interval) = interval {
                interval
            } else if node.announce_status == AnnounceStatus::Announced {
                if let Some(stored_path) = paths_pool.get_stored_path(node.path_id, friend_pk.is_some()) {
                    if node.is_stable() && stored_path.is_stable() {
                        ANNOUNCE_INTERVAL_STABLE
                    } else {
                        ANNOUNCE_INTERVAL_ANNOUNCED
                    }
                } else {
                    ANNOUNCE_INTERVAL_NOT_ANNOUNCED
                }
            } else {
                ANNOUNCE_INTERVAL_NOT_ANNOUNCED
            };

            if clock_elapsed(node.ping_time) >= interval || ping_random && random_limit_usize(capacity) == 0 {
                // Last chance for a long-lived node
                let path = if node.is_last_ping_attempt() && node.is_stable() {
                    paths_pool.random_path(&self.dht, &self.tcp_connections, friend_pk.is_some())
                } else {
                    paths_pool.get_or_random_path(&self.dht, &self.tcp_connections, node.path_id, friend_pk.is_some())
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

                let inner_announce_request = match node.ping_id {
                    Some(ping_id) if friend_pk.is_none() => announce_packet_data.announce_request(&node.pk, ping_id, request_id),
                    _ => announce_packet_data.search_request(&node.pk, request_id)
                };
                futures.push(self.send_onion_request(path, InnerOnionRequest::InnerOnionAnnounceRequest(inner_announce_request), node.saddr));
            }
        }

        if good_nodes_count <= random_limit_usize(close_nodes.capacity()) {
            for _ in 0 .. close_nodes.capacity() / 2 {
                let node = if let Some(node) = paths_pool.path_nodes.rand() {
                    node
                } else {
                    break
                };

                let path = if let Some(path) = paths_pool.random_path(&self.dht, &self.tcp_connections, friend_pk.is_some()) {
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
                futures.push(self.send_onion_request(path, InnerOnionRequest::InnerOnionAnnounceRequest(inner_announce_request), node.saddr));
            }
        }

        let packets_sent = !futures.is_empty();
        (future::try_join_all(futures).map_ok(drop), packets_sent)
    }

    /// Announce ourselves periodically.
    fn announce_loop(&self, state: &mut OnionClientState) -> impl Future<Output = Result<(), RunError>> + Send {
        let announce_packet_data = AnnouncePacketData {
            packet_sk: &self.real_sk,
            packet_pk: self.real_pk,
            search_pk: self.real_pk,
            data_pk: Some(self.data_pk),
        };

        self.ping_close_nodes(
            &mut state.announce_list,
            &mut state.paths_pool,
            &mut state.announce_requests,
            announce_packet_data,
            None,
            None,
        ).0.map_err(|e| e.context(RunErrorKind::SendTo).into())
    }

    /// Get nodes to include to DHT `PublicKey` announcement packet.
    fn dht_pk_nodes(&self) -> Vec<TcpUdpPackedNode> {
        let relays = self.tcp_connections.get_random_relays(2);
        let close_nodes: Vec<PackedNode> = self.dht.get_closest(&self.dht.pk, 4 - relays.len() as u8, false).into();
        relays.into_iter().map(|node| TcpUdpPackedNode {
            pk: node.pk,
            ip_port: IpPort::from_tcp_saddr(node.saddr),
        }).chain(close_nodes.into_iter().map(|node| TcpUdpPackedNode {
            pk: node.pk,
            ip_port: IpPort::from_udp_saddr(node.saddr),
        })).collect()
    }

    /// Announce our DHT `PublicKey` to a friend via onion.
    fn send_dht_pk_onion(&self, friend: &mut OnionFriend, paths_pool: &mut PathsPool) -> impl Future<Output = Result<(), mpsc::SendError>> + Send {
        let dht_pk_announce = DhtPkAnnouncePayload::new(self.dht.pk, self.dht_pk_nodes());
        let inner_payload = OnionDataResponseInnerPayload::DhtPkAnnounce(dht_pk_announce);
        let nonce = gen_nonce();
        let payload = OnionDataResponsePayload::new(&precompute(&friend.real_pk, &self.real_sk), self.real_pk, &nonce, &inner_payload);

        let mut futures = Vec::new();

        for node in friend.close_nodes.iter() {
            if node.is_timed_out() {
                continue;
            }

            let data_pk = if let Some(data_pk) = node.data_pk {
                data_pk
            } else {
                continue
            };

            let path = if let Some(path) = paths_pool.get_or_random_path(&self.dht, &self.tcp_connections, node.path_id, true) {
                path
            } else {
                continue
            };

            let (temporary_pk, temporary_sk) = gen_keypair();
            let inner_data_request = InnerOnionDataRequest::new(&precompute(&data_pk, &temporary_sk), friend.real_pk, temporary_pk, nonce, &payload);

            futures.push(self.send_onion_request(path, InnerOnionRequest::InnerOnionDataRequest(inner_data_request), node.saddr));
        }

        if !futures.is_empty() {
            friend.last_dht_pk_onion_sent = Some(clock_now());
        }

        future::try_join_all(futures).map_ok(drop)
    }

    /// Announce our DHT `PublicKey` to a friend via `DhtRequest`.
    fn send_dht_pk_dht_request(&self, friend: &mut OnionFriend) -> impl Future<Output = Result<(), mpsc::SendError>> + Send {
        let friend_dht_pk = if let Some(friend_dht_pk) = friend.dht_pk {
            friend_dht_pk
        } else {
            return Either::Left(future::ok(()))
        };

        let dht_pk_announce_payload = DhtPkAnnouncePayload::new(self.dht.pk, self.dht_pk_nodes());
        let dht_pk_announce = DhtPkAnnounce::new(
            &precompute(&friend.real_pk, &self.real_sk),
            self.real_pk,
            &dht_pk_announce_payload
        );
        let payload = DhtRequestPayload::DhtPkAnnounce(dht_pk_announce);
        let packet = DhtRequest::new(
            &precompute(&friend_dht_pk, &self.dht.sk),
            &friend_dht_pk,
            &self.dht.pk,
            &payload
        );
        let packet = Packet::DhtRequest(packet);

        let nodes = self.dht.get_closest(&friend_dht_pk, 8, false);

        if !nodes.is_empty() {
            friend.last_dht_pk_dht_sent = Some(clock_now());
        }

        let packets = nodes.iter()
            .map(|node| (packet.clone(), node.saddr))
            .collect::<Vec<_>>();

        let mut tx = self.dht.tx.clone();
        Either::Right(async move {
            let mut fut = futures::stream::iter(packets).map(Ok);
            tx.send_all(&mut fut).await
        })
    }

    /// Search friends periodically.
    fn friends_loop(&self, state: &mut OnionClientState) -> impl Future<Output = Result<(), RunError>> + Send {
        use std::pin::Pin;

        let mut futures: Vec<Pin<Box<dyn Future<Output = Result<_, _>> + Send>>> = vec![];

        for friend in state.friends.values_mut() {
            if friend.connected {
                continue;
            }

            let announce_packet_data = AnnouncePacketData {
                packet_sk: &friend.temporary_sk,
                packet_pk: friend.temporary_pk,
                search_pk: friend.real_pk,
                data_pk: None,
            };

            let interval = if friend.search_count < SEARCH_COUNT_FRIEND_ANNOUNCE_BEGINNING {
                ANNOUNCE_FRIEND_BEGINNING
            } else {
                let backoff_interval = friend.last_seen.map_or_else(
                    || ONION_FRIEND_MAX_PING_INTERVAL,
                    |last_seen| clock_elapsed(last_seen) / ONION_FRIEND_BACKOFF_FACTOR
                );
                backoff_interval
                    .min(ONION_FRIEND_MAX_PING_INTERVAL)
                    .max(ANNOUNCE_FRIEND)
            };

            let (friend_future, packets_sent) = self.ping_close_nodes(
                &mut friend.close_nodes,
                &mut state.paths_pool,
                &mut state.announce_requests,
                announce_packet_data,
                Some(friend.real_pk),
                Some(interval),
            );

            if packets_sent {
                friend.search_count = friend.search_count.saturating_add(1);
            }

            futures.push(Box::pin(friend_future));

            if friend.last_dht_pk_onion_sent.map_or(true, |time| clock_elapsed(time) > ONION_DHTPK_SEND_INTERVAL) {
                futures.push(Box::pin(self.send_dht_pk_onion(friend, &mut state.paths_pool)));
            }

            if friend.last_dht_pk_dht_sent.map_or(true, |time| clock_elapsed(time) > DHT_DHTPK_SEND_INTERVAL) {
                futures.push(Box::pin(self.send_dht_pk_dht_request(friend)));
            }
        }

        future::try_join_all(futures)
            .map_ok(drop)
            .map_err(|e| e.context(RunErrorKind::SendTo).into())
    }

    /// Populate nodes pool from DHT for building random paths.
    fn populate_path_nodes(&self, state: &mut OnionClientState) {
        for node in self.dht.random_friend_nodes(MAX_ONION_ANNOUNCE_NODES) {
            state.paths_pool.path_nodes.put(node);
        }
    }

    /// Run periodical announcements and friends searching.
    pub fn run(self) -> impl Future<Output = Result<(), RunError>> + Send {
        let interval = Duration::from_secs(1);
        let wakeups = tokio::time::interval(interval);

        wakeups
            .map(Ok)
            .try_for_each(move |_instant| {
                trace!("Onion client sender wake up");

                let mut state = self.state.lock();
                self.populate_path_nodes(&mut state);

                future::try_join(
                    self.announce_loop(&mut state),
                    self.friends_loop(&mut state)
                ).map_ok(drop)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl OnionClient {
        pub fn has_friend(&self, pk: &PublicKey) -> bool {
            self.state.lock().friends.contains_key(pk)
        }

        pub fn friend_dht_pk(&self, pk: &PublicKey) -> Option<PublicKey> {
            self.state.lock().friends.get(pk).and_then(|friend| friend.dht_pk)
        }

        pub fn is_friend_connected(&self, pk: &PublicKey) -> bool {
            self.state.lock().friends.get(pk).map_or(false, |friend| friend.connected)
        }
    }

    fn unpack_onion_packet(packet: OnionRequest0, saddr: SocketAddr, key_by_addr: &HashMap<SocketAddr, SecretKey>) -> OnionRequest2Payload {
        let payload = packet.get_payload(&precompute(&packet.temporary_pk, &key_by_addr[&saddr])).unwrap();
        let packet = OnionRequest1 {
            nonce: packet.nonce,
            temporary_pk: payload.temporary_pk,
            payload: payload.inner,
            onion_return: OnionReturn {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; 123],
            }
        };
        let payload = packet.get_payload(&precompute(&packet.temporary_pk, &key_by_addr[&payload.ip_port.to_saddr()])).unwrap();
        let packet = OnionRequest2 {
            nonce: packet.nonce,
            temporary_pk: payload.temporary_pk,
            payload: payload.inner,
            onion_return: OnionReturn {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; 123],
            }
        };
        packet.get_payload(&precompute(&packet.temporary_pk, &key_by_addr[&payload.ip_port.to_saddr()])).unwrap()
    }

    #[test]
    fn onion_node_is_outdated() {
        let now = Instant::now();
        let (pk, _sk) = gen_keypair();
        let saddr = "127.0.0.1:12345".parse().unwrap();
        let onion_node = OnionNode {
            pk,
            saddr,
            path_id: OnionPathId {
                keys: [gen_keypair().0, gen_keypair().0, gen_keypair().0],
                path_type: OnionPathType::UDP,
            },
            ping_id: None,
            data_pk: None,
            unsuccessful_pings: 0,
            added_time: now,
            ping_time: now,
            response_time: now,
            announce_status: AnnounceStatus::Announced,
        };

        assert!(!onion_node.is_outdated(&PackedNode::new(saddr, &pk)));
        let other_saddr = "127.0.0.1:12346".parse().unwrap();
        assert!(onion_node.is_outdated(&PackedNode::new(other_saddr, &pk)))
    }

    #[tokio::test]
    async fn onion_node_update() {
        tokio::time::pause();
        let now = clock_now();
        let (pk, _sk) = gen_keypair();
        let mut onion_node = OnionNode {
            pk,
            saddr: "127.0.0.1:12345".parse().unwrap(),
            path_id: OnionPathId {
                keys: [gen_keypair().0, gen_keypair().0, gen_keypair().0],
                path_type: OnionPathType::UDP,
            },
            ping_id: None,
            data_pk: None,
            unsuccessful_pings: 1,
            added_time: now,
            ping_time: now,
            response_time: now,
            announce_status: AnnounceStatus::Failed,
        };

        let saddr = "127.0.0.1:12346".parse().unwrap();
        let path_id = OnionPathId {
            keys: [gen_keypair().0, gen_keypair().0, gen_keypair().0],
            path_type: OnionPathType::UDP,
        };
        let ping_id = sha256::hash(&[1, 2, 3]);
        let data_pk = gen_keypair().0;
        let new_now = now + Duration::from_secs(1);
        let other_onion_node = OnionNode {
            pk,
            saddr,
            path_id,
            ping_id: Some(ping_id),
            data_pk: Some(data_pk),
            unsuccessful_pings: 0,
            added_time: now,
            ping_time: now,
            response_time: now,
            announce_status: AnnounceStatus::Announced,
        };

        tokio::time::advance(Duration::from_secs(1)).await;

        onion_node.update(&other_onion_node);

        assert_eq!(onion_node.saddr, saddr);
        assert_eq!(onion_node.path_id, path_id);
        assert_eq!(onion_node.ping_id, Some(ping_id));
        assert_eq!(onion_node.data_pk, Some(data_pk));
        assert_eq!(onion_node.unsuccessful_pings, 0);
        assert_eq!(onion_node.added_time, now);
        assert_eq!(onion_node.ping_time, now);
        assert_eq!(onion_node.response_time, new_now);
        assert_eq!(onion_node.announce_status, AnnounceStatus::Announced);
    }

    #[tokio::test]
    async fn onion_node_is_evictable() {
        let now = Instant::now();
        let mut onion_node = OnionNode {
            pk: gen_keypair().0,
            saddr: "127.0.0.1:12345".parse().unwrap(),
            path_id: OnionPathId {
                keys: [gen_keypair().0, gen_keypair().0, gen_keypair().0],
                path_type: OnionPathType::UDP,
            },
            ping_id: None,
            data_pk: None,
            unsuccessful_pings: 0,
            added_time: now,
            ping_time: now,
            response_time: now,
            announce_status: AnnounceStatus::Announced,
        };

        assert!(!onion_node.is_evictable());

        onion_node.unsuccessful_pings = ONION_NODE_MAX_PINGS;

        tokio::time::pause();
        // time when node is timed out
        tokio::time::advance(ONION_NODE_TIMEOUT + Duration::from_secs(1)).await;

        assert!(onion_node.is_evictable());
    }

    #[test]
    fn add_path_node() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk, real_pk);

        let node = PackedNode::new("127.0.0.1:12345".parse().unwrap(), &gen_keypair().0);
        onion_client.add_path_node(node);

        let state = onion_client.state.lock();
        assert_eq!(state.paths_pool.path_nodes.rand(), Some(node));
    }

    #[test]
    fn add_remove_friend() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk, real_pk);

        let (friend_pk, _friend_sk) = gen_keypair();
        onion_client.add_friend(friend_pk);

        assert_eq!(onion_client.state.lock().friends[&friend_pk].real_pk, friend_pk);

        onion_client.remove_friend(friend_pk);

        assert!(!onion_client.state.lock().friends.contains_key(&friend_pk));
    }

    #[tokio::test]
    async fn set_friend_connected() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk, real_pk);

        let (friend_pk, _friend_sk) = gen_keypair();
        onion_client.add_friend(friend_pk);

        onion_client.set_friend_connected(friend_pk, true);

        let state = onion_client.state.lock();
        assert!(state.friends[&friend_pk].connected);
        drop(state);

        tokio::time::pause();
        let now = clock_now();

        onion_client.set_friend_connected(friend_pk, false);

        let state = onion_client.state.lock();
        let friend = &state.friends[&friend_pk];
        assert!(!friend.connected);
        assert_eq!(friend.last_seen, Some(now));
    }

    #[test]
    fn set_friend_dht_pk() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk, real_pk);

        let (friend_pk, _friend_sk) = gen_keypair();
        onion_client.add_friend(friend_pk);

        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        onion_client.set_friend_dht_pk(friend_pk, friend_dht_pk);

        let state = onion_client.state.lock();
        assert_eq!(state.friends[&friend_pk].dht_pk, Some(friend_dht_pk));
    }

    #[tokio::test]
    async fn handle_announce_response_announced() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        // make DHT connected so that we will build UDP onion paths
        dht.add_node(PackedNode::new("127.0.0.1:12345".parse().unwrap(), &gen_keypair().0));
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk, real_pk);

        let mut state = onion_client.state.lock();

        // map needed to decrypt onion packets later
        let mut key_by_addr = HashMap::new();
        let addr = "127.0.0.1".parse().unwrap();
        for i in 0 .. 3 {
            let saddr = SocketAddr::new(addr, 12346 + i);
            let (pk, sk) = gen_keypair();
            key_by_addr.insert(saddr, sk);
            let node = PackedNode::new(saddr, &pk);
            state.paths_pool.path_nodes.put(node);
        }
        let path = state.paths_pool.path_nodes.udp_path().unwrap();

        let (sender_pk, sender_sk) = gen_keypair();
        let saddr = "127.0.0.1:12345".parse().unwrap();

        // the sender will be added to the nodes pool so add it to the map
        key_by_addr.insert(saddr, sender_sk.clone());

        let request_data = AnnounceRequestData {
            pk: sender_pk,
            saddr,
            path_id: path.id(),
            friend_pk: None,
        };
        let request_id = state.announce_requests.new_ping_id(request_data);

        drop(state);

        let ping_id = sha256::hash(&[1, 2, 3]);
        let (node_pk, node_sk) = gen_keypair();
        let node = PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &node_pk);
        let payload = OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Announced,
            ping_id_or_pk: ping_id,
            nodes: vec![node]
        };
        let packet = OnionAnnounceResponse::new(&precompute(&real_pk, &sender_sk), request_id, &payload);

        onion_client.handle_announce_response(&packet, true).await.unwrap();

        let state = onion_client.state.lock();

        // The sender should be added to close nodes
        let onion_node = state.announce_list.get_node(&real_pk, &sender_pk).unwrap();
        assert_eq!(onion_node.path_id, path.id());
        assert_eq!(onion_node.ping_id, Some(ping_id));
        assert_eq!(onion_node.data_pk, None);
        assert_eq!(onion_node.announce_status, AnnounceStatus::Announced);

        // Node from the packet should be pinged
        let (received, _udp_rx) = udp_rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        let packet = unpack!(packet, Packet::OnionRequest0);
        let payload = unpack_onion_packet(packet, addr_to_send, &key_by_addr);
        let packet = unpack!(payload.inner, InnerOnionRequest::InnerOnionAnnounceRequest);
        let payload = packet.get_payload(&precompute(&real_pk, &node_sk)).unwrap();
        assert_eq!(payload.ping_id, initial_ping_id());
        assert_eq!(payload.search_pk, real_pk);
        assert_eq!(payload.data_pk, onion_client.data_pk);
    }

    #[tokio::test]
    async fn handle_announce_response_announced_invalid_status() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk, real_pk);

        let mut state = onion_client.state.lock();

        let (friend_pk, _friend_sk) = gen_keypair();
        let friend = OnionFriend::new(friend_pk);
        let friend_temporary_pk = friend.temporary_pk;
        state.friends.insert(friend_pk, friend);

        let addr = "127.0.0.1".parse().unwrap();
        for i in 0 .. 3 {
            let saddr = SocketAddr::new(addr, 12346 + i);
            let (pk, _sk) = gen_keypair();
            let node = PackedNode::new(saddr, &pk);
            state.paths_pool.path_nodes.put(node);
        }
        let path = state.paths_pool.path_nodes.udp_path().unwrap();

        let (sender_pk, sender_sk) = gen_keypair();
        let saddr = "127.0.0.1:12345".parse().unwrap();

        let request_data = AnnounceRequestData {
            pk: sender_pk,
            saddr,
            path_id: path.id(),
            friend_pk: Some(friend_pk),
        };
        let request_id = state.announce_requests.new_ping_id(request_data);

        drop(state);

        let ping_id = sha256::hash(&[1, 2, 3]);
        let (node_pk, _node_sk) = gen_keypair();
        let node = PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &node_pk);
        let payload = OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Announced,
            ping_id_or_pk: ping_id,
            nodes: vec![node]
        };
        let packet = OnionAnnounceResponse::new(&precompute(&friend_temporary_pk, &sender_sk), request_id, &payload);

        let error = onion_client.handle_announce_response(&packet, true).await.err().unwrap();
        assert_eq!(error.kind(), &HandleAnnounceResponseErrorKind::InvalidAnnounceStatus);
    }

    #[tokio::test]
    async fn handle_announce_response_announced_pinged_recently() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        let mut state = onion_client.state.lock();

        let addr = "127.0.0.1".parse().unwrap();
        for i in 0 .. 3 {
            let saddr = SocketAddr::new(addr, 12346 + i);
            let (pk, _sk) = gen_keypair();
            let node = PackedNode::new(saddr, &pk);
            state.paths_pool.path_nodes.put(node);
        }
        let path = state.paths_pool.path_nodes.udp_path().unwrap();

        let (sender_pk, sender_sk) = gen_keypair();
        let saddr = "127.0.0.1:12345".parse().unwrap();

        let request_data = AnnounceRequestData {
            pk: sender_pk,
            saddr,
            path_id: path.id(),
            friend_pk: None,
        };
        let request_id = state.announce_requests.new_ping_id(request_data);

        // insert request to a node to announce_requests so that it won't be pinged again
        let (node_pk, _node_sk) = gen_keypair();
        let node = PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &node_pk);
        let node_request_data = AnnounceRequestData {
            pk: node_pk,
            saddr: node.saddr,
            path_id: path.id(),
            friend_pk: None,
        };
        let _node_request_id = state.announce_requests.new_ping_id(node_request_data);

        drop(state);

        let payload = OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Announced,
            ping_id_or_pk: sha256::hash(&[1, 2, 3]),
            nodes: vec![node]
        };
        let packet = OnionAnnounceResponse::new(&precompute(&real_pk, &sender_sk), request_id, &payload);

        onion_client.handle_announce_response(&packet, true).await.unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(onion_client);

        assert!(udp_rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn handle_announce_response_found() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        // make DHT connected so that we will build UDP onion paths
        dht.add_node(PackedNode::new("127.0.0.1:12345".parse().unwrap(), &gen_keypair().0));
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        let mut state = onion_client.state.lock();

        let (friend_pk, _friend_sk) = gen_keypair();
        let friend = OnionFriend::new(friend_pk);
        let friend_temporary_pk = friend.temporary_pk;
        state.friends.insert(friend_pk, friend);

        // map needed to decrypt onion packets later
        let mut key_by_addr = HashMap::new();
        let addr = "127.0.0.1".parse().unwrap();
        for i in 0 .. 3 {
            let saddr = SocketAddr::new(addr, 12346 + i);
            let (pk, sk) = gen_keypair();
            key_by_addr.insert(saddr, sk);
            let node = PackedNode::new(saddr, &pk);
            state.paths_pool.path_nodes.put(node);
        }
        let path = state.paths_pool.path_nodes.udp_path().unwrap();

        let (sender_pk, sender_sk) = gen_keypair();
        let saddr = "127.0.0.1:12345".parse().unwrap();

        // the sender will be added to the nodes pool so add it to the map
        key_by_addr.insert(saddr, sender_sk.clone());

        let request_data = AnnounceRequestData {
            pk: sender_pk,
            saddr,
            path_id: path.id(),
            friend_pk: Some(friend_pk),
        };
        let request_id = state.announce_requests.new_ping_id(request_data);

        drop(state);

        let (friend_data_pk, _friend_data_sk) = gen_keypair();
        let (node_pk, node_sk) = gen_keypair();
        let node = PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &node_pk);
        let payload = OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Found,
            ping_id_or_pk: pk_as_digest(friend_data_pk),
            nodes: vec![node]
        };
        let packet = OnionAnnounceResponse::new(&precompute(&friend_temporary_pk, &sender_sk), request_id, &payload);

        onion_client.handle_announce_response(&packet, true).await.unwrap();

        let state = onion_client.state.lock();

        // The sender should be added to close nodes
        let onion_node = state.friends[&friend_pk].close_nodes.get_node(&real_pk, &sender_pk).unwrap();
        assert_eq!(onion_node.path_id, path.id());
        assert_eq!(onion_node.ping_id, None);
        assert_eq!(onion_node.data_pk, Some(friend_data_pk));
        assert_eq!(onion_node.announce_status, AnnounceStatus::Found);

        // Node from the packet should be pinged
        let (received, _udp_rx) = udp_rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        let packet = unpack!(packet, Packet::OnionRequest0);
        let payload = unpack_onion_packet(packet, addr_to_send, &key_by_addr);
        let packet = unpack!(payload.inner, InnerOnionRequest::InnerOnionAnnounceRequest);
        let payload = packet.get_payload(&precompute(&friend_temporary_pk, &node_sk)).unwrap();
        assert_eq!(payload.ping_id, initial_ping_id());
        assert_eq!(payload.search_pk, friend_pk);
        assert_eq!(payload.data_pk, PublicKey([0; 32]));
    }

    #[tokio::test]
    async fn handle_announce_response_found_invalid_status() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        let mut state = onion_client.state.lock();

        let addr = "127.0.0.1".parse().unwrap();
        for i in 0 .. 3 {
            let saddr = SocketAddr::new(addr, 12346 + i);
            let (pk, _sk) = gen_keypair();
            let node = PackedNode::new(saddr, &pk);
            state.paths_pool.path_nodes.put(node);
        }
        let path = state.paths_pool.path_nodes.udp_path().unwrap();

        let (sender_pk, sender_sk) = gen_keypair();
        let saddr = "127.0.0.1:12345".parse().unwrap();

        let request_data = AnnounceRequestData {
            pk: sender_pk,
            saddr,
            path_id: path.id(),
            friend_pk: None,
        };
        let request_id = state.announce_requests.new_ping_id(request_data);

        drop(state);

        let (friend_data_pk, _friend_data_sk) = gen_keypair();
        let (node_pk, _node_sk) = gen_keypair();
        let node = PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &node_pk);
        let payload = OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Found,
            ping_id_or_pk: pk_as_digest(friend_data_pk),
            nodes: vec![node]
        };
        let packet = OnionAnnounceResponse::new(&precompute(&real_pk, &sender_sk), request_id, &payload);

        let error = onion_client.handle_announce_response(&packet, true).await.err().unwrap();
        assert_eq!(error.kind(), &HandleAnnounceResponseErrorKind::InvalidAnnounceStatus);
    }

    #[tokio::test]
    async fn handle_announce_response_no_friend_with_pk() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        let mut state = onion_client.state.lock();

        let (friend_pk, _friend_sk) = gen_keypair();
        let (friend_temporary_pk, _friend_temporary_sk) = gen_keypair();
        let (sender_pk, sender_sk) = gen_keypair();
        let saddr = "127.0.0.1:12345".parse().unwrap();

        let request_data = AnnounceRequestData {
            pk: sender_pk,
            saddr,
            path_id: OnionPathId {
                keys: [gen_keypair().0, gen_keypair().0, gen_keypair().0],
                path_type: OnionPathType::UDP,
            },
            friend_pk: Some(friend_pk),
        };
        let request_id = state.announce_requests.new_ping_id(request_data);

        drop(state);

        let (friend_data_pk, _friend_data_sk) = gen_keypair();
        let payload = OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Found,
            ping_id_or_pk: pk_as_digest(friend_data_pk),
            nodes: vec![]
        };
        let packet = OnionAnnounceResponse::new(&precompute(&friend_temporary_pk, &sender_sk), request_id, &payload);

        let error = onion_client.handle_announce_response(&packet, true).await.err().unwrap();
        assert_eq!(error.kind(), &HandleAnnounceResponseErrorKind::NoFriendWithPk);
    }

    #[tokio::test]
    async fn handle_announce_response_invalid_payload() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        let mut state = onion_client.state.lock();

        let (friend_pk, _friend_sk) = gen_keypair();
        let friend = OnionFriend::new(friend_pk);
        state.friends.insert(friend_pk, friend);

        let (sender_pk, _sender_sk) = gen_keypair();
        let saddr = "127.0.0.1:12345".parse().unwrap();

        let request_data = AnnounceRequestData {
            pk: sender_pk,
            saddr,
            path_id: OnionPathId {
                keys: [gen_keypair().0, gen_keypair().0, gen_keypair().0],
                path_type: OnionPathType::UDP,
            },
            friend_pk: Some(friend_pk),
        };
        let request_id = state.announce_requests.new_ping_id(request_data);

        drop(state);

        let packet = OnionAnnounceResponse {
            sendback_data: request_id,
            nonce: gen_nonce(),
            payload: vec![42; 123],
        };

        let error = onion_client.handle_announce_response(&packet, true).await.err().unwrap();
        assert_eq!(error.kind(), &HandleAnnounceResponseErrorKind::InvalidPayload);
    }

    #[tokio::test]
    async fn handle_announce_response_found_pinged_recently() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        let mut state = onion_client.state.lock();

        let (friend_pk, _friend_sk) = gen_keypair();
        let friend = OnionFriend::new(friend_pk);
        let friend_temporary_pk = friend.temporary_pk;
        state.friends.insert(friend_pk, friend);

        let addr = "127.0.0.1".parse().unwrap();
        for i in 0 .. 3 {
            let saddr = SocketAddr::new(addr, 12346 + i);
            let (pk, _sk) = gen_keypair();
            let node = PackedNode::new(saddr, &pk);
            state.paths_pool.path_nodes.put(node);
        }
        let path = state.paths_pool.path_nodes.udp_path().unwrap();

        let (sender_pk, sender_sk) = gen_keypair();
        let saddr = "127.0.0.1:12345".parse().unwrap();

        let request_data = AnnounceRequestData {
            pk: sender_pk,
            saddr,
            path_id: path.id(),
            friend_pk: Some(friend_pk),
        };
        let request_id = state.announce_requests.new_ping_id(request_data);

        // insert request to a node to announce_requests so that it won't be pinged again
        let (node_pk, _node_sk) = gen_keypair();
        let node = PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &node_pk);
        let node_request_data = AnnounceRequestData {
            pk: node_pk,
            saddr: node.saddr,
            path_id: path.id(),
            friend_pk: Some(friend_pk),
        };
        let _node_request_id = state.announce_requests.new_ping_id(node_request_data);

        drop(state);

        let (friend_data_pk, _friend_data_sk) = gen_keypair();
        let node = PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &node_pk);
        let payload = OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Found,
            ping_id_or_pk: pk_as_digest(friend_data_pk),
            nodes: vec![node]
        };
        let packet = OnionAnnounceResponse::new(&precompute(&friend_temporary_pk, &sender_sk), request_id, &payload);

        onion_client.handle_announce_response(&packet, true).await.unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(onion_client);

        assert!(udp_rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn handle_data_response_dht_pk_announce_udp_node() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let (dht_pk_tx, dht_pk_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        onion_client.set_dht_pk_sink(dht_pk_tx);

        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        let (friend_real_pk, friend_real_sk) = gen_keypair();

        onion_client.add_friend(friend_real_pk);

        let saddr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let (node_pk, node_sk) = gen_keypair();
        let dht_pk_announce_payload = DhtPkAnnouncePayload::new(friend_dht_pk, vec![
            TcpUdpPackedNode {
                ip_port: IpPort {
                    protocol: ProtocolType::UDP,
                    ip_addr: saddr.ip(),
                    port: saddr.port(),
                },
                pk: node_pk,
            },
        ]);
        let no_reply = dht_pk_announce_payload.no_reply;
        let onion_data_response_inner_payload = OnionDataResponseInnerPayload::DhtPkAnnounce(dht_pk_announce_payload);
        let nonce = gen_nonce();
        let onion_data_response_payload = OnionDataResponsePayload::new(&precompute(&real_pk, &friend_real_sk), friend_real_pk, &nonce, &onion_data_response_inner_payload);
        let (temporary_pk, temporary_sk) = gen_keypair();
        let onion_data_response = OnionDataResponse::new(&precompute(&onion_client.data_pk, &temporary_sk), temporary_pk, nonce, &onion_data_response_payload);

        onion_client.handle_data_response(&onion_data_response).await.unwrap();

        let state = onion_client.state.lock();

        // friend should have updated data
        let friend = &state.friends[&friend_real_pk];
        assert_eq!(friend.last_no_reply, no_reply);
        assert_eq!(friend.dht_pk, Some(friend_dht_pk));

        // friend's DHT key should be sent to dht_pk_tx
        let (received, _dht_pk_rx) = dht_pk_rx.into_future().await;
        let (received_real_pk, received_dht_pk) = received.unwrap();
        assert_eq!(received_real_pk, friend_real_pk);
        assert_eq!(received_dht_pk, friend_dht_pk);

        // the node from announce packet should be pinged
        let (received, _udp_rx) = udp_rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, saddr);
        let packet = unpack!(packet, Packet::NodesRequest);
        let payload = packet.get_payload(&precompute(&dht_pk, &node_sk)).unwrap();

        assert_eq!(payload.pk, dht_pk);
    }

    #[tokio::test]
    async fn handle_data_response_dht_pk_announce_tcp_node() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk, real_pk);

        onion_client.set_dht_pk_sink(dht_pk_tx);

        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        let (friend_real_pk, friend_real_sk) = gen_keypair();

        onion_client.add_friend(friend_real_pk);

        let (node_pk, _node_sk) = gen_keypair();
        let dht_pk_announce_payload = DhtPkAnnouncePayload::new(friend_dht_pk, vec![
            TcpUdpPackedNode {
                ip_port: IpPort {
                    protocol: ProtocolType::TCP,
                    ip_addr: "127.0.0.2".parse().unwrap(),
                    port: 12346,
                },
                pk: node_pk,
            },
        ]);
        let no_reply = dht_pk_announce_payload.no_reply;
        let onion_data_response_inner_payload = OnionDataResponseInnerPayload::DhtPkAnnounce(dht_pk_announce_payload);
        let nonce = gen_nonce();
        let onion_data_response_payload = OnionDataResponsePayload::new(&precompute(&real_pk, &friend_real_sk), friend_real_pk, &nonce, &onion_data_response_inner_payload);
        let (temporary_pk, temporary_sk) = gen_keypair();
        let onion_data_response = OnionDataResponse::new(&precompute(&onion_client.data_pk, &temporary_sk), temporary_pk, nonce, &onion_data_response_payload);

        // ignore result future since it spawns the connection which should be
        // executed inside tokio context
        let _ = onion_client.handle_data_response(&onion_data_response);

        let state = onion_client.state.lock();

        // friend should have updated data
        let friend = &state.friends[&friend_real_pk];
        assert_eq!(friend.last_no_reply, no_reply);
        assert_eq!(friend.dht_pk, Some(friend_dht_pk));

        assert!(onion_client.tcp_connections.has_relay(&node_pk));
        assert!(onion_client.tcp_connections.has_connection(&friend_dht_pk));
    }

    #[tokio::test]
    async fn handle_data_response_dht_pk_announce_no_friend_with_pk() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        let (friend_real_pk, friend_real_sk) = gen_keypair();

        let dht_pk_announce_payload = DhtPkAnnouncePayload::new(friend_dht_pk, vec![]);
        let onion_data_response_inner_payload = OnionDataResponseInnerPayload::DhtPkAnnounce(dht_pk_announce_payload);
        let nonce = gen_nonce();
        let onion_data_response_payload = OnionDataResponsePayload::new(&precompute(&real_pk, &friend_real_sk), friend_real_pk, &nonce, &onion_data_response_inner_payload);
        let (temporary_pk, temporary_sk) = gen_keypair();
        let onion_data_response = OnionDataResponse::new(&precompute(&onion_client.data_pk, &temporary_sk), temporary_pk, nonce, &onion_data_response_payload);

        let error = onion_client.handle_data_response(&onion_data_response).await.err().unwrap();
        assert_eq!(error.kind(), &HandleDataResponseErrorKind::DhtPkAnnounce);
        let cause = error.cause().unwrap().downcast_ref::<HandleDhtPkAnnounceError>().unwrap();
        assert_eq!(cause.kind(), &HandleDhtPkAnnounceErrorKind::NoFriendWithPk);
    }

    #[tokio::test]
    async fn handle_data_response_dht_pk_announce_invalid_no_reply() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        let (friend_real_pk, friend_real_sk) = gen_keypair();

        onion_client.add_friend(friend_real_pk);

        let dht_pk_announce_payload = DhtPkAnnouncePayload::new(friend_dht_pk, vec![]);
        let onion_data_response_inner_payload = OnionDataResponseInnerPayload::DhtPkAnnounce(dht_pk_announce_payload);
        let nonce = gen_nonce();
        let onion_data_response_payload = OnionDataResponsePayload::new(&precompute(&real_pk, &friend_real_sk), friend_real_pk, &nonce, &onion_data_response_inner_payload);
        let (temporary_pk, temporary_sk) = gen_keypair();
        let onion_data_response = OnionDataResponse::new(&precompute(&onion_client.data_pk, &temporary_sk), temporary_pk, nonce, &onion_data_response_payload);

        onion_client.handle_data_response(&onion_data_response).await.unwrap();

        // second announce with the same no_reply should be rejected
        let error = onion_client.handle_data_response(&onion_data_response).await.err().unwrap();
        assert_eq!(error.kind(), &HandleDataResponseErrorKind::DhtPkAnnounce);
        let cause = error.cause().unwrap().downcast_ref::<HandleDhtPkAnnounceError>().unwrap();
        assert_eq!(cause.kind(), &HandleDhtPkAnnounceErrorKind::InvalidNoReply);
    }

    #[tokio::test]
    async fn handle_data_response_invalid_payload() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        let onion_data_response = OnionDataResponse {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123],
        };

        let error = onion_client.handle_data_response(&onion_data_response).await.err().unwrap();
        assert_eq!(error.kind(), &HandleDataResponseErrorKind::InvalidPayload);
    }

    #[tokio::test]
    async fn handle_data_response_invalid_inner_payload() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        let onion_data_response_payload = OnionDataResponsePayload {
            real_pk: gen_keypair().0,
            payload: vec![42; 123],
        };
        let (temporary_pk, temporary_sk) = gen_keypair();
        let onion_data_response = OnionDataResponse::new(&precompute(&onion_client.data_pk, &temporary_sk), temporary_pk, gen_nonce(), &onion_data_response_payload);

        let error = onion_client.handle_data_response(&onion_data_response).await.err().unwrap();
        assert_eq!(error.kind(), &HandleDataResponseErrorKind::InvalidInnerPayload);
    }

    #[tokio::test]
    async fn announce_loop_empty() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(MAX_ONION_ANNOUNCE_NODES as usize / 2);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        // make DHT connected so that we will build UDP onion paths
        dht.add_node(PackedNode::new("127.0.0.1:12345".parse().unwrap(), &gen_keypair().0));
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        let mut state = onion_client.state.lock();

        // map needed to decrypt onion packets later
        let mut key_by_addr = HashMap::new();
        let addr = "127.0.0.1".parse().unwrap();
        for i in 0 .. 3 {
            let saddr = SocketAddr::new(addr, 12346 + i);
            let (pk, sk) = gen_keypair();
            key_by_addr.insert(saddr, sk);
            let node = PackedNode::new(saddr, &pk);
            state.paths_pool.path_nodes.put(node);
        }

        onion_client.announce_loop(&mut state).await.unwrap();

        let data_pk = onion_client.data_pk;

        // Necessary to drop tx so that rx.collect() can be finished
        drop(state);
        drop(onion_client);

        let packets = udp_rx.collect::<Vec<_>>().await;

        assert!(!packets.is_empty());

        for (packet, addr_to_send) in packets {
            let packet = unpack!(packet, Packet::OnionRequest0);
            let payload = unpack_onion_packet(packet, addr_to_send, &key_by_addr);
            let packet = unpack!(payload.inner, InnerOnionRequest::InnerOnionAnnounceRequest);
            let payload = packet.get_payload(&precompute(&real_pk, &key_by_addr[&payload.ip_port.to_saddr()])).unwrap();
            assert_eq!(payload.ping_id, initial_ping_id());
            assert_eq!(payload.search_pk, real_pk);
            assert_eq!(payload.data_pk, data_pk);
        }
    }

    #[tokio::test]
    async fn announce_loop() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(MAX_ONION_ANNOUNCE_NODES as usize);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        // make DHT connected so that we will build UDP onion paths
        dht.add_node(PackedNode::new("127.0.0.1:12345".parse().unwrap(), &gen_keypair().0));
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        let mut state = onion_client.state.lock();

        // map needed to decrypt onion packets later
        let mut key_by_addr = HashMap::new();
        let addr = "127.0.0.1".parse().unwrap();
        for i in 0 .. 3 {
            let saddr = SocketAddr::new(addr, 12346 + i);
            let (pk, sk) = gen_keypair();
            key_by_addr.insert(saddr, sk);
            let node = PackedNode::new(saddr, &pk);
            state.paths_pool.path_nodes.put(node);
        }

        let ping_id = sha256::hash(&[1, 2, 3]);
        let now = Instant::now();

        let mut nodes_key_by_addr = HashMap::new();
        for i in 0 .. MAX_ONION_ANNOUNCE_NODES {
            let saddr = SocketAddr::new(addr, 23456 + u16::from(i));
            let path = state.paths_pool.path_nodes.udp_path().unwrap();
            let (node_pk, node_sk) = gen_keypair();
            nodes_key_by_addr.insert(saddr, node_sk);
            let node = OnionNode {
                pk: node_pk,
                saddr,
                path_id: path.id(),
                ping_id: Some(ping_id),
                data_pk: None,
                unsuccessful_pings: 0,
                added_time: now,
                ping_time: now,
                response_time: now,
                announce_status: AnnounceStatus::Failed,
            };
            assert!(state.announce_list.try_add(&real_pk, node, true));
        }

        tokio::time::pause();
        // time when entry is timed out
        tokio::time::advance(ANNOUNCE_INTERVAL_NOT_ANNOUNCED + Duration::from_secs(1)).await;

        onion_client.announce_loop(&mut state).await.unwrap();

        let data_pk = onion_client.data_pk;

        // Necessary to drop tx so that rx.collect() can be finished
        drop(state);
        drop(onion_client);

        let packets = udp_rx.collect::<Vec<_>>().await;

        assert_eq!(packets.len(), MAX_ONION_ANNOUNCE_NODES as usize);

        for (packet, addr_to_send) in packets {
            let packet = unpack!(packet, Packet::OnionRequest0);
            let payload = unpack_onion_packet(packet, addr_to_send, &key_by_addr);
            let packet = unpack!(payload.inner, InnerOnionRequest::InnerOnionAnnounceRequest);
            let payload = packet.get_payload(&precompute(&real_pk, &nodes_key_by_addr[&payload.ip_port.to_saddr()])).unwrap();
            assert_eq!(payload.ping_id, ping_id);
            assert_eq!(payload.search_pk, real_pk);
            assert_eq!(payload.data_pk, data_pk);
        }
    }

    #[tokio::test]
    async fn friends_loop_empty() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(MAX_ONION_ANNOUNCE_NODES as usize / 2);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        // make DHT connected so that we will build UDP onion paths
        dht.add_node(PackedNode::new("127.0.0.1:12345".parse().unwrap(), &gen_keypair().0));
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        let mut state = onion_client.state.lock();

        let (friend_pk, _friend_sk) = gen_keypair();
        let friend = OnionFriend::new(friend_pk);
        let friend_temporary_pk = friend.temporary_pk;
        state.friends.insert(friend_pk, friend);

        // map needed to decrypt onion packets later
        let mut key_by_addr = HashMap::new();
        let addr = "127.0.0.1".parse().unwrap();
        for i in 0 .. 3 {
            let saddr = SocketAddr::new(addr, 12346 + i);
            let (pk, sk) = gen_keypair();
            key_by_addr.insert(saddr, sk);
            let node = PackedNode::new(saddr, &pk);
            state.paths_pool.path_nodes.put(node);
        }

        onion_client.friends_loop(&mut state).await.unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(state);
        drop(onion_client);

        let packets = udp_rx.collect::<Vec<_>>().await;

        assert!(!packets.is_empty());

        for (packet, addr_to_send) in packets {
            let packet = unpack!(packet, Packet::OnionRequest0);
            let payload = unpack_onion_packet(packet, addr_to_send, &key_by_addr);
            let packet = unpack!(payload.inner, InnerOnionRequest::InnerOnionAnnounceRequest);
            let payload = packet.get_payload(&precompute(&friend_temporary_pk, &key_by_addr[&payload.ip_port.to_saddr()])).unwrap();
            assert_eq!(payload.ping_id, initial_ping_id());
            assert_eq!(payload.search_pk, friend_pk);
            assert_eq!(payload.data_pk, PublicKey([0; 32]));
        }
    }

    #[tokio::test]
    async fn friends_loop() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(MAX_ONION_FRIEND_NODES as usize);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        // make DHT connected so that we will build UDP onion paths
        dht.add_node(PackedNode::new("127.0.0.1:12345".parse().unwrap(), &gen_keypair().0));
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        let mut state = onion_client.state.lock();

        let (friend_pk, _friend_sk) = gen_keypair();
        let mut friend = OnionFriend::new(friend_pk);
        let friend_temporary_pk = friend.temporary_pk;

        // map needed to decrypt onion packets later
        let mut key_by_addr = HashMap::new();
        let addr = "127.0.0.1".parse().unwrap();
        for i in 0 .. 3 {
            let saddr = SocketAddr::new(addr, 12346 + i);
            let (pk, sk) = gen_keypair();
            key_by_addr.insert(saddr, sk);
            let node = PackedNode::new(saddr, &pk);
            state.paths_pool.path_nodes.put(node);
        }

        let now = Instant::now();

        let mut nodes_key_by_addr = HashMap::new();
        for i in 0 .. MAX_ONION_FRIEND_NODES {
            let saddr = SocketAddr::new(addr, 23456 + u16::from(i));
            let path = state.paths_pool.path_nodes.udp_path().unwrap();
            let (node_pk, node_sk) = gen_keypair();
            nodes_key_by_addr.insert(saddr, node_sk);
            let node = OnionNode {
                pk: node_pk,
                saddr,
                path_id: path.id(),
                // regardless of this ping_id search requests should contain 0
                ping_id: Some(sha256::hash(&[1, 2, 3])),
                data_pk: None,
                unsuccessful_pings: 0,
                added_time: now,
                ping_time: now,
                response_time: now,
                announce_status: AnnounceStatus::Failed,
            };
            assert!(friend.close_nodes.try_add(&real_pk, node, true));
        }

        state.friends.insert(friend_pk, friend);

        tokio::time::pause();
        // time when announce packet should be sent
        tokio::time::advance(ANNOUNCE_INTERVAL_NOT_ANNOUNCED + Duration::from_secs(1)).await;

        onion_client.friends_loop(&mut state).await.unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(state);
        drop(onion_client);

        let packets = udp_rx.collect::<Vec<_>>().await;

        assert_eq!(packets.len(), MAX_ONION_FRIEND_NODES as usize);

        for (packet, addr_to_send) in packets {
            let packet = unpack!(packet, Packet::OnionRequest0);
            let payload = unpack_onion_packet(packet, addr_to_send, &key_by_addr);
            let packet = unpack!(payload.inner, InnerOnionRequest::InnerOnionAnnounceRequest);
            let payload = packet.get_payload(&precompute(&friend_temporary_pk, &nodes_key_by_addr[&payload.ip_port.to_saddr()])).unwrap();
            assert_eq!(payload.ping_id, initial_ping_id());
            assert_eq!(payload.search_pk, friend_pk);
            assert_eq!(payload.data_pk, PublicKey([0; 32]));
        }
    }

    #[tokio::test]
    async fn friends_loop_ignore_online() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(MAX_ONION_FRIEND_NODES as usize);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        let mut state = onion_client.state.lock();

        let (friend_pk, _friend_sk) = gen_keypair();
        let mut friend = OnionFriend::new(friend_pk);
        friend.connected = true;

        let addr = "127.0.0.1".parse().unwrap();
        for i in 0 .. 3 {
            let saddr = SocketAddr::new(addr, 12346 + i);
            let (pk, _sk) = gen_keypair();
            let node = PackedNode::new(saddr, &pk);
            state.paths_pool.path_nodes.put(node);
        }

        let now = Instant::now();

        for i in 0 .. MAX_ONION_FRIEND_NODES {
            let saddr = SocketAddr::new(addr, 23456 + u16::from(i));
            let path = state.paths_pool.path_nodes.udp_path().unwrap();
            let (node_pk, _node_sk) = gen_keypair();
            let node = OnionNode {
                pk: node_pk,
                saddr,
                path_id: path.id(),
                ping_id: None,
                data_pk: None,
                unsuccessful_pings: 0,
                added_time: now,
                ping_time: now,
                response_time: now,
                announce_status: AnnounceStatus::Failed,
            };
            assert!(friend.close_nodes.try_add(&real_pk, node, true));
        }

        state.friends.insert(friend_pk, friend);

        tokio::time::pause();
        // time when announce packet should be sent
        tokio::time::advance(ANNOUNCE_INTERVAL_NOT_ANNOUNCED + Duration::from_secs(1)).await;

        onion_client.friends_loop(&mut state).await.unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(state);
        drop(onion_client);

        assert!(udp_rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn send_dht_pk_onion() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(MAX_ONION_FRIEND_NODES as usize);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        let mut state = onion_client.state.lock();

        let (friend_pk, friend_sk) = gen_keypair();
        let mut friend = OnionFriend::new(friend_pk);

        // map needed to decrypt onion packets later
        let mut key_by_addr = HashMap::new();
        let addr = "127.0.0.1".parse().unwrap();
        for i in 0 .. 3 {
            let saddr = SocketAddr::new(addr, 12346 + i);
            let (pk, sk) = gen_keypair();
            key_by_addr.insert(saddr, sk);
            let node = PackedNode::new(saddr, &pk);
            state.paths_pool.path_nodes.put(node);
        }

        let now = Instant::now();

        let (data_pk, data_sk) = gen_keypair();
        let mut nodes_key_by_addr = HashMap::new();
        for i in 0 .. MAX_ONION_FRIEND_NODES {
            let saddr = SocketAddr::new(addr, 23456 + u16::from(i));
            let path = state.paths_pool.path_nodes.udp_path().unwrap();
            let (node_pk, node_sk) = gen_keypair();
            nodes_key_by_addr.insert(saddr, node_sk);
            let node = OnionNode {
                pk: node_pk,
                saddr,
                path_id: path.id(),
                ping_id: None,
                data_pk: Some(data_pk),
                unsuccessful_pings: 0,
                added_time: now,
                ping_time: now,
                response_time: now,
                announce_status: AnnounceStatus::Failed,
            };
            assert!(friend.close_nodes.try_add(&real_pk, node, true));
        }

        state.friends.insert(friend_pk, friend);

        let mut dht_close_nodes = onion_client.dht.close_nodes.write();
        for i in 0 .. 4 {
            let saddr = SocketAddr::new(addr, 23456 + i);
            let (node_pk, _node_sk) = gen_keypair();
            let node = PackedNode::new(saddr, &node_pk);
            assert!(dht_close_nodes.try_add(node));
        }
        drop(dht_close_nodes);

        onion_client.friends_loop(&mut state).await.unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(state);
        drop(onion_client);

        let packets = udp_rx.collect::<Vec<_>>().await;

        assert_eq!(packets.len(), MAX_ONION_FRIEND_NODES as usize);

        for (packet, addr_to_send) in packets {
            let packet = unpack!(packet, Packet::OnionRequest0);
            let payload = unpack_onion_packet(packet, addr_to_send, &key_by_addr);
            let packet = unpack!(payload.inner, InnerOnionRequest::InnerOnionDataRequest);
            assert_eq!(packet.destination_pk, friend_pk);
            let payload = packet.get_payload(&precompute(&packet.temporary_pk, &data_sk)).unwrap();
            assert_eq!(payload.real_pk, real_pk);
            let payload = payload.get_payload(&packet.nonce, &precompute(&real_pk, &friend_sk)).unwrap();
            let payload = unpack!(payload, OnionDataResponseInnerPayload::DhtPkAnnounce);
            assert_eq!(payload.dht_pk, dht_pk);
            assert_eq!(payload.nodes.len(), 4);
        }
    }

    #[tokio::test]
    async fn send_dht_pk_dht_request() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(MAX_ONION_FRIEND_NODES as usize);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk.clone(), real_pk);

        let mut state = onion_client.state.lock();

        let (friend_pk, friend_sk) = gen_keypair();
        let (friend_dht_pk, friend_dht_sk) = gen_keypair();
        let mut friend = OnionFriend::new(friend_pk);
        friend.dht_pk = Some(friend_dht_pk);
        state.friends.insert(friend_pk, friend);

        let addr = "127.0.0.1".parse().unwrap();
        let mut dht_close_nodes = onion_client.dht.close_nodes.write();
        for i in 0 .. 8 {
            let saddr = SocketAddr::new(addr, 23456 + i);
            let (node_pk, _node_sk) = gen_keypair();
            let node = PackedNode::new(saddr, &node_pk);
            assert!(dht_close_nodes.try_add(node));
        }
        drop(dht_close_nodes);

        onion_client.friends_loop(&mut state).await.unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(state);
        drop(onion_client);

        let packets = udp_rx.collect::<Vec<_>>().await;

        assert_eq!(packets.len(), 8);

        for (packet, _addr_to_send) in packets {
            let packet = unpack!(packet, Packet::DhtRequest);
            assert_eq!(packet.rpk, friend_dht_pk);
            assert_eq!(packet.spk, dht_pk);
            let payload = packet.get_payload(&precompute(&dht_pk, &friend_dht_sk)).unwrap();
            let packet = unpack!(payload, DhtRequestPayload::DhtPkAnnounce);
            assert_eq!(packet.real_pk, real_pk);
            let payload = packet.get_payload(&precompute(&real_pk, &friend_sk)).unwrap();
            assert_eq!(payload.dht_pk, dht_pk);
        }
    }

    #[tokio::test]
    async fn populate_path_nodes() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk, real_pk);

        let (node_pk, node_sk) = gen_keypair();
        let node = PackedNode::new("127.0.0.1:12345".parse().unwrap(), &node_pk);

        // add node to DHT server via responding to NodesRequest
        onion_client.dht.ping_node(&node).await.unwrap();
        let (received, _udp_rx) = udp_rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();
        assert_eq!(addr_to_send, node.saddr);
        let shared_secret = precompute(&dht_pk, &node_sk);
        let request_packet = unpack!(packet, Packet::NodesRequest);
        let request_payload = request_packet.get_payload(&shared_secret).unwrap();
        let response_payload = NodesResponsePayload {
            nodes: vec![],
            id: request_payload.id,
        };
        let response_packet = NodesResponse::new(&shared_secret, &node_pk, &response_payload);
        onion_client.dht.handle_packet(Packet::NodesResponse(response_packet), node.saddr).await.unwrap();

        let mut state = onion_client.state.lock();

        onion_client.populate_path_nodes(&mut state);

        assert!(state.paths_pool.path_nodes.rand().is_some());
    }

    #[tokio::test]
    async fn send_onion_request_udp() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk, real_pk);

        let inner_onion_request = InnerOnionRequest::InnerOnionAnnounceRequest(InnerOnionAnnounceRequest {
            nonce: gen_nonce(),
            pk: gen_keypair().0,
            payload: vec![42; 123],
        });

        let path = OnionPath::new([
            PackedNode::new("127.0.0.1:12346".parse().unwrap(), &gen_keypair().0),
            PackedNode::new("127.0.0.1:12347".parse().unwrap(), &gen_keypair().0),
            PackedNode::new("127.0.0.1:12348".parse().unwrap(), &gen_keypair().0),
        ], OnionPathType::UDP);
        let saddr = "127.0.0.1:12345".parse().unwrap();
        onion_client.send_onion_request(path, inner_onion_request, saddr).await.unwrap();

        let (_received, _udp_rx) = udp_rx.into_future().await;
    }

    #[tokio::test]
    async fn send_onion_request_tcp() {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let (_relay_incoming_rx, relay_outgoing_rx, relay_pk) = tcp_connections.add_client();
        let onion_client = OnionClient::new(dht, tcp_connections, real_sk, real_pk);

        let inner_onion_request = InnerOnionRequest::InnerOnionAnnounceRequest(InnerOnionAnnounceRequest {
            nonce: gen_nonce(),
            pk: gen_keypair().0,
            payload: vec![42; 123],
        });

        let path = OnionPath::new([
            PackedNode::new("127.0.0.1:12346".parse().unwrap(), &relay_pk),
            PackedNode::new("127.0.0.1:12347".parse().unwrap(), &gen_keypair().0),
            PackedNode::new("127.0.0.1:12348".parse().unwrap(), &gen_keypair().0),
        ], OnionPathType::TCP);
        let saddr = "127.0.0.1:12345".parse().unwrap();
        onion_client.send_onion_request(path, inner_onion_request, saddr).await.unwrap();

        let (_received, _relay_outgoing_rx) = relay_outgoing_rx.into_future().await;

        // Necessary to drop tx so that rx.collect() can be finished
        drop(onion_client);

        assert!(udp_rx.collect::<Vec<_>>().await.is_empty());
    }
}
