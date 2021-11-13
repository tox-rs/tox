/*!
Functionality needed to work as a DHT node.
This module works on top of other modules.
*/

pub mod hole_punching;
pub mod errors;

use futures::{TryFutureExt, StreamExt, SinkExt, future};
use futures::channel::mpsc;
use tokio::sync::RwLock;
use rand::{Rng, prelude::SliceRandom, thread_rng};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{iter, mem};
use xsalsa20poly1305::{XSalsa20Poly1305, aead::NewAead};

use crate::time::*;
use tox_crypto::*;
use tox_packet::dht::*;
use tox_packet::dht::packed_node::*;
use crate::dht::kbucket::*;
use crate::dht::ktree::*;
use crate::dht::forced_ktree::*;
use crate::dht::precomputed_cache::*;
use tox_packet::onion::*;
use crate::onion::onion_announce::*;
use crate::dht::request_queue::*;
use tox_packet::ip_port::*;
use crate::dht::dht_friend::*;
use crate::dht::dht_node::*;
use crate::dht::server::hole_punching::*;
use tox_packet::relay::OnionRequest;
use crate::dht::ip_port::IsGlobal;
use crate::utils::*;
use crate::dht::server::errors::*;
use crate::io_tokio::*;

/// Shorthand for the transmit half of the message channel.
type Tx = mpsc::Sender<(Packet, SocketAddr)>;

/// Shorthand for the transmit half of the TCP onion channel.
type TcpOnionTx = mpsc::Sender<(InnerOnionResponse, SocketAddr)>;

/// Number of random `NodesRequest` packet to send every second one per second.
/// After random requests count exceeds this number `NODES_REQ_INTERVAL` will be
/// used.
pub const MAX_BOOTSTRAP_TIMES: u32 = 5;
/// How often onion key should be refreshed.
pub const ONION_REFRESH_KEY_INTERVAL: Duration = Duration::from_secs(7200);
/// Interval for random `NodesRequest`.
pub const NODES_REQ_INTERVAL: Duration = Duration::from_secs(20);
/// Ping timeout in seconds.
pub const PING_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum newly announced nodes to ping per `TIME_TO_PING`.
pub const MAX_TO_PING: u8 = 32;
/// Maximum nodes to send `NodesRequest` packet.
pub const MAX_TO_BOOTSTRAP: u8 = 8;
/// How often to ping newly announced nodes.
pub const TIME_TO_PING: Duration = Duration::from_secs(2);
/// How often to ping initial bootstrap nodes.
pub const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(1);
/// Number of fake friends that server has.
pub const FAKE_FRIENDS_NUMBER: usize = 2;
/// Maximum number of entry in Lru cache for precomputed keys.
pub const PRECOMPUTED_LRU_CACHE_SIZE: usize = KBUCKET_DEFAULT_SIZE as usize * KBUCKET_MAX_ENTRIES as usize + // For KTree.
    KBUCKET_DEFAULT_SIZE as usize * (2 + 10); // For friend's close_nodes of 2 fake friends + 10 friends reserved
/// How often DHT main loop should be called.
const MAIN_LOOP_INTERVAL: u64 = 1;

/// Struct that contains necessary data for `BootstrapInfo` packet.
#[derive(Clone)]
struct ServerBootstrapInfo {
    /// Version of tox core which will be sent with `BootstrapInfo` packet.
    version: u32,
    /// Callback to get the message of the day which will be sent with
    /// `BootstrapInfo` packet.
    motd_cb: Arc<dyn Fn(&Server) -> Vec<u8> + Send + Sync>,
}

/// DHT server state.
#[derive(Clone)]
struct ServerState {
    /// Struct that stores and manages requests IDs and timeouts.
    request_queue: RequestQueue<PublicKey>,
    /// Friends list used to store friends related data like close nodes per
    /// friend, hole punching status, etc. First FAKE_FRIENDS_NUMBER friends
    /// are fake with random public key.
    friends: HashMap<PublicKey, DhtFriend>,
    /// List of nodes to send `NodesRequest` packet. When we receive
    /// `NodesResponse` packet we should send `NodesRequest` to all nodes from
    /// the response to check if they are capable of handling our requests and
    /// to continue bootstrapping. But instead of instant sending `NodesRequest`
    /// we will add the node to this list which is processed every second. The
    /// purpose of this is to prevent amplification attacks.
    nodes_to_bootstrap: Kbucket<PackedNode>,
    /// Close nodes list which contains nodes close to own DHT `PublicKey`.
    close_nodes: ForcedKtree,
    /// How many times we sent `NodesRequest` packet to a random node from close
    /// nodes list.
    random_requests_count: u32,
    /// Time when we sent `NodesRequest` packet to a random node from close
    /// nodes list.
    last_nodes_req_time: Instant,
}

impl ServerState {
    /// Adapt `RequestQueue.check_ping_id()`.
    fn check_ping_id(&mut self, ping_id: u64, packet_pk: &PublicKey) -> bool {
        self.request_queue.check_ping_id(ping_id, |pk| packet_pk.eq(pk)).is_some()
    }
}

/**
Own DHT node data.

Contains:

- DHT public key
- DHT secret key
- Close List ([`ForcedKtree`] with nodes close to own DHT public key)

Before a [`PackedNode`] is added to the Close List, it needs to be
checked whether:

- it can be added to [`ForcedKtree`] \(using [`ForcedKtree::can_add()`])
- [`PackedNode`] is actually online

Once the first check passes node is added to the temporary list, and
a [`NodesRequest`] request is sent to it in order to check whether it's
online. If the node responds correctly within [`PING_TIMEOUT`], it's
removed from temporary list and added to the Close List.

[`NodesRequest`]: ../dht/struct.NodesRequest.html
[`ForcedKtree`]: ../dht/struct.ForcedKtree.html
[`ForcedKtree::can_add()`]: ../dht/struct.ForcedKtree.html#method.can_add
[`PackedNode`]: ../dht/struct.PackedNode.html
*/
#[derive(Clone)]
pub struct Server {
    /// DHT `SecretKey`.
    pub sk: SecretKey,
    /// DHT `PublicKey`.
    pub pk: PublicKey,
    /// Tx split of a channel to send packets to this peer via UDP socket.
    pub tx: Tx,
    /// DHT server state
    state: Arc<RwLock<ServerState>>,
    /// Sink to send friend's `SocketAddr` when it gets known.
    friend_saddr_sink: Arc<RwLock<Option<mpsc::UnboundedSender<PackedNode>>>>,
    /// Symmetric key used for onion return encryption.
    onion_symmetric_key: Arc<RwLock<XSalsa20Poly1305>>,
    /// Onion announce struct to handle `OnionAnnounce` and `OnionData` packets.
    onion_announce: Arc<RwLock<OnionAnnounce>>,
    /// `PublicKey`s of fake friends. They serve two purposes:
    /// - server will send NodesRequest packets with these 2 random keys
    ///   periodically thereby it will fill Ktree with farther nodes and speed
    ///   up bootstrap process.
    /// - close nodes of these two friends can be used as pool of random nodes
    /// for onion client.
    fake_friends_keys: Vec<PublicKey>,
    /// List of nodes to send `PingRequest`. When we receive `PingRequest` or
    /// `NodesRequest` packet from a new node we should send `PingRequest` to
    /// this node to check if it's capable of handling our requests. But instead
    /// of instant sending `PingRequest` we will add the node to this list which
    /// is processed every `TIME_TO_PING`. The purpose of this is to
    /// prevent amplification attacks.
    nodes_to_ping: Arc<RwLock<Kbucket<PackedNode>>>,
    /// Info used to respond to `BootstrapInfo` packets.
    bootstrap_info: Option<ServerBootstrapInfo>,
    /// `OnionResponse1` packets that have TCP protocol kind inside onion return
    /// should be redirected to TCP sender trough this sink
    /// None if there is no TCP relay
    tcp_onion_sink: Option<TcpOnionTx>,
    /// If LAN discovery is enabled `Server` will handle `LanDiscovery` packets
    /// and send `NodesRequest` packets in reply.
    lan_discovery_enabled: bool,
    /// If IPv6 mode is enabled `Server` will send packets to IPv6 addresses. If
    /// it's disabled such packets will be dropped.
    is_ipv6_enabled: bool,
    /// Initial bootstrap nodes list. We send `NodesRequest` packet to each node
    /// from this list if Ktree doesn't have good (or bad but not discarded)
    /// nodes.
    initial_bootstrap: Vec<PackedNode>,
    /// Lru cache for precomputed keys. It stores precomputed keys to avoid
    /// redundant calculations.
    precomputed_keys: PrecomputedCache,
}

impl Server {
    /// Create new `Server` instance.
    pub fn new(tx: Tx, pk: PublicKey, sk: SecretKey) -> Server {
        debug!("Created new Server instance");

        let mut rng = thread_rng();
        let fake_friends_keys = iter::repeat_with(|| SecretKey::generate(&mut rng).public_key())
            .take(FAKE_FRIENDS_NUMBER)
            .collect::<Vec<_>>();
        let friends = fake_friends_keys.iter()
            .map(|pk| (pk.clone(), DhtFriend::new(&mut rng, pk.clone())))
            .collect();

        let precomputed_keys = PrecomputedCache::new(sk.clone(), PRECOMPUTED_LRU_CACHE_SIZE);
        let onion_symmetric_key = XSalsa20Poly1305::new(&XSalsa20Poly1305::generate_key(&mut rng));

        let state = ServerState {
            request_queue: RequestQueue::new(PING_TIMEOUT),
            friends,
            nodes_to_bootstrap: Kbucket::new(MAX_TO_BOOTSTRAP),
            close_nodes: ForcedKtree::new(pk.clone()),
            random_requests_count: 0,
            last_nodes_req_time: clock_now(),
        };

        Server {
            sk,
            pk: pk.clone(),
            tx,
            state: Arc::new(RwLock::new(state)),
            friend_saddr_sink: Default::default(),
            onion_symmetric_key: Arc::new(RwLock::new(onion_symmetric_key)),
            onion_announce: Arc::new(RwLock::new(OnionAnnounce::new(&mut rng, pk))),
            fake_friends_keys,
            nodes_to_ping: Arc::new(RwLock::new(Kbucket::new(MAX_TO_PING))),
            bootstrap_info: None,
            tcp_onion_sink: None,
            lan_discovery_enabled: true,
            is_ipv6_enabled: false,
            initial_bootstrap: Vec::new(),
            precomputed_keys,
        }
    }

    /// Enable/disable IPv6 mode of DHT server.
    pub fn enable_ipv6_mode(&mut self, enable: bool) {
        self.is_ipv6_enabled = enable;
    }

    /// Get is_ipv6_enabled member variable
    pub fn is_ipv6_enabled(&self) -> bool {
        self.is_ipv6_enabled
    }

    /// Enable/disable `LanDiscovery` packets handling.
    pub fn enable_lan_discovery(&mut self, enable: bool) {
        self.lan_discovery_enabled = enable;
    }

    /// Check if we have at least one node in good state.
    pub async fn is_connected(&self) -> bool {
        self.state.read()
            .await
            .close_nodes
            .iter()
            .any(|node| !node.is_bad())
    }

    /// Get all known nodes.
    pub async fn get_all_nodes(&self) -> Vec<PackedNode> {
        let state = self.state.read().await;

        state.close_nodes.iter()
            .flat_map(|node| node.to_packed_node())
            .collect::<Vec<PackedNode>>()
    }

    /// Get closest nodes from both close_nodes and friend's close_nodes
    fn get_closest_inner(
        close_nodes: &ForcedKtree,
        friends: &HashMap<PublicKey, DhtFriend>,
        base_pk: &PublicKey,
        count: u8,
        only_global: bool
    ) -> Kbucket<PackedNode> {
        let mut kbucket = close_nodes.get_closest(base_pk, count, only_global);

        for node in friends.values().flat_map(|friend| friend.close_nodes.iter()) {
            if let Some(pn) = node.to_packed_node() {
                if !only_global || IsGlobal::is_global(&pn.saddr.ip()) {
                    kbucket.try_add(base_pk, pn, /* evict */ true);
                }
            }
        }

        kbucket
    }

    /// Get closest nodes from both close_nodes and friend's close_nodes
    pub async fn get_closest(&self, base_pk: &PublicKey, count: u8, only_global: bool) -> Kbucket<PackedNode> {
        let state = self.state.read().await;

        Server::get_closest_inner(&state.close_nodes, &state.friends, base_pk, count, only_global)
    }

    /// Add a friend to the DHT friends list to look for it's IP address. After
    /// IP address it will be sent to `friend_saddr_sink`.
    pub async fn add_friend(&self, friend_pk: PublicKey) {
        let mut state = self.state.write().await;

        if state.friends.contains_key(&friend_pk) {
            return;
        }

        let mut friend = DhtFriend::new(&mut thread_rng(), friend_pk.clone());
        let close_nodes = Server::get_closest_inner(&state.close_nodes, &state.friends, &friend.pk, 4, true);

        for node in close_nodes.iter() {
            friend.nodes_to_bootstrap.try_add(&friend.pk, node.clone(), /* evict */ true);
        }

        state.friends.insert(friend_pk, friend);
    }

    /// Remove a friend from the DHT friends list to stop looking for it's IP
    /// address.
    pub async fn remove_friend(&self, friend_pk: PublicKey) {
        self.state.write().await.friends.remove(&friend_pk);
    }

    /// The main loop of DHT server which should be called every second. This
    /// method iterates over all nodes from close nodes list, close nodes of
    /// friends and bootstrap nodes and sends `NodesRequest` packets if
    /// necessary.
    async fn dht_main_loop(&self) -> Result<(), RunError> {
        // Check if we should send `NodesRequest` packet to a random node. This
        // request is sent every second 5 times and then every 20 seconds.
        fn send_random_request(last_nodes_req_time: &mut Instant, random_requests_count: &mut u32) -> bool {
            if clock_elapsed(*last_nodes_req_time) > NODES_REQ_INTERVAL || *random_requests_count < MAX_BOOTSTRAP_TIMES {
                *random_requests_count = random_requests_count.saturating_add(1);
                *last_nodes_req_time = clock_now();
                true
            } else {
                false
            }
        }

        let state = &mut *self.state.write().await;

        state.request_queue.clear_timed_out();

        // Send NodesRequest packets to nodes from the Server
        self.ping_nodes_to_bootstrap(&mut state.request_queue, &mut state.nodes_to_bootstrap, self.pk.clone()).await
            .map_err(RunError::SendTo)?;
        self.ping_close_nodes(&mut state.request_queue, state.close_nodes.iter_mut(), self.pk.clone()).await
            .map_err(RunError::SendTo)?;
        if send_random_request(&mut state.last_nodes_req_time, &mut state.random_requests_count) {
            self.send_nodes_req_random(&mut state.request_queue, state.close_nodes.iter(), self.pk.clone()).await
                .map_err(RunError::SendTo)?;
        }

        // Send NodesRequest packets to nodes from every DhtFriend
        for friend in state.friends.values_mut() {
            self.ping_nodes_to_bootstrap(&mut state.request_queue, &mut friend.nodes_to_bootstrap, friend.pk.clone()).await
                .map_err(RunError::SendTo)?;
            self.ping_close_nodes(&mut state.request_queue, friend.close_nodes.nodes.iter_mut(), friend.pk.clone()).await
                .map_err(RunError::SendTo)?;
            if send_random_request(&mut friend.last_nodes_req_time, &mut friend.random_requests_count) {
                self.send_nodes_req_random(&mut state.request_queue, friend.close_nodes.nodes.iter(), friend.pk.clone()).await
                    .map_err(RunError::SendTo)?
            }
        }

        self.send_nat_ping_req(&mut state.request_queue, &mut state.friends).await
            .map_err(RunError::SendTo)
    }

    /// Run DHT periodical tasks. Result future will never be completed
    /// successfully.
    pub async fn run(&self) -> Result<(), RunError> {
        let (r1, r2, r3, r4) = futures::join!(
            self.run_pings_sending(),
            self.run_onion_key_refreshing(),
            self.run_main_loop(),
            self.run_bootstrap_requests_sending(),
        );

        r1?; r2?; r3?; r4?;

        Ok(())
    }

    /// Store bootstap nodes
    pub fn add_initial_bootstrap(&mut self, pn: PackedNode) {
        self.initial_bootstrap.push(pn);
    }

    /// Run initial bootstrapping. It sends `NodesRequest` packet to bootstrap
    /// nodes periodically if all nodes in Ktree are discarded (including the
    /// case when it's empty). It has to be an endless loop because we might
    /// loose the network connection and thereby loose all nodes in Ktree.
    async fn run_bootstrap_requests_sending(&self) -> Result<(), RunError> {
        let interval = BOOTSTRAP_INTERVAL;
        let mut wakeups = tokio::time::interval(interval);

        loop {
            wakeups.tick().await;

            trace!("Bootstrap wake up");
            let send_res = tokio::time::timeout(
                interval,
                self.send_bootstrap_requests(),
            ).await;

            let res =
                match send_res {
                    Ok(Ok(_)) => Ok(()),
                    Ok(Err(e)) =>
                        Err(RunError::SendTo(e)),
                    Err(e) =>
                        Err(RunError::Timeout(e)),
                };

            if let Err(ref e) = res {
                warn!("Failed to send initial bootstrap packets: {}", e);

                return res
            }
        }
    }

    /// Check if all nodes in Ktree are discarded (including the case when
    /// it's empty) and if so then send `NodesRequest` packet to nodes from
    /// initial bootstrap list and from Ktree.
    async fn send_bootstrap_requests(&self) -> Result<(), mpsc::SendError> {
        let state = &mut *self.state.write().await;

        if !state.close_nodes.is_all_discarded() {
            return Ok(());
        }

        let nodes = state.close_nodes
            .iter()
            .flat_map(|node| node.to_all_packed_nodes())
            .chain(self.initial_bootstrap.iter().cloned());

        for node in nodes {
            self.send_nodes_req(node, &mut state.request_queue, self.pk.clone()).await?;
        }

        Ok(())
    }

    /// Run DHT main loop periodically. Result future will never be completed
    /// successfully.
    async fn run_main_loop(&self) -> Result<(), RunError> {
        let interval = Duration::from_secs(MAIN_LOOP_INTERVAL);
        let mut wakeups = tokio::time::interval(interval);

        loop {
            wakeups.tick().await;

            trace!("DHT server wake up");

            let loop_res =
                tokio::time::timeout(interval, self.dht_main_loop()).await;

            let res = match loop_res {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) =>
                    Err(e),
                Err(e) =>
                    Err(RunError::Timeout(e)),
            };

            if let Err(ref e) = res {
                warn!("Failed to send DHT periodical packets: {}", e);
                return res
            }
        }
    }

    /// Refresh onion symmetric key periodically. Result future will never be
    /// completed successfully.
    async fn run_onion_key_refreshing(&self) -> Result<(), RunError> {
        let interval = ONION_REFRESH_KEY_INTERVAL;
        let mut wakeups = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);

        loop {
            wakeups.tick().await;

            trace!("Refreshing onion key");
            self.refresh_onion_key().await;
        }
    }

    /// Run ping sending periodically. Result future will never be completed
    /// successfully.
    async fn run_pings_sending(&self) -> Result<(), RunError> {
        let interval = TIME_TO_PING;
        let mut wakeups = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);

        loop {
            wakeups.tick().await;

            self.send_pings().await
                .map_err(RunError::SendTo)?;
        }
    }

    /// Send `PingRequest` packets to nodes from `nodes_to_ping` list.
    async fn send_pings(&self) -> Result<(), mpsc::SendError> {
        let nodes_to_ping = mem::replace(
            &mut *self.nodes_to_ping.write().await,
            Kbucket::<PackedNode>::new(MAX_TO_PING)
        );

        if nodes_to_ping.is_empty() {
            return Ok(());
        }

        let mut state = self.state.write().await;

        for node in nodes_to_ping.iter() {
            self.send_ping_req(node.clone(), &mut state.request_queue).await?;
        }

        Ok(())
    }

    /// Add node to a `nodes_to_ping` list to send ping later. If node is
    /// a friend and we don't know it's address then this method will send
    /// `PingRequest` immediately instead of adding to a `nodes_to_ping`
    /// list.
    async fn ping_add(&self, node: PackedNode) -> Result<(), mpsc::SendError> {
        let mut state = self.state.write().await;

        if !state.close_nodes.can_add(&node) {
            return Ok(());
        }

        // If node is friend and we don't know friend's IP address yet then send
        // PingRequest immediately and unconditionally
        if state.friends.get(&node.pk).map_or(false, |friend| !friend.is_addr_known()) {
            return self.send_ping_req(node.clone(), &mut state.request_queue).await;
        }

        self.nodes_to_ping.write().await.try_add(&self.pk, node, /* evict */ true);

        Ok(())
    }

    /// Send `NodesRequest` packets to nodes from bootstrap list. This is
    /// necessary to check whether node is alive before adding it to close
    /// nodes lists.
    async fn ping_nodes_to_bootstrap(&self, request_queue: &mut RequestQueue<PublicKey>, nodes_to_bootstrap: &mut Kbucket<PackedNode>, pk: PublicKey)
        -> Result<(), mpsc::SendError> {
        let capacity = nodes_to_bootstrap.capacity() as u8;
        let nodes_to_bootstrap = mem::replace(nodes_to_bootstrap, Kbucket::new(capacity));

        for node in nodes_to_bootstrap.iter() {
            self.send_nodes_req(node.clone(), request_queue, pk.clone()).await?;
        }

        Ok(())
    }

    /// Iterate over nodes from close nodes list and send `NodesRequest` packets
    /// to them if necessary.
    async fn ping_close_nodes<'a, T>(&self, request_queue: &mut RequestQueue<PublicKey>, nodes: T, pk: PublicKey)
        -> Result<(), mpsc::SendError>
        where T: Iterator<Item = &'a mut DhtNode>
    {
        let nodes = nodes
            .flat_map(|node| {
                let ping_addr_v4 = node.assoc4
                    .ping_addr()
                    .map(|addr| PackedNode::new(addr.into(), node.pk.clone()));
                let ping_addr_v6 = node.assoc6
                    .ping_addr()
                    .map(|addr| PackedNode::new(addr.into(), node.pk.clone()));
                ping_addr_v4.into_iter().chain(ping_addr_v6.into_iter())
            });

        for node in nodes {
            self.send_nodes_req(node.clone(), request_queue, pk.clone()).await?;
        }

        Ok(())
    }

    /// Send `NodesRequest` packet to a random good node every 20 seconds or if
    /// it was sent less than `NODES_REQ_INTERVAL`. This function should be
    /// called every second.
    async fn send_nodes_req_random<'a, T>(&self, request_queue: &mut RequestQueue<PublicKey>, nodes: T, pk: PublicKey)
        -> Result<(), mpsc::SendError>
        where T: Iterator<Item = &'a DhtNode>
    {
        let good_nodes = nodes
            .filter(|&node| !node.is_bad())
            .flat_map(|node| node.to_all_packed_nodes())
            .collect::<Vec<_>>();

        if good_nodes.is_empty() {
            // Random request should be sent only to good nodes
            return Ok(());
        }

        let rng = &mut thread_rng();
        let mut random_node_idx = rng.gen_range(0 .. good_nodes.len());
        // Increase probability of sending packet to a close node (has lower index)
        if random_node_idx != 0 {
            random_node_idx -= rng.gen_range(0 ..= random_node_idx);
        }

        let random_node = good_nodes[random_node_idx].clone();

        self.send_nodes_req(random_node, request_queue, pk).await
    }

    /// Ping node with `NodesRequest` packet with self DHT `PublicKey`.
    pub async fn ping_node(&self, node: PackedNode) -> Result<(), PingError> {
        let mut state = self.state.write().await;
        self.send_nodes_req(node, &mut state.request_queue, self.pk.clone())
            .await
            .map_err(PingError::SendTo)
    }

    /// Send `PingRequest` packet to the node.
    async fn send_ping_req(&self, node: PackedNode, request_queue: &mut RequestQueue<PublicKey>)
        -> Result<(), mpsc::SendError> {
        let payload = PingRequestPayload {
            id: request_queue.new_ping_id(&mut thread_rng(), node.pk.clone()),
        };
        let ping_req = Packet::PingRequest(PingRequest::new(
            &self.precomputed_keys.get(node.pk).await,
            self.pk.clone(),
            &payload,
        ));
        self.send_to(node.saddr, ping_req).await
    }

    /// Send `NodesRequest` packet to the node.
    async fn send_nodes_req(&self, node: PackedNode, request_queue: &mut RequestQueue<PublicKey>, search_pk: PublicKey)
        -> Result<(), mpsc::SendError> {
        // Check if packet is going to be sent to ourselves.
        if self.pk == node.pk {
            trace!("Attempt to send NodesRequest to ourselves.");
            return Ok(());
        }

        let payload = NodesRequestPayload {
            pk: search_pk,
            id: request_queue.new_ping_id(&mut thread_rng(), node.pk.clone()),
        };
        let nodes_req = Packet::NodesRequest(NodesRequest::new(
            &self.precomputed_keys.get(node.pk).await,
            self.pk.clone(),
            &payload,
        ));
        self.send_to(node.saddr, nodes_req).await
    }

    /// Send `NatPingRequest` packet to all friends and try to punch holes.
    async fn send_nat_ping_req(&self, request_queue: &mut RequestQueue<PublicKey>, friends: &mut HashMap<PublicKey, DhtFriend>)
        -> Result<(), mpsc::SendError> {
        for friend in friends.values_mut() {
            if friend.is_addr_known() {
                continue;
            }

            let addrs = friend.get_returned_addrs();

            if addrs.len() < FRIEND_CLOSE_NODES_COUNT as usize / 2 {
                continue;
            }

            self.punch_holes(request_queue, friend, &addrs).await?;

            if friend.hole_punch.last_send_ping_time.map_or(true, |time| clock_elapsed(time) >= PUNCH_INTERVAL) {
                friend.hole_punch.last_send_ping_time = Some(clock_now());
                let payload = DhtRequestPayload::NatPingRequest(NatPingRequest {
                    id: friend.hole_punch.ping_id,
                });
                let nat_ping_req_packet = DhtRequest::new(
                    &self.precomputed_keys.get(friend.pk.clone()).await,
                    friend.pk.clone(),
                    self.pk.clone(),
                    &payload,
                );
                self.send_nat_ping_req_inner(friend, nat_ping_req_packet).await?;
            }
        }

        Ok(())
    }

    /// Try to punch holes to specified friend.
    async fn punch_holes(&self, request_queue: &mut RequestQueue<PublicKey>, friend: &mut DhtFriend, returned_addrs: &[SocketAddr])
        -> Result<(), mpsc::SendError> {
        let punch_addrs = friend.hole_punch.next_punch_addrs(returned_addrs);
        let mut tx = self.tx.clone();
        let payload = PingRequestPayload {
            id: request_queue.new_ping_id(&mut thread_rng(), friend.pk.clone()),
        };
        let packet = Packet::PingRequest(PingRequest::new(
            &self.precomputed_keys.get(friend.pk.clone()).await,
            self.pk.clone(),
            &payload,
        ));

        let packets = punch_addrs.into_iter().map(|addr| {
            (packet.clone(), addr)
        }).collect::<Vec<_>>();

        let mut stream = futures::stream::iter(packets).map(Ok);
        tx.send_all(&mut stream).await
    }

    /// Send `NatPingRequest` packet to all close nodes of friend in the hope
    /// that they will redirect it to this friend.
    async fn send_nat_ping_req_inner(&self, friend: &DhtFriend, nat_ping_req_packet: DhtRequest)
        -> Result<(), mpsc::SendError> {
        let packet = Packet::DhtRequest(nat_ping_req_packet);
        let nodes = friend.close_nodes.nodes
            .iter()
            .flat_map(|node| node.to_packed_node().into_iter());

        for node in nodes {
            self.send_to(node.saddr, packet.clone()).await?;
        }

        Ok(())
    }

    /// Send UDP packet to specified address.
    async fn send_to(&self, addr: SocketAddr, packet: Packet) -> Result<(), mpsc::SendError> {
        self.tx.clone().send((packet, addr)).await
    }

    /// Handle received `PingRequest` packet and response with `PingResponse`
    /// packet. If node that sent this packet is not present in close nodes list
    /// and can be added there then it will be added to ping list.
    pub async fn handle_ping_req(&self, packet: PingRequest, addr: SocketAddr)
        -> Result<(), HandlePacketError> {
        let precomputed_key = self.precomputed_keys.get(packet.pk.clone()).await;
        let payload = match packet.get_payload(&precomputed_key) {
            Err(e) => return future::err(HandlePacketError::GetPayload(e)).await,
            Ok(payload) => payload,
        };

        let resp_payload = PingResponsePayload {
            id: payload.id,
        };
        let ping_resp = Packet::PingResponse(PingResponse::new(
            &precomputed_key,
            self.pk.clone(),
            &resp_payload,
        ));

        future::try_join(
            self.ping_add(PackedNode::new(addr, packet.pk)),
            self.send_to(addr, ping_resp),
        )
            .map_ok(drop)
            .map_err(HandlePacketError::SendTo)
            .await
    }

    /// Add node to close list after we received a response from it. If it's a
    /// friend then send it's IP address to appropriate sink.
    async fn try_add_to_close(&self, state: &mut ServerState, payload_id: u64, node: PackedNode, check_ping_id: bool) -> Result<(), HandlePacketError> {
        if check_ping_id && !state.check_ping_id(payload_id, &node.pk) {
            return Err(HandlePacketError::PingIdMismatch);
        }

        state.close_nodes.try_add(node.clone());
        for friend in state.friends.values_mut() {
            friend.try_add_to_close(node.clone());
        }
        if state.friends.contains_key(&node.pk) {
            let sink = self.friend_saddr_sink.read().await.clone();
            maybe_send_unbounded(sink, node).await
                .map_err(HandlePacketError::FriendSaddr)
        } else {
            Ok(())
        }
    }

    /// Handle received `PingResponse` packet and if it's correct add the node
    /// that sent this packet to close nodes lists.
    pub async fn handle_ping_resp(&self, packet: PingResponse, addr: SocketAddr) -> Result<(), HandlePacketError> {
        let precomputed_key = self.precomputed_keys.get(packet.pk.clone()).await;
        let payload = match packet.get_payload(&precomputed_key) {
            Err(e) => return Err(HandlePacketError::GetPayload(e)),
            Ok(payload) => payload,
        };

        if payload.id == 0u64 {
            return Err(HandlePacketError::ZeroPingId);
        }

        self.try_add_to_close(&mut *self.state.write().await, payload.id, PackedNode::new(addr, packet.pk), true).await
    }

    /// Handle received `NodesRequest` packet and respond with `NodesResponse`
    /// packet. If node that sent this packet is not present in close nodes list
    /// and can be added there then it will be added to ping list.
    pub async fn handle_nodes_req(&self, packet: NodesRequest, addr: SocketAddr)
        -> Result<(), HandlePacketError> {
        let precomputed_key = self.precomputed_keys.get(packet.pk.clone()).await;
        let payload = match packet.get_payload(&precomputed_key) {
            Err(e) => return Err(HandlePacketError::GetPayload(e)),
            Ok(payload) => payload,
        };

        let close_nodes = self.get_closest(&payload.pk, 4, IsGlobal::is_global(&addr.ip())).await;

        let resp_payload = NodesResponsePayload {
            nodes: close_nodes.into(),
            id: payload.id,
        };
        let nodes_resp = Packet::NodesResponse(NodesResponse::new(
            &precomputed_key,
            self.pk.clone(),
            &resp_payload,
        ));

        future::try_join(
            self.ping_add(PackedNode::new(addr, packet.pk)),
            self.send_to(addr, nodes_resp),
        )
            .map_ok(drop)
            .map_err(HandlePacketError::SendTo)
            .await
    }

    /// Add nodes to bootstrap nodes list to send `NodesRequest` packet to them
    /// later.
    async fn add_bootstrap_nodes(&self, state: &mut ServerState, nodes: &[PackedNode], packet_pk: &PublicKey) {
        // Process nodes from NodesResponse
        for node in nodes {
            if !self.is_ipv6_enabled && node.saddr.is_ipv6() {
                continue;
            }

            if state.close_nodes.can_add(node) {
                state.nodes_to_bootstrap.try_add(&self.pk, node.clone(), /* evict */ true);
            }

            for friend in state.friends.values_mut() {
                if friend.can_add_to_close(node) {
                    friend.nodes_to_bootstrap.try_add(&friend.pk, node.clone(), /* evict */ true);
                }
            }

            self.update_returned_addr(node, packet_pk, &mut state.close_nodes, &mut state.friends);
        }
    }

    /// Handle received `NodesResponse` packet and if it's correct add the node
    /// that sent this packet to close nodes lists. Nodes from response will be
    /// added to bootstrap nodes list to send `NodesRequest` packet to them
    /// later.
    pub async fn handle_nodes_resp(&self, packet: NodesResponse, addr: SocketAddr)
        -> Result<(), HandlePacketError> {
        let precomputed_key = self.precomputed_keys.get(packet.pk.clone()).await;

        let payload = match packet.get_payload(&precomputed_key) {
            Err(e) => return Err(HandlePacketError::GetPayload(e)),
            Ok(payload) => payload,
        };

        let mut state = self.state.write().await;

        if state.check_ping_id(payload.id, &packet.pk) {
            trace!("Received nodes with NodesResponse from {}: {:?}", addr, payload.nodes);

            self.try_add_to_close(&mut *state, payload.id, PackedNode::new(addr, packet.pk.clone()), false).await?;

            // Process nodes from NodesResponse
            self.add_bootstrap_nodes(&mut *state, &payload.nodes, &packet.pk).await;
        } else {
            // Some old version toxcore responds with wrong ping_id.
            // So we do not treat this as our own error.
            trace!("NodesResponse.ping_id does not match");
        }

        Ok(())
    }

    /// Update returned socket address and time of receiving packet
    fn update_returned_addr(&self, node: &PackedNode, packet_pk: &PublicKey, close_nodes: &mut ForcedKtree, friends: &mut HashMap<PublicKey, DhtFriend>) {
        if self.pk == node.pk {
            if let Some(node_to_update) = close_nodes.get_node_mut(packet_pk) {
                node_to_update.update_returned_addr(node.saddr);
            }
        }

        if let Some(friend) = friends.get_mut(&node.pk) {
            if let Some(node_to_update) = friend.close_nodes.get_node_mut(&friend.pk, packet_pk) {
                node_to_update.update_returned_addr(node.saddr);
            }
        }
    }

    /// Handle received `DhtRequest` packet, redirect it if it's sent for
    /// someone else or parse it and handle the payload if it's sent for us.
    pub async fn handle_dht_req(&self, packet: DhtRequest, addr: SocketAddr)
        -> Result<(), HandlePacketError> { // TODO: split to functions
        if packet.rpk == self.pk { // the target peer is me
            self.handle_dht_req_for_us(packet, addr).await
        } else {
            self.handle_dht_req_for_others(packet).await
        }
    }

    /// Parse received `DhtRequest` packet and handle the payload.
    async fn handle_dht_req_for_us(&self, packet: DhtRequest, addr: SocketAddr) -> Result<(), HandlePacketError> {
        let precomputed_key = self.precomputed_keys.get(packet.spk.clone()).await;
        let payload = packet.get_payload(&precomputed_key);
        let payload = match payload {
            Err(e) => return Err(HandlePacketError::GetPayload(e)),
            Ok(payload) => payload,
        };

        match payload {
            DhtRequestPayload::NatPingRequest(nat_payload) => {
                debug!("Received nat ping request");
                self.handle_nat_ping_req(nat_payload, packet.spk, addr).await
            }
            DhtRequestPayload::NatPingResponse(nat_payload) => {
                debug!("Received nat ping response");
                self.handle_nat_ping_resp(nat_payload, &packet.spk).await
            }
            DhtRequestPayload::DhtPkAnnounce(_dht_pk_payload) => {
                debug!("Received DHT PublicKey Announce");
                // TODO: handle this packet in onion client
                Ok(())
            }
            DhtRequestPayload::HardeningRequest(_dht_pk_payload) => {
                debug!("Received Hardening request");
                // TODO: implement handler
                Ok(())
            }
            DhtRequestPayload::HardeningResponse(_dht_pk_payload) => {
                debug!("Received Hardening response");
                // TODO: implement handler
                Ok(())
            }
        }
    }

    /// Redirect received `DhtRequest` packet.
    async fn handle_dht_req_for_others(&self, packet: DhtRequest) -> Result<(), HandlePacketError> {
        let state = self.state.read().await;
        if let Some(node) = state.close_nodes.get_node(&packet.rpk).and_then(|node| node.to_packed_node()) {
            let packet = Packet::DhtRequest(packet);
            self.send_to(node.saddr, packet).await
                .map_err(HandlePacketError::SendTo)?;
        }

        Ok(())
    }

    /// Set last received ping time for `DhtFriend`.
    async fn set_friend_hole_punch_last_recv_ping_time(&self, spk: &PublicKey, ping_time: Instant)
        -> Result<(), HandlePacketError> {
        let mut state = self.state.write().await;
        match state.friends.get_mut(spk) {
            None => Err(HandlePacketError::NoFriend),
            Some(friend) => {
                friend.hole_punch.last_recv_ping_time = ping_time;
                Ok(())
            }
        }
    }

    /// Handle received `NatPingRequest` packet and respond with
    /// `NatPingResponse` packet.
    async fn handle_nat_ping_req(&self, payload: NatPingRequest, spk: PublicKey, addr: SocketAddr) -> Result<(), HandlePacketError> {
        self.set_friend_hole_punch_last_recv_ping_time(&spk, clock_now()).await?;

        let resp_payload = DhtRequestPayload::NatPingResponse(NatPingResponse {
            id: payload.id,
        });
        let nat_ping_resp = Packet::DhtRequest(DhtRequest::new(
            &self.precomputed_keys.get(spk.clone()).await,
            spk,
            self.pk.clone(),
            &resp_payload,
        ));
        self.send_to(addr, nat_ping_resp).await
            .map_err(HandlePacketError::SendTo)
    }

    /// Handle received `NatPingResponse` packet and enable hole punching if
    /// it's correct.
    async fn handle_nat_ping_resp(&self, payload: NatPingResponse, spk: &PublicKey) -> Result<(), HandlePacketError> {
        if payload.id == 0 {
            return Err(HandlePacketError::ZeroPingId)
        }

        let mut state = self.state.write().await;

        let friend = match state.friends.get_mut(spk) {
            None => return Err(HandlePacketError::NoFriend),
            Some(friend) => friend,
        };

        if friend.hole_punch.ping_id == payload.id {
            // Refresh ping id for the next NatPingRequest
            friend.hole_punch.ping_id = gen_ping_id(&mut thread_rng());
            // We send NatPingRequest packet only if we are not directly
            // connected to a friend but we have several nodes that connected
            // to him. If we received NatPingResponse that means that this
            // friend is likely behind NAT so we should try to punch holes.
            friend.hole_punch.is_punching_done = false;
            Ok(())
        } else {
            Err(HandlePacketError::PingIdMismatch)
        }
    }

    /// Handle received `LanDiscovery` packet and response with `NodesRequest`
    /// packet.
    pub async fn handle_lan_discovery(&self, packet: &LanDiscovery, addr: SocketAddr)
        -> Result<(), HandlePacketError> {
        // LanDiscovery is optional
        if !self.lan_discovery_enabled {
            return Ok(());
        }

        // if Lan Discovery packet has my PK, then it is sent by myself.
        if packet.pk == self.pk {
            return Ok(());
        }

        let mut state = self.state.write().await;

        self.send_nodes_req(PackedNode::new(addr, packet.pk.clone()), &mut state.request_queue, self.pk.clone())
            .await
            .map_err(HandlePacketError::SendTo)
    }

    /// Handle received `OnionRequest0` packet and send `OnionRequest1` packet
    /// to the next peer.
    pub async fn handle_onion_request_0(&self, packet: OnionRequest0, addr: SocketAddr) -> Result<(), HandlePacketError> {
        let onion_symmetric_key = self.onion_symmetric_key.read().await;
        let onion_return = OnionReturn::new(
            &mut thread_rng(),
            &onion_symmetric_key,
            &IpPort::from_udp_saddr(addr),
            None, // no previous onion return
        );
        let shared_secret = self.precomputed_keys.get(packet.temporary_pk.clone()).await;
        let payload = packet.get_payload(&shared_secret);
        let payload = match payload {
            Err(e) => return Err(HandlePacketError::GetPayload(e)),
            Ok(payload) => payload,
        };

        let next_packet = Packet::OnionRequest1(OnionRequest1 {
            nonce: packet.nonce,
            temporary_pk: payload.temporary_pk,
            payload: payload.inner,
            onion_return,
        });
        self.send_to(payload.ip_port.to_saddr(), next_packet).await
            .map_err(HandlePacketError::SendTo)
    }

    /// Handle received `OnionRequest1` packet and send `OnionRequest2` packet
    /// to the next peer.
    pub async fn handle_onion_request_1(&self, packet: OnionRequest1, addr: SocketAddr) -> Result<(), HandlePacketError> {
        let onion_symmetric_key = self.onion_symmetric_key.read().await;
        let onion_return = OnionReturn::new(
            &mut thread_rng(),
            &onion_symmetric_key,
            &IpPort::from_udp_saddr(addr),
            Some(&packet.onion_return)
        );
        let shared_secret = self.precomputed_keys.get(packet.temporary_pk.clone()).await;
        let payload = packet.get_payload(&shared_secret);
        let payload = match payload {
            Err(e) => return Err(HandlePacketError::GetPayload(e)),
            Ok(payload) => payload,
        };
        let next_packet = Packet::OnionRequest2(OnionRequest2 {
            nonce: packet.nonce,
            temporary_pk: payload.temporary_pk,
            payload: payload.inner,
            onion_return,
        });
        self.send_to(payload.ip_port.to_saddr(), next_packet).await
            .map_err(HandlePacketError::SendTo)
    }

    /// Handle received `OnionRequest2` packet and send `OnionAnnounceRequest`
    /// or `OnionDataRequest` packet to the next peer.
    pub async fn handle_onion_request_2(&self, packet: OnionRequest2, addr: SocketAddr) -> Result<(), HandlePacketError> {
        let onion_symmetric_key = self.onion_symmetric_key.read().await;
        let onion_return = OnionReturn::new(
            &mut thread_rng(),
            &onion_symmetric_key,
            &IpPort::from_udp_saddr(addr),
            Some(&packet.onion_return),
        );
        let shared_secret = self.precomputed_keys.get(packet.temporary_pk.clone()).await;
        let payload = packet.get_payload(&shared_secret);
        let payload = match payload {
            Err(e) => return Err(HandlePacketError::GetPayload(e)),
            Ok(payload) => payload,
        };

        let next_packet = match payload.inner {
            InnerOnionRequest::InnerOnionAnnounceRequest(inner) => Packet::OnionAnnounceRequest(OnionAnnounceRequest {
                inner,
                onion_return,
            }),
            InnerOnionRequest::InnerOnionDataRequest(inner) => Packet::OnionDataRequest(OnionDataRequest {
                inner,
                onion_return,
            }),
        };
        self.send_to(payload.ip_port.to_saddr(), next_packet).await
            .map_err(HandlePacketError::SendTo)
    }

    /// Adapt `OnionAnnounce.handle_onion_announce_request()`.
    async fn get_onion_announce_ping_id_or_pk(
        &self,
        payload: &OnionAnnounceRequestPayload,
        packet: &OnionAnnounceRequest,
        addr: SocketAddr
    ) -> (AnnounceStatus, [u8; 32]) {
        let mut onion_announce = self.onion_announce.write().await;
        onion_announce.handle_onion_announce_request(
            payload,
            packet.inner.pk.clone(),
            packet.onion_return.clone(),
            addr
        )
    }

    /// Handle received `OnionAnnounceRequest` packet and response with
    /// `OnionAnnounceResponse` packet if the request succeed.
    ///
    /// The response packet will contain up to 4 closest to `search_pk` nodes
    /// from ktree. They are used to search closest to long term `PublicKey`
    /// nodes to announce.
    pub async fn handle_onion_announce_request(&self, packet: OnionAnnounceRequest, addr: SocketAddr) -> Result<(), HandlePacketError> {
        let shared_secret = self.precomputed_keys.get(packet.inner.pk.clone()).await;
        let payload = match packet.inner.get_payload(&shared_secret) {
            Err(e) => return Err(HandlePacketError::GetPayload(e)),
            Ok(payload) => payload,
        };

        let (announce_status, ping_id_or_pk) = self.get_onion_announce_ping_id_or_pk(
            &payload,
            &packet,
            addr,
        ).await;

        let close_nodes = self.get_closest(&payload.search_pk, 4, IsGlobal::is_global(&addr.ip())).await;

        let response_payload = OnionAnnounceResponsePayload {
            announce_status,
            ping_id_or_pk,
            nodes: close_nodes.into(),
        };
        let response = OnionAnnounceResponse::new(&shared_secret, payload.sendback_data, &response_payload);

        self.send_to(addr, Packet::OnionResponse3(OnionResponse3 {
            onion_return: packet.onion_return,
            payload: InnerOnionResponse::OnionAnnounceResponse(response),
        }))
            .await
            .map_err(HandlePacketError::SendTo)
    }

    /// Handle received `OnionDataRequest` packet and send `OnionResponse3`
    /// packet with inner `OnionDataResponse` to destination node through its
    /// onion path.
    pub async fn handle_onion_data_request(&self, packet: OnionDataRequest)
        -> Result<(), HandlePacketError> {
        let onion_announce = self.onion_announce.read().await;
        match onion_announce.handle_data_request(packet) {
            Ok((response, addr)) => self.send_to(addr, Packet::OnionResponse3(response)).await
                .map_err(HandlePacketError::SendTo),
            Err(e) => Err(HandlePacketError::Onion(e))
        }
    }

    /// Handle received `OnionResponse3` packet and send `OnionResponse2` packet
    /// to the next peer which address is stored in encrypted onion return.
    pub async fn handle_onion_response_3(&self, packet: OnionResponse3) -> Result<(), HandlePacketError> {
        let onion_symmetric_key = self.onion_symmetric_key.read().await;
        let payload = packet.onion_return.get_payload(&onion_symmetric_key);
        let payload = match payload {
            Err(e) => {
                // Onion symmetric key is changed every 2 hours to enforce onion
                // paths expiration. It means that we can get packets with old
                // onion key. So we do not consider this as error.
                trace!("Failed to decrypt onion_return from OnionResponse3: {}", e);
                return Ok(());
            },
            Ok(payload) => payload,
        };

        if let (ip_port, Some(next_onion_return)) = payload {
            let next_packet = Packet::OnionResponse2(OnionResponse2 {
                onion_return: next_onion_return,
                payload: packet.payload
            });
            self.send_to(ip_port.to_saddr(), next_packet).await
                .map_err(HandlePacketError::SendTo)
        } else {
            Err(HandlePacketError::OnionResponseNext)
        }
    }

    /// Handle received `OnionResponse2` packet and send `OnionResponse1` packet
    /// to the next peer which address is stored in encrypted onion return.
    pub async fn handle_onion_response_2(&self, packet: OnionResponse2) -> Result<(), HandlePacketError> {
        let onion_symmetric_key = self.onion_symmetric_key.read().await;
        let payload = packet.onion_return.get_payload(&onion_symmetric_key);
        let payload = match payload {
            Err(e) => {
                // Onion symmetric key is changed every 2 hours to enforce onion
                // paths expiration. It means that we can get packets with old
                // onion key. So we do not consider this as error.
                trace!("Failed to decrypt onion_return from OnionResponse2: {}", e);
                return Ok(());
            },
            Ok(payload) => payload,
        };

        if let (ip_port, Some(next_onion_return)) = payload {
            let next_packet = Packet::OnionResponse1(OnionResponse1 {
                onion_return: next_onion_return,
                payload: packet.payload
            });
            self.send_to(ip_port.to_saddr(), next_packet).await
                .map_err(HandlePacketError::SendTo)
        } else {
            Err(HandlePacketError::OnionResponseNext)
        }
    }

    /// Handle received `OnionResponse1` packet and send `OnionAnnounceResponse`
    /// or `OnionDataResponse` packet to the next peer which address is stored
    /// in encrypted onion return.
    pub async fn handle_onion_response_1(&self, packet: OnionResponse1) -> Result<(), HandlePacketError> {
        let onion_symmetric_key = self.onion_symmetric_key.read().await;
        let payload = packet.onion_return.get_payload(&onion_symmetric_key);
        let payload = match payload {
            Err(e) => {
                // Onion symmetric key is changed every 2 hours to enforce onion
                // paths expiration. It means that we can get packets with old
                // onion key. So we do not consider this as error.
                trace!("Failed to decrypt onion_return from OnionResponse1: {}", e);
                return Ok(())
            },
            Ok(payload) => payload,
        };

        if let (ip_port, None) = payload {
            match ip_port.protocol {
                ProtocolType::Udp => {
                    let next_packet = match packet.payload {
                        InnerOnionResponse::OnionAnnounceResponse(inner) => Packet::OnionAnnounceResponse(inner),
                        InnerOnionResponse::OnionDataResponse(inner) => Packet::OnionDataResponse(inner),
                    };
                    self.send_to(ip_port.to_saddr(), next_packet).await
                        .map_err(HandlePacketError::SendTo)
                },
                ProtocolType::Tcp => {
                    if let Some(ref tcp_onion_sink) = self.tcp_onion_sink {
                        tcp_onion_sink.clone().send((packet.payload, ip_port.to_saddr())).await
                            .map_err(HandlePacketError::OnionResponseRedirectSend)
                    } else {
                        Err(HandlePacketError::OnionResponseRedirect)
                    }
                },
            }
        } else {
            Err(HandlePacketError::OnionResponseNext)
        }
    }

    /// Refresh onion symmetric key to enforce onion paths expiration.
    async fn refresh_onion_key(&self) {
        *self.onion_symmetric_key.write().await =
            XSalsa20Poly1305::new(&XSalsa20Poly1305::generate_key(&mut thread_rng()));
    }

    /// Handle `OnionRequest` from TCP relay and send `OnionRequest1` packet
    /// to the next node in the onion path.
    pub async fn handle_tcp_onion_request(&self, packet: OnionRequest, addr: SocketAddr)
        -> Result<(), mpsc::SendError> {
        let onion_symmetric_key = self.onion_symmetric_key.read().await;

        let onion_return = OnionReturn::new(
            &mut thread_rng(),
            &onion_symmetric_key,
            &IpPort::from_tcp_saddr(addr),
            None // no previous onion return
        );
        let next_packet = Packet::OnionRequest1(OnionRequest1 {
            nonce: packet.nonce,
            temporary_pk: packet.temporary_pk,
            payload: packet.payload,
            onion_return
        });
        self.send_to(packet.ip_port.to_saddr(), next_packet).await
    }

    /// Handle `BootstrapInfo` packet and response with `BootstrapInfo` packet.
    pub async fn handle_bootstrap_info(&self, packet: &BootstrapInfo, addr: SocketAddr) -> Result<(), HandlePacketError> {
        if packet.motd.len() != BOOSTRAP_CLIENT_MAX_MOTD_LENGTH {
            return Err(HandlePacketError::BootstrapInfoLength)
        }

        if let Some(ref bootstrap_info) = self.bootstrap_info {
            let mut motd = (bootstrap_info.motd_cb)(self);
            if motd.len() > BOOSTRAP_SERVER_MAX_MOTD_LENGTH {
                warn!(
                    "Too long MOTD: {} bytes. Truncating to {} bytes",
                    motd.len(),
                    BOOSTRAP_SERVER_MAX_MOTD_LENGTH
                );
                motd.truncate(BOOSTRAP_SERVER_MAX_MOTD_LENGTH);
            }
            let packet = Packet::BootstrapInfo(BootstrapInfo {
                version: bootstrap_info.version,
                motd,
            });
            self.send_to(addr, packet).await
                .map_err(HandlePacketError::SendTo)?;
        }

        Ok(())
    }

    /// Get up to `count` random nodes stored in fake friends.
    pub async fn random_friend_nodes(&self, count: u8) -> Vec<PackedNode> {
        let state = self.state.read().await;
        let mut nodes = Vec::new();
        let mut rng = thread_rng();
        let mut fake_friends_keys = self.fake_friends_keys.clone();
        fake_friends_keys.shuffle(&mut rng);
        for pk in fake_friends_keys {
            let mut close_nodes: Vec<_> = state.friends[&pk]
                .close_nodes
                .iter()
                .flat_map(|node| node.to_packed_node())
                .collect();
            close_nodes.shuffle(&mut rng);
            nodes.extend(close_nodes.iter().take(count as usize - nodes.len()).cloned());
            if nodes.len() == count as usize {
                break;
            }
        }
        nodes
    }

    /// Set toxcore version and message of the day callback.
    pub fn set_bootstrap_info(&mut self, version: u32, motd_cb: Box<dyn Fn(&Server) -> Vec<u8> + Send + Sync>) {
        self.bootstrap_info = Some(ServerBootstrapInfo {
            version,
            motd_cb: motd_cb.into(),
        });
    }

    /// Set TCP sink for onion packets.
    pub fn set_tcp_onion_sink(&mut self, tcp_onion_sink: TcpOnionTx) {
        self.tcp_onion_sink = Some(tcp_onion_sink)
    }

    /// Set sink to send friend's `SocketAddr` when it gets known.
    pub async fn set_friend_saddr_sink(&self, friend_saddr_sink: mpsc::UnboundedSender<PackedNode>) {
        *self.friend_saddr_sink.write().await = Some(friend_saddr_sink);
    }

    /// Get `SalsaBox`s cache.
    pub fn get_precomputed_keys(&self) -> PrecomputedCache {
        self.precomputed_keys.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tox_binary_io::*;

    use std::net::SocketAddr;
    use crypto_box::{SalsaBox, aead::{AeadCore, generic_array::typenum::marker_traits::Unsigned}};

    const ONION_RETURN_1_PAYLOAD_SIZE: usize = ONION_RETURN_1_SIZE - xsalsa20poly1305::NONCE_SIZE;
    const ONION_RETURN_2_PAYLOAD_SIZE: usize = ONION_RETURN_2_SIZE - xsalsa20poly1305::NONCE_SIZE;
    const ONION_RETURN_3_PAYLOAD_SIZE: usize = ONION_RETURN_3_SIZE - xsalsa20poly1305::NONCE_SIZE;

    impl Server {
        pub async fn has_friend(&self, pk: &PublicKey) -> bool {
            self.state.read().await.friends.contains_key(pk)
        }

        pub async fn add_node(&self, node: PackedNode) {
            assert!(self.state.write().await.close_nodes.try_add(node));
        }
    }

    fn create_node() -> (Server, SalsaBox, PublicKey, SecretKey,
            mpsc::Receiver<(Packet, SocketAddr)>, SocketAddr) {
        let mut rng = thread_rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let (tx, rx) = mpsc::channel(32);
        let alice = Server::new(tx, pk, sk);
        let bob_sk = SecretKey::generate(&mut rng);
        let bob_pk = bob_sk.public_key();
        let precomp = SalsaBox::new(&alice.pk, &bob_sk);

        let addr: SocketAddr = "127.0.0.1:12346".parse().unwrap();
        (alice, precomp, bob_pk, bob_sk, rx, addr)
    }

    #[tokio::test]
    async fn add_friend() {
        let mut rng = thread_rng();
        let (alice, _precomp, bob_pk, _bob_sk, _rx, _addr) = create_node();

        let packed_node = PackedNode::new("211.192.153.67:33445".parse().unwrap(), bob_pk.clone());
        assert!(alice.state.write().await.close_nodes.try_add(packed_node));

        let friend_pk = SecretKey::generate(&mut rng).public_key();
        alice.add_friend(friend_pk.clone()).await;

        let inserted_friend = &alice.state.read().await.friends[&friend_pk];
        assert!(inserted_friend.nodes_to_bootstrap.contains(&friend_pk, &bob_pk));
    }

    #[tokio::test]
    async fn readd_friend() {
        let mut rng = thread_rng();
        let (alice, _precomp, bob_pk, _bob_sk, _rx, _addr) = create_node();

        let friend_pk = SecretKey::generate(&mut rng).public_key();
        alice.add_friend(friend_pk.clone()).await;

        let packed_node = PackedNode::new("127.0.0.1:33445".parse().unwrap(), bob_pk.clone());
        assert!(alice.state.write().await.friends.get_mut(&friend_pk).unwrap().try_add_to_close(packed_node));

        // adding the same friend shouldn't replace existing `DhtFriend`
        alice.add_friend(friend_pk.clone()).await;

        // so it should still contain the added node
        assert!(alice.state.read().await.friends[&friend_pk].close_nodes.contains(&friend_pk, &bob_pk));
    }

    #[tokio::test]
    async fn remove_friend() {
        let mut rng = thread_rng();
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, _addr) = create_node();

        let friend_pk = SecretKey::generate(&mut rng).public_key();
        alice.add_friend(friend_pk.clone()).await;

        assert!(alice.state.read().await.friends.contains_key(&friend_pk));

        alice.remove_friend(friend_pk.clone()).await;

        assert!(!alice.state.read().await.friends.contains_key(&friend_pk));
    }

    #[tokio::test]
    async fn handle_bootstrap_info() {
        let (mut alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let version = 42;
        let motd = b"motd".to_vec();
        let motd_c = motd.clone();

        alice.set_bootstrap_info(version, Box::new(move |_| motd_c.clone()));

        let packet = BootstrapInfo {
            version: 00,
            motd: vec![0; BOOSTRAP_CLIENT_MAX_MOTD_LENGTH],
        };

        alice.handle_bootstrap_info(&packet, addr).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let bootstrap_info = unpack!(packet, Packet::BootstrapInfo);

        assert_eq!(bootstrap_info.version, version);
        assert_eq!(bootstrap_info.motd, motd);
    }

    #[tokio::test]
    async fn handle_bootstrap_info_wrong_length() {
        let (mut alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let version = 42;
        let motd = b"motd".to_vec();

        alice.set_bootstrap_info(version, Box::new(move |_| motd.clone()));

        let packet = BootstrapInfo {
            version: 00,
            motd: Vec::new(),
        };

        let res = alice.handle_bootstrap_info(&packet, addr).await;
        assert!(matches!(res, Err(HandlePacketError::BootstrapInfoLength)));

        // Necessary to drop tx so that rx.collect::<Vec<_>>() can be finished
        drop(alice);

        assert!(rx.collect::<Vec<_>>().await.is_empty());
    }

    // handle_ping_req
    #[tokio::test]
    async fn handle_ping_req() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();

        let req_payload = PingRequestPayload { id: 42 };
        let ping_req = PingRequest::new(&precomp, bob_pk.clone(), &req_payload);

        alice.handle_ping_req(ping_req, addr).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let ping_resp = unpack!(packet, Packet::PingResponse);
        let precomputed_key = SalsaBox::new(&ping_resp.pk, &bob_sk);
        let ping_resp_payload = ping_resp.get_payload(&precomputed_key).unwrap();

        assert_eq!(ping_resp_payload.id, req_payload.id);

        assert!(alice.nodes_to_ping.read().await.contains(&alice.pk, &bob_pk));
    }

    #[tokio::test]
    async fn handle_ping_req_from_friend_with_unknown_addr() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();

        alice.add_friend(bob_pk.clone()).await;

        let req_payload = PingRequestPayload { id: 42 };
        let ping_req = PingRequest::new(&precomp, bob_pk.clone(), &req_payload);

        alice.handle_ping_req(ping_req, addr).await.unwrap();

        let mut state = alice.state.write().await;

        rx.take(2).map(|(packet, addr_to_send)| {
            assert_eq!(addr_to_send, addr);

            if let Packet::PingResponse(ping_resp) = packet {
                let precomputed_key = SalsaBox::new(&ping_resp.pk, &bob_sk);
                let ping_resp_payload = ping_resp.get_payload(&precomputed_key).unwrap();
                assert_eq!(ping_resp_payload.id, req_payload.id);
            } else {
                let ping_req = unpack!(packet, Packet::PingRequest);
                let precomputed_key = SalsaBox::new(&ping_req.pk, &bob_sk);
                let ping_req_payload = ping_req.get_payload(&precomputed_key).unwrap();
                assert!(state.request_queue.check_ping_id(ping_req_payload.id, |pk| pk == &bob_pk).is_some());
            }
        }).collect::<Vec<_>>().await;

        // In case of friend with yet unknown address we should send ping
        // request immediately instead of adding node to nodes_to_ping list
        assert!(!alice.nodes_to_ping.read().await.contains(&alice.pk, &bob_pk));
    }

    #[tokio::test]
    async fn handle_ping_req_invalid_payload() {
        let (alice, precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        // can't be decrypted payload since packet contains wrong key
        let req_payload = PingRequestPayload { id: 42 };
        let ping_req = PingRequest::new(&precomp, alice.pk.clone(), &req_payload);

        let res = alice.handle_ping_req(ping_req, addr).await;
        assert!(matches!(res, Err(HandlePacketError::GetPayload(GetPayloadError::Decrypt))));
    }

    // handle_ping_resp
    #[tokio::test]
    async fn handle_ping_resp() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        alice.add_friend(bob_pk.clone()).await;

        let packed_node = PackedNode::new(addr, bob_pk.clone());
        assert!(alice.state.write().await.close_nodes.try_add(packed_node));

        let ping_id = alice.state.write().await.request_queue.new_ping_id(&mut thread_rng(), bob_pk.clone());

        let resp_payload = PingResponsePayload { id: ping_id };
        let ping_resp = PingResponse::new(&precomp, bob_pk.clone(), &resp_payload);

        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(1)).await;

        alice.handle_ping_resp(ping_resp, addr).await.unwrap();

        let state = alice.state.read().await;
        let friend = state.friends.values().next().unwrap();

        // All nodes from PingResponse should be added to bootstrap nodes list
        // of each friend
        assert!(friend.close_nodes.contains(&bob_pk, &bob_pk));

        let state = alice.state.read().await;
        let node = state.close_nodes.get_node(&bob_pk).unwrap();

        // Node that sent PingResponse should be added to close nodes list and
        // have updated last_resp_time
        let time = clock_now();
        assert_eq!(node.assoc4.last_resp_time.unwrap(), time);
    }

    #[tokio::test]
    async fn handle_ping_resp_not_a_friend() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let (friend_saddr_tx, friend_saddr_rx) = mpsc::unbounded();
        alice.set_friend_saddr_sink(friend_saddr_tx).await;

        let packed_node = PackedNode::new(addr, bob_pk.clone());
        assert!(alice.state.write().await.close_nodes.try_add(packed_node));

        let ping_id = alice.state.write().await.request_queue.new_ping_id(&mut thread_rng(), bob_pk.clone());

        let resp_payload = PingResponsePayload { id: ping_id };
        let ping_resp = PingResponse::new(&precomp, bob_pk, &resp_payload);

        alice.handle_ping_resp(ping_resp, addr).await.unwrap();

        // Necessary to drop tx so that rx.collect::<Vec<_>>() can be finished
        drop(alice);

        assert!(friend_saddr_rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn handle_ping_resp_friend_saddr() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let (friend_saddr_tx, friend_saddr_rx) = mpsc::unbounded();
        alice.set_friend_saddr_sink(friend_saddr_tx).await;

        alice.add_friend(bob_pk.clone()).await;

        let packed_node = PackedNode::new(addr, bob_pk.clone());
        assert!(alice.state.write().await.close_nodes.try_add(packed_node));

        let ping_id = alice.state.write().await.request_queue.new_ping_id(&mut thread_rng(), bob_pk.clone());

        let resp_payload = PingResponsePayload { id: ping_id };
        let ping_resp = PingResponse::new(&precomp, bob_pk.clone(), &resp_payload);

        alice.handle_ping_resp(ping_resp, addr).await.unwrap();

        let (received_node, _friend_saddr_rx) = friend_saddr_rx.into_future().await;
        let received_node = received_node.unwrap();

        assert_eq!(received_node.pk, bob_pk);
        assert_eq!(received_node.saddr, addr);
    }

    #[tokio::test]
    async fn handle_ping_resp_invalid_payload() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let packed_node = PackedNode::new(addr, bob_pk.clone());
        assert!(alice.state.write().await.close_nodes.try_add(packed_node));

        let ping_id = alice.state.write().await.request_queue.new_ping_id(&mut thread_rng(), bob_pk);

        // can't be decrypted payload since packet contains wrong key
        let payload = PingResponsePayload { id: ping_id };
        let ping_resp = PingResponse::new(&precomp, alice.pk.clone(), &payload);

        let res = alice.handle_ping_resp(ping_resp, addr).await;
        assert!(matches!(res, Err(HandlePacketError::GetPayload(GetPayloadError::Decrypt))));
    }

    #[tokio::test]
    async fn handle_ping_resp_ping_id_is_0() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let packed_node = PackedNode::new(addr, bob_pk.clone());
        assert!(alice.state.write().await.close_nodes.try_add(packed_node));

        let payload = PingResponsePayload { id: 0 };
        let ping_resp = PingResponse::new(&precomp, bob_pk, &payload);

        let res = alice.handle_ping_resp(ping_resp, addr).await;
        assert!(matches!(res, Err(HandlePacketError::ZeroPingId)));
    }

    #[tokio::test]
    async fn handle_ping_resp_invalid_ping_id() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let packed_node = PackedNode::new(addr, bob_pk.clone());
        assert!(alice.state.write().await.close_nodes.try_add(packed_node));

        let ping_id = alice.state.write().await.request_queue.new_ping_id(&mut thread_rng(), bob_pk.clone());

        let payload = PingResponsePayload { id: ping_id + 1 };
        let ping_resp = PingResponse::new(&precomp, bob_pk, &payload);

        let res = alice.handle_ping_resp(ping_resp, addr).await;
        assert!(matches!(res, Err(HandlePacketError::PingIdMismatch)));
    }

    // handle_nodes_req
    #[tokio::test]
    async fn handle_nodes_req() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();

        let packed_node = PackedNode::new("127.0.0.1:12345".parse().unwrap(), bob_pk.clone());

        assert!(alice.state.write().await.close_nodes.try_add(packed_node.clone()));

        let req_payload = NodesRequestPayload { pk: bob_pk.clone(), id: 42 };
        let nodes_req = NodesRequest::new(&precomp, bob_pk.clone(), &req_payload);

        alice.handle_nodes_req(nodes_req, addr).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let nodes_resp = unpack!(packet, Packet::NodesResponse);
        let precomputed_key = SalsaBox::new(&nodes_resp.pk, &bob_sk);
        let nodes_resp_payload = nodes_resp.get_payload(&precomputed_key).unwrap();

        assert_eq!(nodes_resp_payload.id, req_payload.id);
        assert_eq!(nodes_resp_payload.nodes, vec!(packed_node));

        assert!(alice.nodes_to_ping.read().await.contains(&alice.pk, &bob_pk));
    }

    #[tokio::test]
    async fn handle_nodes_req_should_return_nodes_from_friends() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();

        alice.add_friend(bob_pk.clone()).await;

        let packed_node = PackedNode::new("127.0.0.1:12345".parse().unwrap(), bob_pk.clone());
        assert!(alice.state.write().await.friends.get_mut(&bob_pk).unwrap().try_add_to_close(packed_node.clone()));

        let req_payload = NodesRequestPayload { pk: bob_pk.clone(), id: 42 };
        let nodes_req = NodesRequest::new(&precomp, bob_pk.clone(), &req_payload);

        alice.handle_nodes_req(nodes_req, addr).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let nodes_resp = unpack!(packet, Packet::NodesResponse);
        let precomputed_key = SalsaBox::new(&nodes_resp.pk, &bob_sk);
        let nodes_resp_payload = nodes_resp.get_payload(&precomputed_key).unwrap();

        assert_eq!(nodes_resp_payload.id, req_payload.id);
        assert_eq!(nodes_resp_payload.nodes, vec!(packed_node));

        assert!(alice.nodes_to_ping.read().await.contains(&alice.pk, &bob_pk));
    }

    #[tokio::test]
    async fn handle_nodes_req_should_not_return_bad_nodes() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();

        let packed_node = PackedNode::new("127.0.0.1:12345".parse().unwrap(), bob_pk.clone());

        assert!(alice.state.write().await.close_nodes.try_add(packed_node));

        let req_payload = NodesRequestPayload { pk: bob_pk.clone(), id: 42 };
        let nodes_req = NodesRequest::new(&precomp, bob_pk.clone(), &req_payload);

        let delay = BAD_NODE_TIMEOUT + Duration::from_secs(1);

        tokio::time::pause();
        tokio::time::advance(delay).await;

        alice.handle_nodes_req(nodes_req, addr).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let nodes_resp = unpack!(packet, Packet::NodesResponse);
        let precomputed_key = SalsaBox::new(&nodes_resp.pk, &bob_sk);
        let nodes_resp_payload = nodes_resp.get_payload(&precomputed_key).unwrap();

        assert_eq!(nodes_resp_payload.id, req_payload.id);
        assert!(nodes_resp_payload.nodes.is_empty());

        assert!(alice.nodes_to_ping.read().await.contains(&alice.pk, &bob_pk));
    }

    #[tokio::test]
    async fn handle_nodes_req_should_not_return_lan_nodes_when_address_is_global() {
        let (alice, precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let addr = "8.10.8.10:12345".parse().unwrap();

        let packed_node = PackedNode::new("192.168.42.42:12345".parse().unwrap(), bob_pk.clone());

        assert!(alice.state.write().await.close_nodes.try_add(packed_node));

        let req_payload = NodesRequestPayload { pk: bob_pk.clone(), id: 42 };
        let nodes_req = NodesRequest::new(&precomp, bob_pk.clone(), &req_payload);

        alice.handle_nodes_req(nodes_req, addr).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let nodes_resp = unpack!(packet, Packet::NodesResponse);
        let precomputed_key = SalsaBox::new(&nodes_resp.pk, &bob_sk);
        let nodes_resp_payload = nodes_resp.get_payload(&precomputed_key).unwrap();

        assert_eq!(nodes_resp_payload.id, req_payload.id);
        assert!(nodes_resp_payload.nodes.is_empty());

        assert!(alice.nodes_to_ping.read().await.contains(&alice.pk, &bob_pk));
    }

    #[tokio::test]
    async fn handle_nodes_req_invalid_payload() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        // can't be decrypted payload since packet contains wrong key
        let req_payload = NodesRequestPayload { pk: bob_pk, id: 42 };
        let nodes_req = NodesRequest::new(&precomp, alice.pk.clone(), &req_payload);

        let res = alice.handle_nodes_req(nodes_req, addr).await;
        assert!(matches!(res, Err(HandlePacketError::GetPayload(GetPayloadError::Decrypt))));
    }

    // handle_nodes_resp
    #[tokio::test]
    async fn handle_nodes_resp() {
        let mut rng = thread_rng();
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        alice.add_friend(bob_pk.clone()).await;

        let node = PackedNode::new("127.0.0.1:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key());

        let ping_id = alice.state.write().await.request_queue.new_ping_id(&mut rng, bob_pk.clone());

        let resp_payload = NodesResponsePayload { nodes: vec![node.clone()], id: ping_id };
        let nodes_resp = NodesResponse::new(&precomp, bob_pk.clone(), &resp_payload);

        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(1)).await;

        alice.handle_nodes_resp(nodes_resp, addr).await.unwrap();

        let state = alice.state.read().await;

        // All nodes from NodesResponse should be added to bootstrap nodes list
        assert!(state.nodes_to_bootstrap.contains(&alice.pk, &node.pk));

        let friend = state.friends.values().next().unwrap();

        // Node that sent NodesResponse should be added to close nodes list of
        // each friend
        assert!(friend.nodes_to_bootstrap.contains(&bob_pk, &node.pk));
        // All nodes from NodesResponse should be added to bootstrap nodes list
        // of each friend
        assert!(friend.close_nodes.contains(&bob_pk, &bob_pk));

        let state = alice.state.read().await;
        let node = state.close_nodes.get_node(&bob_pk).unwrap();

        // Node that sent NodesResponse should be added to close nodes list and
        // have updated last_resp_time
        let time = clock_now();
        assert_eq!(node.assoc4.last_resp_time.unwrap(), time);
    }

    #[tokio::test]
    async fn handle_nodes_resp_friend_saddr() {
        let mut rng = thread_rng();
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let (friend_saddr_tx, friend_saddr_rx) = mpsc::unbounded();
        alice.set_friend_saddr_sink(friend_saddr_tx).await;

        alice.add_friend(bob_pk.clone()).await;

        let packed_node = PackedNode::new(addr, bob_pk.clone());
        assert!(alice.state.write().await.close_nodes.try_add(packed_node));

        let node = PackedNode::new("127.0.0.1:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key());

        let ping_id = alice.state.write().await.request_queue.new_ping_id(&mut rng, bob_pk.clone());

        let resp_payload = NodesResponsePayload { nodes: vec![node], id: ping_id };
        let nodes_resp = NodesResponse::new(&precomp, bob_pk.clone(), &resp_payload);

        alice.handle_nodes_resp(nodes_resp, addr).await.unwrap();

        let (received_node, _friend_saddr_rx) = friend_saddr_rx.into_future().await;
        let received_node = received_node.unwrap();

        assert_eq!(received_node.pk, bob_pk);
        assert_eq!(received_node.saddr, addr);
    }

    #[tokio::test]
    async fn handle_nodes_resp_invalid_payload() {
        let mut rng = thread_rng();
        let (alice, precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        // can't be decrypted payload since packet contains wrong key
        let resp_payload = NodesResponsePayload { nodes: vec![
            PackedNode::new("127.0.0.1:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key())
        ], id: 38 };
        let nodes_resp = NodesResponse::new(&precomp, alice.pk.clone(), &resp_payload);

        let res = alice.handle_nodes_resp(nodes_resp, addr).await;
        assert!(matches!(res, Err(HandlePacketError::GetPayload(GetPayloadError::Decrypt))));
    }

    #[tokio::test]
    async fn handle_nodes_resp_ping_id_is_0() {
        let mut rng = thread_rng();
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let resp_payload = NodesResponsePayload { nodes: vec![
            PackedNode::new("127.0.0.1:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key())
        ], id: 0 };
        let nodes_resp = NodesResponse::new(&precomp, bob_pk, &resp_payload);

        alice.handle_nodes_resp(nodes_resp, addr).await.unwrap();

        // Necessary to drop tx so that rx.collect::<Vec<_>>() can be finished
        drop(alice);

        assert!(rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn handle_nodes_resp_invalid_ping_id() {
        let mut rng = thread_rng();
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let ping_id = alice.state.write().await.request_queue.new_ping_id(&mut rng, bob_pk.clone());

        let resp_payload = NodesResponsePayload {
            nodes: vec![
                PackedNode::new("127.0.0.1:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key())
            ],
            id: ping_id + 1
        };
        let nodes_resp = NodesResponse::new(&precomp, bob_pk, &resp_payload);

        alice.handle_nodes_resp(nodes_resp, addr).await.unwrap();

        // Necessary to drop tx so that rx.collect::<Vec<_>>() can be finished
        drop(alice);

        assert!(rx.collect::<Vec<_>>().await.is_empty());
    }

    // handle_dht_req
    #[tokio::test]
    async fn handle_dht_req_for_unknown_node() {
        let mut rng = thread_rng();
        let (alice, _precomp, bob_pk, bob_sk, rx, addr) = create_node();

        let charlie_pk = SecretKey::generate(&mut rng).public_key();
        let precomp = SalsaBox::new(&charlie_pk, &bob_sk);

        // if receiver' pk != node's pk just returns ok()
        let nat_req = NatPingRequest { id: 42 };
        let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
        let dht_req = DhtRequest::new(&precomp, charlie_pk, bob_pk, &nat_payload);

        alice.handle_dht_req(dht_req, addr).await.unwrap();

        // Necessary to drop tx so that rx.collect::<Vec<_>>() can be finished
        drop(alice);

        assert!(rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn handle_dht_req_for_known_node() {
        let mut rng = thread_rng();
        let (alice, _precomp, bob_pk, bob_sk, rx, addr) = create_node();

        let charlie_addr = "1.2.3.4:12345".parse().unwrap();
        let charlie_pk = SecretKey::generate(&mut rng).public_key();
        let precomp = SalsaBox::new(&charlie_pk, &bob_sk);

        // if receiver' pk != node's pk and receiver's pk exists in close_nodes, returns ok()
        let pn = PackedNode::new(charlie_addr, charlie_pk.clone());
        assert!(alice.state.write().await.close_nodes.try_add(pn));

        let nat_req = NatPingRequest { id: 42 };
        let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
        let dht_req = DhtRequest::new(&precomp, charlie_pk, bob_pk, &nat_payload);

        alice.handle_dht_req(dht_req.clone(), addr).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, charlie_addr);
        assert_eq!(packet, Packet::DhtRequest(dht_req));
    }

    #[tokio::test]
    async fn handle_dht_req_invalid_payload() {
        let (alice, _precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let dht_req = DhtRequest {
            rpk: alice.pk.clone(),
            spk: bob_pk,
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 123]
        };

        let res = alice.handle_dht_req(dht_req, addr).await;
        assert!(matches!(res, Err(HandlePacketError::GetPayload(GetPayloadError::Decrypt))));
    }

    // handle_nat_ping_request
    #[tokio::test]
    async fn handle_nat_ping_req() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();

        alice.add_friend(bob_pk.clone()).await;

        let nat_req = NatPingRequest { id: 42 };
        let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
        let dht_req = DhtRequest::new(&precomp, alice.pk.clone(), bob_pk.clone(), &nat_payload);

        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(1)).await;

        alice.handle_dht_req(dht_req, addr).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let dht_req = unpack!(packet, Packet::DhtRequest);
        let precomputed_key = SalsaBox::new(&dht_req.spk, &bob_sk);
        let dht_payload = dht_req.get_payload(&precomputed_key).unwrap();
        let nat_ping_resp_payload = unpack!(dht_payload, DhtRequestPayload::NatPingResponse);

        assert_eq!(nat_ping_resp_payload.id, nat_req.id);

        let state = alice.state.read().await;

        let time = clock_now();
        assert_eq!(state.friends[&bob_pk].hole_punch.last_recv_ping_time, time);
    }

    // handle_nat_ping_response
    #[tokio::test]
    async fn handle_nat_ping_resp() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        alice.add_friend(bob_pk.clone()).await;
        let ping_id = alice.state.read().await.friends[&bob_pk].hole_punch.ping_id;

        let nat_res = NatPingResponse { id: ping_id };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtRequest::new(&precomp, alice.pk.clone(), bob_pk.clone(), &nat_payload);

        alice.handle_dht_req(dht_req, addr).await.unwrap();

        let state = alice.state.read().await;

        assert!(!state.friends[&bob_pk].hole_punch.is_punching_done);
    }

    #[tokio::test]
    async fn handle_nat_ping_resp_ping_id_is_0() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        // error case, ping_id = 0
        let nat_res = NatPingResponse { id: 0 };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtRequest::new(&precomp, alice.pk.clone(), bob_pk, &nat_payload);

        let res = alice.handle_dht_req(dht_req, addr).await;
        assert!(matches!(res, Err(HandlePacketError::ZeroPingId)));
    }

    #[tokio::test]
    async fn handle_nat_ping_resp_invalid_ping_id() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        // error case, incorrect ping_id
        let ping_id = alice.state.write().await.request_queue.new_ping_id(&mut thread_rng(), bob_pk.clone());

        let nat_res = NatPingResponse { id: ping_id + 1 };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = DhtRequest::new(&precomp, alice.pk.clone(), bob_pk, &nat_payload);

        let res = alice.handle_dht_req(dht_req, addr).await;
        assert!(matches!(res, Err(HandlePacketError::NoFriend)));
    }

    // handle_onion_request_0
    #[tokio::test]
    async fn handle_onion_request_0() {
        let mut rng = thread_rng();
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let temporary_pk = SecretKey::generate(&mut rng).public_key();
        let inner = vec![42; 123];
        let ip_port = IpPort {
            protocol: ProtocolType::Udp,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let payload = OnionRequest0Payload {
            ip_port: ip_port.clone(),
            temporary_pk: temporary_pk.clone(),
            inner: inner.clone()
        };
        let packet = OnionRequest0::new(&precomp, bob_pk, &payload);

        alice.handle_onion_request_0(packet, addr).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionRequest1);

        assert_eq!(next_packet.temporary_pk, temporary_pk);
        assert_eq!(next_packet.payload, inner);

        let onion_symmetric_key = alice.onion_symmetric_key.read().await;
        let onion_return_payload = next_packet.onion_return.get_payload(&onion_symmetric_key).unwrap();

        assert_eq!(onion_return_payload.0, IpPort::from_udp_saddr(addr));
    }

    #[tokio::test]
    async fn handle_onion_request_0_invalid_payload() {
        let mut rng = thread_rng();
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let packet = OnionRequest0 {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            temporary_pk: SecretKey::generate(&mut rng).public_key(),
            payload: vec![42; 123] // not encrypted with dht pk
        };

        let res = alice.handle_onion_request_0(packet, addr).await;
        assert!(matches!(res, Err(HandlePacketError::GetPayload(GetPayloadError::Decrypt))));
    }

    // handle_onion_request_1
    #[tokio::test]
    async fn handle_onion_request_1() {
        let mut rng = thread_rng();
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let temporary_pk = SecretKey::generate(&mut rng).public_key();
        let inner = vec![42; 123];
        let ip_port = IpPort {
            protocol: ProtocolType::Udp,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let payload = OnionRequest1Payload {
            ip_port: ip_port.clone(),
            temporary_pk: temporary_pk.clone(),
            inner: inner.clone()
        };
        let onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
        };
        let packet = OnionRequest1::new(&precomp, bob_pk, &payload, onion_return);

        alice.handle_onion_request_1(packet, addr).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionRequest2);

        assert_eq!(next_packet.temporary_pk, temporary_pk);
        assert_eq!(next_packet.payload, inner);

        let onion_symmetric_key = alice.onion_symmetric_key.read().await;
        let onion_return_payload = next_packet.onion_return.get_payload(&onion_symmetric_key).unwrap();

        assert_eq!(onion_return_payload.0, IpPort::from_udp_saddr(addr));
    }

    #[tokio::test]
    async fn handle_onion_request_1_invalid_payload() {
        let mut rng = thread_rng();
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let packet = OnionRequest1 {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            temporary_pk: SecretKey::generate(&mut rng).public_key(),
            payload: vec![42; 123], // not encrypted with dht pk
            onion_return: OnionReturn {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
            }
        };

        let res = alice.handle_onion_request_1(packet, addr).await;
        assert!(matches!(res, Err(HandlePacketError::GetPayload(GetPayloadError::Decrypt))));
    }

    // handle_onion_request_2
    #[tokio::test]
    async fn handle_onion_request_2_with_onion_announce_request() {
        let mut rng = thread_rng();
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let inner = InnerOnionAnnounceRequest {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            pk: SecretKey::generate(&mut rng).public_key(),
            payload: vec![42; 123]
        };
        let ip_port = IpPort {
            protocol: ProtocolType::Udp,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let payload = OnionRequest2Payload {
            ip_port: ip_port.clone(),
            inner: InnerOnionRequest::InnerOnionAnnounceRequest(inner.clone())
        };
        let onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
        };
        let packet = OnionRequest2::new(&precomp, bob_pk, &payload, onion_return);

        alice.handle_onion_request_2(packet, addr).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionAnnounceRequest);

        assert_eq!(next_packet.inner, inner);

        let onion_symmetric_key = alice.onion_symmetric_key.read().await;
        let onion_return_payload = next_packet.onion_return.get_payload(&onion_symmetric_key).unwrap();

        assert_eq!(onion_return_payload.0, IpPort::from_udp_saddr(addr));
    }

    #[tokio::test]
    async fn handle_onion_request_2_with_onion_data_request() {
        let mut rng = thread_rng();
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let inner = InnerOnionDataRequest {
            destination_pk: SecretKey::generate(&mut rng).public_key(),
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            temporary_pk: SecretKey::generate(&mut rng).public_key(),
            payload: vec![42; 123]
        };
        let ip_port = IpPort {
            protocol: ProtocolType::Udp,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let payload = OnionRequest2Payload {
            ip_port: ip_port.clone(),
            inner: InnerOnionRequest::InnerOnionDataRequest(inner.clone())
        };
        let onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
        };
        let packet = OnionRequest2::new(&precomp, bob_pk, &payload, onion_return);

        alice.handle_onion_request_2(packet, addr).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionDataRequest);

        assert_eq!(next_packet.inner, inner);

        let onion_symmetric_key = alice.onion_symmetric_key.read().await;
        let onion_return_payload = next_packet.onion_return.get_payload(&onion_symmetric_key).unwrap();

        assert_eq!(onion_return_payload.0, IpPort::from_udp_saddr(addr));
    }

    #[tokio::test]
    async fn handle_onion_request_2_invalid_payload() {
        let mut rng = thread_rng();
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let packet = OnionRequest2 {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            temporary_pk: SecretKey::generate(&mut rng).public_key(),
            payload: vec![42; 123], // not encrypted with dht pk
            onion_return: OnionReturn {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
            }
        };

        let res = alice.handle_onion_request_2(packet, addr).await;
        assert!(matches!(res, Err(HandlePacketError::GetPayload(GetPayloadError::Decrypt))));
    }

    // handle_onion_announce_request
    #[tokio::test]
    async fn handle_onion_announce_request() {
        let mut rng = thread_rng();
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let sendback_data = 42;
        let payload = OnionAnnounceRequestPayload {
            ping_id: INITIAL_PING_ID,
            search_pk: SecretKey::generate(&mut rng).public_key(),
            data_pk: SecretKey::generate(&mut rng).public_key(),
            sendback_data
        };
        let inner = InnerOnionAnnounceRequest::new(&precomp, bob_pk, &payload);
        let onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
        };
        let packet = OnionAnnounceRequest {
            inner,
            onion_return: onion_return.clone()
        };

        alice.handle_onion_announce_request(packet, addr).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let response = unpack!(packet, Packet::OnionResponse3);

        assert_eq!(response.onion_return, onion_return);

        let response = unpack!(response.payload, InnerOnionResponse::OnionAnnounceResponse);

        assert_eq!(response.sendback_data, sendback_data);

        let payload = response.get_payload(&precomp).unwrap();

        assert_eq!(payload.announce_status, AnnounceStatus::Failed);
    }

    #[tokio::test]
    async fn handle_onion_announce_request_invalid_payload() {
        let (alice, _precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let inner = InnerOnionAnnounceRequest {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            pk: bob_pk,
            payload: vec![42; 123]
        };
        let onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
        };
        let packet = OnionAnnounceRequest {
            inner,
            onion_return: onion_return.clone()
        };

        let res = alice.handle_onion_announce_request(packet, addr).await;
        assert!(matches!(res, Err(HandlePacketError::GetPayload(GetPayloadError::Decrypt))));
    }

    // handle_onion_data_request
    #[tokio::test]
    async fn handle_onion_data_request() {
        let mut rng = thread_rng();
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        // get ping id

        let payload = OnionAnnounceRequestPayload {
            ping_id: INITIAL_PING_ID,
            search_pk: SecretKey::generate(&mut rng).public_key(),
            data_pk: SecretKey::generate(&mut rng).public_key(),
            sendback_data: 42
        };
        let inner = InnerOnionAnnounceRequest::new(&precomp, bob_pk.clone(), &payload);
        let onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
        };
        let packet = OnionAnnounceRequest {
            inner,
            onion_return: onion_return.clone()
        };

        alice.handle_onion_announce_request(packet, addr).await.unwrap();

        let (received, rx) = rx.into_future().await;
        let (packet, _addr_to_send) = received.unwrap();
        let response = unpack!(packet, Packet::OnionResponse3);
        let response = unpack!(response.payload, InnerOnionResponse::OnionAnnounceResponse);
        let payload = response.get_payload(&precomp).unwrap();

        // announce node

        let payload = OnionAnnounceRequestPayload {
            ping_id: payload.ping_id_or_pk,
            search_pk: SecretKey::generate(&mut rng).public_key(),
            data_pk: SecretKey::generate(&mut rng).public_key(),
            sendback_data: 42
        };
        let inner = InnerOnionAnnounceRequest::new(&precomp, bob_pk.clone(), &payload);
        let packet = OnionAnnounceRequest {
            inner,
            onion_return: onion_return.clone()
        };

        alice.handle_onion_announce_request(packet, addr).await.unwrap();

        // send onion data request

        let nonce = crypto_box::generate_nonce(&mut rng).into();
        let temporary_pk = SecretKey::generate(&mut rng).public_key();
        let payload = vec![42; 123];
        let inner = InnerOnionDataRequest {
            destination_pk: bob_pk,
            nonce,
            temporary_pk: temporary_pk.clone(),
            payload: payload.clone()
        };
        let packet = OnionDataRequest {
            inner,
            onion_return: onion_return.clone()
        };

        alice.handle_onion_data_request(packet).await.unwrap();

        let (received, _rx) = rx.skip(1).into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let response = unpack!(packet, Packet::OnionResponse3);

        assert_eq!(response.onion_return, onion_return);

        let response = unpack!(response.payload, InnerOnionResponse::OnionDataResponse);

        assert_eq!(response.nonce, nonce);
        assert_eq!(response.temporary_pk, temporary_pk);
        assert_eq!(response.payload, payload);
    }

    // handle_onion_response_3
    #[tokio::test]
    async fn handle_onion_response_3() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, _addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read().await;

        let ip_port = IpPort {
            protocol: ProtocolType::Udp,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let next_onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
        };
        let onion_return = OnionReturn::new(&mut thread_rng(), &onion_symmetric_key, &ip_port, Some(&next_onion_return));
        let payload = InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 123]
        });
        let packet = OnionResponse3 {
            onion_return,
            payload: payload.clone()
        };

        alice.handle_onion_response_3(packet).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionResponse2);

        assert_eq!(next_packet.payload, payload);
        assert_eq!(next_packet.onion_return, next_onion_return);
    }

    #[tokio::test]
    async fn handle_onion_response_3_invalid_onion_return() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, _addr) = create_node();

        let onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE] // not encrypted with onion_symmetric_key
        };
        let payload = InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 123]
        });
        let packet = OnionResponse3 {
            onion_return,
            payload
        };

        alice.handle_onion_response_3(packet).await.unwrap();

        // Necessary to drop tx so that rx.collect::<Vec<_>>() can be finished
        drop(alice);

        assert!(rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn handle_onion_response_3_invalid_next_onion_return() {
        let mut rng = thread_rng();
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, _addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read().await;

        let ip_port = IpPort {
            protocol: ProtocolType::Udp,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let onion_return = OnionReturn::new(&mut thread_rng(), &onion_symmetric_key, &ip_port, None);
        let inner = OnionDataResponse {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            temporary_pk: SecretKey::generate(&mut rng).public_key(),
            payload: vec![42; 123]
        };
        let packet = OnionResponse3 {
            onion_return,
            payload: InnerOnionResponse::OnionDataResponse(inner.clone())
        };

        let res = alice.handle_onion_response_3(packet).await;
        assert!(matches!(res, Err(HandlePacketError::OnionResponseNext)));
    }

    // handle_onion_response_2
    #[tokio::test]
    async fn handle_onion_response_2() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, _addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read().await;

        let ip_port = IpPort {
            protocol: ProtocolType::Udp,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let next_onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
        };
        let onion_return = OnionReturn::new(&mut thread_rng(), &onion_symmetric_key, &ip_port, Some(&next_onion_return));
        let payload = InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 123]
        });
        let packet = OnionResponse2 {
            onion_return,
            payload: payload.clone()
        };

        alice.handle_onion_response_2(packet).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionResponse1);

        assert_eq!(next_packet.payload, payload);
        assert_eq!(next_packet.onion_return, next_onion_return);
    }

    #[tokio::test]
    async fn handle_onion_response_2_invalid_onion_return() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, _addr) = create_node();

        let onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE] // not encrypted with onion_symmetric_key
        };
        let payload = InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 123]
        });
        let packet = OnionResponse2 {
            onion_return,
            payload
        };

        alice.handle_onion_response_2(packet).await.unwrap();

        // Necessary to drop tx so that rx.collect::<Vec<_>>() can be finished
        drop(alice);

        assert!(rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn handle_onion_response_2_invalid_next_onion_return() {
        let mut rng = thread_rng();
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, _addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read().await;

        let ip_port = IpPort {
            protocol: ProtocolType::Udp,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let onion_return = OnionReturn::new(&mut thread_rng(), &onion_symmetric_key, &ip_port, None);
        let inner = OnionDataResponse {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            temporary_pk: SecretKey::generate(&mut rng).public_key(),
            payload: vec![42; 123]
        };
        let packet = OnionResponse2 {
            onion_return,
            payload: InnerOnionResponse::OnionDataResponse(inner.clone())
        };

        let res = alice.handle_onion_response_2(packet).await;
        assert!(matches!(res, Err(HandlePacketError::OnionResponseNext)));
    }

    // handle_onion_response_1
    #[tokio::test]
    async fn handle_onion_response_1_with_onion_announce_response() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, _addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read().await;

        let ip_port = IpPort {
            protocol: ProtocolType::Udp,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let onion_return = OnionReturn::new(&mut thread_rng(), &onion_symmetric_key, &ip_port, None);
        let inner = OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 123]
        };
        let packet = OnionResponse1 {
            onion_return,
            payload: InnerOnionResponse::OnionAnnounceResponse(inner.clone())
        };

        alice.handle_onion_response_1(packet).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionAnnounceResponse);

        assert_eq!(next_packet, inner);
    }

    #[tokio::test]
    async fn server_handle_onion_response_1_with_onion_data_response_test() {
        let mut rng = thread_rng();
        let (alice, _precomp, _bob_pk, _bob_sk, rx, _addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read().await;

        let ip_port = IpPort {
            protocol: ProtocolType::Udp,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let onion_return = OnionReturn::new(&mut thread_rng(), &onion_symmetric_key, &ip_port, None);
        let inner = OnionDataResponse {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            temporary_pk: SecretKey::generate(&mut rng).public_key(),
            payload: vec![42; 123]
        };
        let packet = OnionResponse1 {
            onion_return,
            payload: InnerOnionResponse::OnionDataResponse(inner.clone())
        };

        alice.handle_onion_response_1(packet).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionDataResponse);

        assert_eq!(next_packet, inner);
    }

    #[tokio::test]
    async fn handle_onion_response_1_redirect_to_tcp() {
        let (mut alice, _precomp, _bob_pk, _bob_sk, _rx, _addr) = create_node();
        let (tcp_onion_tx, tcp_onion_rx) = mpsc::channel(1);
        alice.set_tcp_onion_sink(tcp_onion_tx);

        let onion_symmetric_key = alice.onion_symmetric_key.read().await;

        let ip_port = IpPort {
            protocol: ProtocolType::Tcp,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let onion_return = OnionReturn::new(&mut thread_rng(), &onion_symmetric_key, &ip_port, None);
        let inner = InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 123]
        });
        let packet = OnionResponse1 {
            onion_return,
            payload: inner.clone()
        };

        alice.handle_onion_response_1(packet).await.unwrap();

        let (received, _tcp_onion_rx) = tcp_onion_rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());
        assert_eq!(packet, inner);
    }

    #[tokio::test]
    async fn handle_onion_response_1_can_not_redirect_to_tcp() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, _addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read().await;

        let ip_port = IpPort {
            protocol: ProtocolType::Tcp,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let onion_return = OnionReturn::new(&mut thread_rng(), &onion_symmetric_key, &ip_port, None);
        let inner = OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 123]
        };
        let packet = OnionResponse1 {
            onion_return,
            payload: InnerOnionResponse::OnionAnnounceResponse(inner.clone())
        };

        let res = alice.handle_onion_response_1(packet).await;
        assert!(matches!(res, Err(HandlePacketError::OnionResponseRedirect)));
    }

    #[tokio::test]
    async fn handle_onion_response_1_invalid_onion_return() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, _addr) = create_node();

        let onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE] // not encrypted with onion_symmetric_key
        };
        let payload = InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 123]
        });
        let packet = OnionResponse1 {
            onion_return,
            payload
        };

        alice.handle_onion_response_1(packet).await.unwrap();

        // Necessary to drop tx so that rx.collect::<Vec<_>>() can be finished
        drop(alice);

        assert!(rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn handle_onion_response_1_invalid_next_onion_return() {
        let mut rng = thread_rng();
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, _addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read().await;

        let ip_port = IpPort {
            protocol: ProtocolType::Udp,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let next_onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
        };
        let onion_return = OnionReturn::new(&mut thread_rng(), &onion_symmetric_key, &ip_port, Some(&next_onion_return));
        let inner = OnionDataResponse {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            temporary_pk: SecretKey::generate(&mut rng).public_key(),
            payload: vec![42; 123]
        };
        let packet = OnionResponse1 {
            onion_return,
            payload: InnerOnionResponse::OnionDataResponse(inner.clone())
        };

        let res = alice.handle_onion_response_1(packet).await;
        assert!(matches!(res, Err(HandlePacketError::OnionResponseNext)));
    }

    // send_nat_ping_req()
    #[tokio::test]
    async fn send_nat_ping_req() {
        let mut rng = thread_rng();
        let (alice, _precomp, _bob_pk, _bob_sk, mut rx, _addr) = create_node();

        let friend_sk = SecretKey::generate(&mut rng);
        let friend_pk = friend_sk.public_key();

        let nodes = [
            PackedNode::new("127.1.1.1:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key()),
            PackedNode::new("127.1.1.2:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key()),
            PackedNode::new("127.1.1.3:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key()),
            PackedNode::new("127.1.1.4:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key()),
        ];
        alice.add_friend(friend_pk.clone()).await;

        let mut state = alice.state.write().await;
        for node in &nodes {
            let friend = state.friends.get_mut(&friend_pk).unwrap();
            friend.try_add_to_close(node.clone());
            let dht_node = friend.close_nodes.get_node_mut(&friend_pk, &node.pk).unwrap();
            dht_node.update_returned_addr(node.saddr);
        }
        drop(state);

        alice.dht_main_loop().await.unwrap();

        loop {
            let (received, rx1) = rx.into_future().await;
            let (packet, _addr_to_send) = received.unwrap();

            if let Packet::DhtRequest(nat_ping_req) = packet {
                let precomputed_key = SalsaBox::new(&nat_ping_req.spk, &friend_sk);
                let nat_ping_req_payload = nat_ping_req.get_payload(&precomputed_key).unwrap();
                let nat_ping_req_payload = unpack!(nat_ping_req_payload, DhtRequestPayload::NatPingRequest);

                assert_eq!(alice.state.read().await.friends[&friend_pk].hole_punch.ping_id, nat_ping_req_payload.id);
                break;
            }
            rx = rx1;
        }
    }

    // handle_lan_discovery
    #[tokio::test]
    async fn handle_lan_discovery() {
        let (alice, _precomp, bob_pk, bob_sk, rx, addr) = create_node();

        let lan = LanDiscovery { pk: bob_pk };

        alice.handle_lan_discovery(&lan, addr).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let nodes_req = unpack!(packet, Packet::NodesRequest);
        let precomputed_key = SalsaBox::new(&nodes_req.pk, &bob_sk);
        let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();

        assert_eq!(nodes_req_payload.pk, alice.pk);
    }

    #[tokio::test]
    async fn handle_lan_discovery_for_ourselves() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let lan = LanDiscovery { pk: alice.pk.clone() };

        alice.handle_lan_discovery(&lan, addr).await.unwrap();

        // Necessary to drop tx so that rx.collect::<Vec<_>>() can be finished
        drop(alice);

        assert!(rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn handle_lan_discovery_when_disabled() {
        let (mut alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        alice.enable_lan_discovery(false);
        assert!(!alice.lan_discovery_enabled);

        let lan = LanDiscovery { pk: alice.pk.clone() };

        alice.handle_lan_discovery(&lan, addr).await.unwrap();

        // Necessary to drop tx so that rx.collect::<Vec<_>>() can be finished
        drop(alice);

        assert!(rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn handle_tcp_onion_request() {
        let mut rng = thread_rng();
        let (alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let temporary_pk = SecretKey::generate(&mut rng).public_key();
        let payload = vec![42; 123];
        let ip_port = IpPort {
            protocol: ProtocolType::Udp,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let packet = OnionRequest {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            ip_port: ip_port.clone(),
            temporary_pk: temporary_pk.clone(),
            payload: payload.clone()
        };

        alice.handle_tcp_onion_request(packet, addr).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionRequest1);

        assert_eq!(next_packet.temporary_pk, temporary_pk);
        assert_eq!(next_packet.payload, payload);

        let onion_symmetric_key = alice.onion_symmetric_key.read().await;
        let onion_return_payload = next_packet.onion_return.get_payload(&onion_symmetric_key).unwrap();

        assert_eq!(onion_return_payload.0, IpPort::from_tcp_saddr(addr));
    }

    #[tokio::test]
    async fn ping_nodes_to_bootstrap() {
        let mut rng = thread_rng();
        let (alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let node_sk = SecretKey::generate(&mut rng);
        let node_pk = node_sk.public_key();

        let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), node_pk.clone());
        assert!(alice.state.write().await.nodes_to_bootstrap.try_add(&alice.pk, pn, /* evict */ true));

        let pn = PackedNode::new("127.0.0.1:33445".parse().unwrap(), bob_pk.clone());
        assert!(alice.state.write().await.nodes_to_bootstrap.try_add(&alice.pk, pn, /* evict */ true));

        alice.dht_main_loop().await.unwrap();

        let mut state = alice.state.write().await;

        rx.take(2).map(|(packet, addr)| {
            let nodes_req = unpack!(packet, Packet::NodesRequest);
            if addr == "127.0.0.1:33445".parse().unwrap() {
                let precomputed_key = SalsaBox::new(&nodes_req.pk, &bob_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(state.request_queue.check_ping_id(nodes_req_payload.id, |pk| pk == &bob_pk).is_some());
                assert_eq!(nodes_req_payload.pk, alice.pk);
            } else {
                let precomputed_key = SalsaBox::new(&nodes_req.pk, &node_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(state.request_queue.check_ping_id(nodes_req_payload.id, |pk| pk == &node_pk).is_some());
                assert_eq!(nodes_req_payload.pk, alice.pk);
            }
        }).collect::<Vec<_>>().await;
    }

    #[tokio::test]
    async fn ping_nodes_from_nodes_to_ping_list() {
        let mut rng = thread_rng();
        let (alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let node_sk = SecretKey::generate(&mut rng);
        let node_pk = node_sk.public_key();

        let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), node_pk.clone());
        assert!(alice.nodes_to_ping.write().await.try_add(&alice.pk, pn, /* evict */ true));

        let pn = PackedNode::new("127.0.0.1:33445".parse().unwrap(), bob_pk.clone());
        assert!(alice.nodes_to_ping.write().await.try_add(&alice.pk, pn, /* evict */ true));

        alice.send_pings().await.unwrap();

        let mut state = alice.state.write().await;

        rx.take(2).map(|(packet, addr)| {
            let nodes_req = unpack!(packet, Packet::PingRequest);
            if addr == "127.0.0.1:33445".parse().unwrap() {
                let precomputed_key = SalsaBox::new(&nodes_req.pk, &bob_sk);
                let ping_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(state.request_queue.check_ping_id(ping_req_payload.id, |pk| pk == &bob_pk).is_some());
            } else {
                let precomputed_key = SalsaBox::new(&nodes_req.pk, &node_sk);
                let ping_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(state.request_queue.check_ping_id(ping_req_payload.id, |pk| pk == &node_pk).is_some());
            }
        }).collect::<Vec<_>>().await;
    }

    #[tokio::test]
    async fn ping_nodes_when_nodes_to_ping_list_is_empty() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, _addr) = create_node();

        alice.send_pings().await.unwrap();

        // Necessary to drop tx so that rx.collect::<Vec<_>>() can be finished
        drop(alice);

        assert!(rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn ping_close_nodes() {
        let mut rng = thread_rng();
        let (alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let node_sk = SecretKey::generate(&mut rng);
        let node_pk = node_sk.public_key();

        let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), node_pk.clone());
        assert!(alice.state.write().await.close_nodes.try_add(pn));

        let pn = PackedNode::new("127.0.0.1:33445".parse().unwrap(), bob_pk.clone());
        assert!(alice.state.write().await.close_nodes.try_add(pn));

        alice.dht_main_loop().await.unwrap();

        let mut state = alice.state.write().await;

        // 3 = 2 packets sent by ping_close_nodes + 1 packet sent by send_nodes_req_random
        rx.take(3).map(|(packet, addr)| {
            let nodes_req = unpack!(packet, Packet::NodesRequest);
            if addr == "127.0.0.1:33445".parse().unwrap() {
                let precomputed_key = SalsaBox::new(&nodes_req.pk, &bob_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(state.request_queue.check_ping_id(nodes_req_payload.id, |pk| pk == &bob_pk).is_some());
                assert_eq!(nodes_req_payload.pk, alice.pk);
            } else {
                let precomputed_key = SalsaBox::new(&nodes_req.pk, &node_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(state.request_queue.check_ping_id(nodes_req_payload.id, |pk| pk == &node_pk).is_some());
                assert_eq!(nodes_req_payload.pk, alice.pk);
            }
        }).collect::<Vec<_>>().await;
    }

    #[tokio::test]
    async fn send_nodes_req_random_periodicity() {
        let (alice, _precomp, bob_pk, _bob_sk, mut rx, _addr) = create_node();

        {
            let mut state = alice.state.write().await;
            let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), bob_pk.clone());
            assert!(state.close_nodes.try_add(pn));
            let node = state.close_nodes.get_node_mut(&bob_pk).unwrap();
            // Set last_ping_req_time so that only random request will be sent
            node.assoc4.last_ping_req_time = Some(clock_now());
            node.assoc6.last_ping_req_time = Some(clock_now());
        }

        tokio::time::pause();

        // Random request should be sent every second MAX_BOOTSTRAP_TIMES times
        // This loop will produce MAX_BOOTSTRAP_TIMES random packets
        for _ in 0 .. MAX_BOOTSTRAP_TIMES {
            alice.dht_main_loop().await.unwrap();

            let (received, rx1) = rx.into_future().await;
            let (packet, _) = received.unwrap();

            unpack!(packet, Packet::NodesRequest);

            tokio::time::advance(Duration::from_secs(1)).await;
            rx = rx1;
        }

        // Random packet won't be sent anymore if NODES_REQ_INTERVAL is not passed
        alice.dht_main_loop().await.unwrap();

        // Necessary to drop tx so that rx.collect::<Vec<_>>() can be finished
        drop(alice);

        assert!(rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn ping_nodes_to_bootstrap_of_friend() {
        let mut rng = thread_rng();
        let (alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let node_sk = SecretKey::generate(&mut rng);
        let node_pk = node_sk.public_key();

        let friend_pk = SecretKey::generate(&mut rng).public_key();

        alice.add_friend(friend_pk.clone()).await;

        let mut state = alice.state.write().await;
        let friend = state.friends.get_mut(&friend_pk).unwrap();

        let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), node_pk.clone());
        assert!(friend.nodes_to_bootstrap.try_add(&alice.pk, pn, /* evict */ true));

        let pn = PackedNode::new("127.0.0.1:33445".parse().unwrap(), bob_pk.clone());
        assert!(friend.nodes_to_bootstrap.try_add(&alice.pk, pn, /* evict */ true));

        drop(state);

        alice.dht_main_loop().await.unwrap();

        let mut state = alice.state.write().await;

        rx.take(2).map(|(packet, addr)| {
            let nodes_req = unpack!(packet, Packet::NodesRequest);
            if addr == "127.0.0.1:33445".parse().unwrap() {
                let precomputed_key = SalsaBox::new(&nodes_req.pk, &bob_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(state.request_queue.check_ping_id(nodes_req_payload.id, |pk| pk == &bob_pk).is_some());
                assert_eq!(nodes_req_payload.pk, friend_pk);
            } else {
                let precomputed_key = SalsaBox::new(&nodes_req.pk, &node_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(state.request_queue.check_ping_id(nodes_req_payload.id, |pk| pk == &node_pk).is_some());
                assert_eq!(nodes_req_payload.pk, friend_pk);
            }
        }).collect::<Vec<_>>().await;
    }

    #[tokio::test]
    async fn ping_close_nodes_of_friend() {
        let mut rng = thread_rng();
        let (alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let node_sk = SecretKey::generate(&mut rng);
        let node_pk = node_sk.public_key();

        let friend_pk = SecretKey::generate(&mut rng).public_key();

        alice.add_friend(friend_pk.clone()).await;

        {
            let mut state = alice.state.write().await;
            let friend = state.friends.get_mut(&friend_pk).unwrap();

            let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), node_pk.clone());
            assert!(friend.try_add_to_close(pn));

            let pn = PackedNode::new("127.0.0.1:33445".parse().unwrap(), bob_pk.clone());
            assert!(friend.try_add_to_close(pn));
        }

        alice.dht_main_loop().await.unwrap();

        let mut state = alice.state.write().await;

        // 3 = 2 packets sent by ping_close_nodes + 1 packet sent by send_nodes_req_random
        rx.take(3).map(|(packet, addr)| {
            let nodes_req = unpack!(packet, Packet::NodesRequest);
            if addr == "127.0.0.1:33445".parse().unwrap() {
                let precomputed_key = SalsaBox::new(&nodes_req.pk, &bob_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(state.request_queue.check_ping_id(nodes_req_payload.id, |pk| pk == &bob_pk).is_some());
                assert_eq!(nodes_req_payload.pk, friend_pk);
            } else {
                let precomputed_key = SalsaBox::new(&nodes_req.pk, &node_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(state.request_queue.check_ping_id(nodes_req_payload.id, |pk| pk == &node_pk).is_some());
                assert_eq!(nodes_req_payload.pk, friend_pk);
            }
        }).collect::<Vec<_>>().await;
    }

    #[tokio::test]
    async fn send_nodes_req_random_friend_periodicity() {
        let mut rng = thread_rng();
        let (alice, _precomp, bob_pk, _bob_sk, mut rx, _addr) = create_node();

        let friend_pk = SecretKey::generate(&mut rng).public_key();
        alice.add_friend(friend_pk.clone()).await;

        let mut state = alice.state.write().await;
        let friend = state.friends.get_mut(&friend_pk).unwrap();

        let pn = PackedNode::new("127.0.0.1:33445".parse().unwrap(), bob_pk);
        assert!(friend.try_add_to_close(pn));

        // Set last_ping_req_time so that only random request will be sent
        friend.close_nodes.nodes[0].assoc4.last_ping_req_time = Some(clock_now());
        friend.close_nodes.nodes[0].assoc6.last_ping_req_time = Some(clock_now());

        drop(state);

        tokio::time::pause();

        // Random request should be sent every second MAX_BOOTSTRAP_TIMES times
        // This loop will produce MAX_BOOTSTRAP_TIMES random packets
        for _ in 0 .. MAX_BOOTSTRAP_TIMES {
            alice.state.write().await.friends.get_mut(&friend_pk).unwrap().hole_punch.last_send_ping_time = Some(clock_now());
            alice.dht_main_loop().await.unwrap();

            let (received, rx1) = rx.into_future().await;
            let (packet, _) = received.unwrap();

            unpack!(packet, Packet::NodesRequest);

            tokio::time::advance(Duration::from_secs(1)).await;
            rx = rx1;
        }

        // Random packet won't be sent anymore if NODES_REQ_INTERVAL is not passed
        alice.dht_main_loop().await.unwrap();

        // Necessary to drop tx so that rx.collect::<Vec<_>>() can be finished
        drop(alice);

        assert!(rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn enable_ipv6_mode() {
        let (mut alice, _precomp, _bob_pk, _bob_sk, _rx, _addr) = create_node();

        alice.enable_ipv6_mode(true);
        assert!(alice.is_ipv6_enabled);
    }

    #[tokio::test]
    async fn send_to() {
        let mut rng = thread_rng();
        let (mut alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let node_sk = SecretKey::generate(&mut rng);
        let node_pk = node_sk.public_key();

        let pn = PackedNode::new("[FF::01]:33445".parse().unwrap(), bob_pk.clone());
        assert!(alice.state.write().await.close_nodes.try_add(pn));

        let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), node_pk.clone());
        assert!(alice.state.write().await.close_nodes.try_add(pn));

        // test with ipv6 mode
        alice.enable_ipv6_mode(true);
        alice.dht_main_loop().await.unwrap();

        let mut state = alice.state.write().await;

        rx.take(2).map(|(packet, addr)| {
            let nodes_req = unpack!(packet, Packet::NodesRequest);
            if addr == "[FF::01]:33445".parse().unwrap() {
                let precomputed_key = SalsaBox::new(&nodes_req.pk, &bob_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(state.request_queue.check_ping_id(nodes_req_payload.id, |pk| pk == &bob_pk).is_some());
            } else {
                let precomputed_key = SalsaBox::new(&nodes_req.pk, &node_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(state.request_queue.check_ping_id(nodes_req_payload.id, |pk| pk == &node_pk).is_some());
            }
        }).collect::<Vec<_>>().await;
    }

    #[tokio::test]
    async fn send_bootstrap_requests() {
        let mut rng = thread_rng();
        let (mut alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let node_sk = SecretKey::generate(&mut rng);
        let node_pk = node_sk.public_key();

        let pn = PackedNode::new("[FF::01]:33445".parse().unwrap(), bob_pk.clone());
        alice.add_initial_bootstrap(pn);

        let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), node_pk.clone());
        alice.add_initial_bootstrap(pn);

        // test with ipv6 mode
        alice.enable_ipv6_mode(true);
        alice.send_bootstrap_requests().await.unwrap();

        let mut state = alice.state.write().await;

        rx.take(2).map(|(packet, addr)| {
            let nodes_req = unpack!(packet, Packet::NodesRequest);
            if addr == "[FF::01]:33445".parse().unwrap() {
                let precomputed_key = SalsaBox::new(&nodes_req.pk, &bob_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(state.request_queue.check_ping_id(nodes_req_payload.id, |pk| pk == &bob_pk).is_some());
            } else {
                let precomputed_key = SalsaBox::new(&nodes_req.pk, &node_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(state.request_queue.check_ping_id(nodes_req_payload.id, |pk| pk == &node_pk).is_some());
            }
        }).collect::<Vec<_>>().await;
    }

    #[tokio::test]
    async fn send_bootstrap_requests_when_ktree_has_good_node() {
        let mut rng = thread_rng();
        let (mut alice, _precomp, bob_pk, _bob_sk, rx, _addr) = create_node();
        let node_pk = SecretKey::generate(&mut rng).public_key();

        let pn = PackedNode::new("[FF::01]:33445".parse().unwrap(), bob_pk);
        alice.add_initial_bootstrap(pn);

        let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), node_pk);
        assert!(alice.state.write().await.close_nodes.try_add(pn));

        // test with ipv6 mode
        alice.enable_ipv6_mode(true);
        alice.send_bootstrap_requests().await.unwrap();

        // Necessary to drop tx so that rx.collect::<Vec<_>>() can be finished
        drop(alice);

        assert!(rx.collect::<Vec<_>>().await.is_empty());
    }

    #[tokio::test]
    async fn send_bootstrap_requests_with_discarded() {
        let mut rng = thread_rng();
        let (mut alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let node_sk = SecretKey::generate(&mut rng);
        let node_pk = node_sk.public_key();

        let mut state = alice.state.write().await;

        let pn = PackedNode::new("[FF::01]:33445".parse().unwrap(), bob_pk.clone());
        assert!(state.close_nodes.try_add(pn));
        let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), node_pk.clone());
        assert!(state.close_nodes.try_add(pn));

        drop(state);

        // test with ipv6 mode
        alice.enable_ipv6_mode(true);

        tokio::time::pause();
        tokio::time::advance(KILL_NODE_TIMEOUT + Duration::from_secs(1)).await;

        alice.send_bootstrap_requests().await.unwrap();

        let mut state = alice.state.write().await;

        rx.take(2).map(|(packet, addr)| {
            let nodes_req = unpack!(packet, Packet::NodesRequest);
            if addr == "[FF::01]:33445".parse().unwrap() {
                let precomputed_key = SalsaBox::new(&nodes_req.pk, &bob_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(state.request_queue.check_ping_id(nodes_req_payload.id, |pk| pk == &bob_pk).is_some());
            } else {
                let precomputed_key = SalsaBox::new(&nodes_req.pk, &node_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(state.request_queue.check_ping_id(nodes_req_payload.id, |pk| pk == &node_pk).is_some());
            }
        }).collect::<Vec<_>>().await;
    }

    #[tokio::test]
    async fn ping_node() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let node = PackedNode::new(addr, bob_pk);

        alice.ping_node(node).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let nodes_req = unpack!(packet, Packet::NodesRequest);
        let nodes_req_payload = nodes_req.get_payload(&precomp).unwrap();

        assert_eq!(nodes_req_payload.pk, alice.pk);
    }

    #[tokio::test]
    async fn random_friend_nodes() {
        let mut rng = thread_rng();
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, _addr) = create_node();

        // add one real friend to make sure that its node won't get to the result
        let friend_pk = SecretKey::generate(&mut rng).public_key();
        alice.add_friend(friend_pk.clone()).await;

        let mut state = alice.state.write().await;

        for pk in &alice.fake_friends_keys {
            let node = PackedNode::new("127.0.0.1:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key());
            assert!(state.friends.get_mut(pk).unwrap().close_nodes.try_add(pk, node, true));
        }

        let node = PackedNode::new("127.0.0.1:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key());
        assert!(state.friends.get_mut(&friend_pk).unwrap().close_nodes.try_add(&friend_pk, node.clone(), true));

        drop(state);

        let nodes = alice.random_friend_nodes(FAKE_FRIENDS_NUMBER as u8 + 1).await;
        assert_eq!(nodes.len(), FAKE_FRIENDS_NUMBER);
        assert!(!nodes.contains(&node));

        let nodes = alice.random_friend_nodes(FAKE_FRIENDS_NUMBER as u8 - 1).await;
        assert_eq!(nodes.len(), FAKE_FRIENDS_NUMBER - 1);
        assert!(!nodes.contains(&node));
    }

    #[tokio::test]
    async fn is_connected() {
        let mut rng = thread_rng();
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, _addr) = create_node();

        assert!(!alice.is_connected().await);
        alice.add_node(PackedNode::new("127.0.0.1:12345".parse().unwrap(), SecretKey::generate(&mut rng).public_key())).await;
        assert!(alice.is_connected().await);
    }
}
