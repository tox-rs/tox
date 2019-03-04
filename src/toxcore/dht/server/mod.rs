/*!
Functionality needed to work as a DHT node.
This module works on top of other modules.
*/

pub mod hole_punching;
mod errors;

use failure::Fail;
use futures::{Future, Sink, Stream, future, stream};
use futures::future::{Either, join_all};
use futures::sync::mpsc;
use parking_lot::RwLock;
use tokio::timer::Interval;
use tokio::timer::timeout::Error as TimeoutError;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{iter, mem};

use crate::toxcore::time::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packet::*;
use crate::toxcore::dht::packed_node::*;
use crate::toxcore::dht::kbucket::*;
use crate::toxcore::dht::ktree::*;
use crate::toxcore::dht::precomputed_cache::*;
use crate::toxcore::onion::packet::*;
use crate::toxcore::onion::onion_announce::*;
use crate::toxcore::dht::request_queue::*;
use crate::toxcore::io_tokio::*;
use crate::toxcore::ip_port::*;
use crate::toxcore::dht::dht_friend::*;
use crate::toxcore::dht::dht_node::*;
use crate::toxcore::dht::server::hole_punching::*;
use crate::toxcore::tcp::packet::OnionRequest;
use crate::toxcore::net_crypto::*;
use crate::toxcore::dht::ip_port::IsGlobal;
use crate::toxcore::utils::*;
use crate::toxcore::dht::server::errors::*;

/// Shorthand for the transmit half of the message channel.
type Tx = mpsc::Sender<(Packet, SocketAddr)>;

/// Shorthand for the transmit half of the TCP onion channel.
type TcpOnionTx = mpsc::Sender<(InnerOnionResponse, SocketAddr)>;

/// Number of random `NodesRequest` packet to send every second one per second.
/// After random requests count exceeds this number `NODES_REQ_INTERVAL` will be
/// used.
pub const MAX_BOOTSTRAP_TIMES: u32 = 5;
/// How often onion key should be refreshed.
pub const ONION_REFRESH_KEY_INTERVAL: u64 = 7200;
/// Interval in seconds for random `NodesRequest`.
pub const NODES_REQ_INTERVAL: u64 = 20;
/// Ping timeout in seconds.
pub const PING_TIMEOUT: u64 = 5;
/// Maximum newly announced nodes to ping per `TIME_TO_PING` seconds.
pub const MAX_TO_PING: u8 = 32;
/// Maximum nodes to send `NodesRequest` packet.
pub const MAX_TO_BOOTSTRAP: u8 = 8;
/// How often in seconds to ping newly announced nodes.
pub const TIME_TO_PING: u64 = 2;
/// How often in seconds to ping initial bootstrap nodes.
pub const BOOTSTRAP_INTERVAL: u64 = 1;
/// Number of fake friends that server has.
pub const FAKE_FRIENDS_NUMBER: usize = 2;
/// Maximum number of entry in Lru cache for precomputed keys.
pub const PRECOMPUTED_LRU_CACHE_SIZE: usize = KBUCKET_DEFAULT_SIZE as usize * KBUCKET_MAX_ENTRIES as usize + // For KTree.
    KBUCKET_DEFAULT_SIZE as usize * (2 + 10); // For friend's close_nodes of 2 fake friends + 10 friends reserved
/// Timeout in seconds for packet sending
pub const DHT_SEND_TIMEOUT: u64 = 1;
/// How often DHT main loop should be called.
const MAIN_LOOP_INTERVAL: u64 = 1;

/// Struct that contains necessary data for `BootstrapInfo` packet.
#[derive(Clone)]
struct ServerBootstrapInfo {
    /// Version of tox core which will be sent with `BootstrapInfo` packet.
    version: u32,
    /// Callback to get the message of the day which will be sent with
    /// `BootstrapInfo` packet.
    motd_cb: Arc<Fn(&Server) -> Vec<u8> + Send + Sync>,
}

/**
Own DHT node data.

Contains:

- DHT public key
- DHT secret key
- Close List ([`Ktree`] with nodes close to own DHT public key)

Before a [`PackedNode`] is added to the Close List, it needs to be
checked whether:

- it can be added to [`Ktree`] \(using [`Ktree::can_add()`])
- [`PackedNode`] is actually online

Once the first check passes node is added to the temporary list, and
a [`NodesRequest`] request is sent to it in order to check whether it's
online. If the node responds correctly within [`PING_TIMEOUT`], it's
removed from temporary list and added to the Close List.

[`NodesRequest`]: ../dht/struct.NodesRequest.html
[`Ktree`]: ../dht/struct.Ktree.html
[`Ktree::can_add()`]: ../dht/struct.Ktree.html#method.can_add
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
    /// Sink to send friend's `SocketAddr` when it gets known.
    friend_saddr_sink: Option<mpsc::UnboundedSender<PackedNode>>,
    /// Struct that stores and manages requests IDs and timeouts.
    request_queue: Arc<RwLock<RequestQueue>>,
    /// Close nodes list which contains nodes close to own DHT `PublicKey`.
    pub close_nodes: Arc<RwLock<Ktree>>,
    /// Symmetric key used for onion return encryption.
    onion_symmetric_key: Arc<RwLock<secretbox::Key>>,
    /// Onion announce struct to handle `OnionAnnounce` and `OnionData` packets.
    onion_announce: Arc<RwLock<OnionAnnounce>>,
    /// Friends list used to store friends related data like close nodes per
    /// friend, hole punching status, etc. First FAKE_FRIENDS_NUMBER friends
    /// are fake with random public key.
    friends: Arc<RwLock<HashMap<PublicKey, DhtFriend>>>,
    /// List of nodes to send `NodesRequest` packet. When we `NodesResponse`
    /// packet we should send `NodesRequest` to all nodes from the response to
    /// check if they are capable of handling our requests and to continue
    /// bootstrapping. But instead of instant sending `NodesRequest` we will add
    /// the node to this list which is processed every second. The purpose of
    /// this is to prevent amplification attacks.
    nodes_to_bootstrap: Arc<RwLock<Kbucket<PackedNode>>>,
    /// How many times we sent `NodesRequest` packet to a random node from close
    /// nodes list.
    random_requests_count: Arc<RwLock<u32>>,
    /// Time when we sent `NodesRequest` packet to a random node from close
    /// nodes list.
    last_nodes_req_time: Arc<RwLock<Instant>>,
    /// List of nodes to send `PingRequest`. When we receive `PingRequest` or
    /// `NodesRequest` packet from a new node we should send `PingRequest` to
    /// this node to check if it's capable of handling our requests. But instead
    /// of instant sending `PingRequest` we will add the node to this list which
    /// is processed every `TIME_TO_PING` seconds. The purpose of this is to
    /// prevent amplification attacks.
    nodes_to_ping: Arc<RwLock<Kbucket<PackedNode>>>,
    /// Info used to respond to `BootstrapInfo` packets.
    bootstrap_info: Option<ServerBootstrapInfo>,
    /// `OnionResponse1` packets that have TCP protocol kind inside onion return
    /// should be redirected to TCP sender trough this sink
    /// None if there is no TCP relay
    tcp_onion_sink: Option<TcpOnionTx>,
    /// Net crypto module that handles `CookieRequest`, `CookieResponse`,
    /// `CryptoHandshake` and `CryptoData` packets. It can be `None` in case of
    /// pure bootstrap server when we don't have friends and therefore don't
    /// have to handle related packets.
    net_crypto: Option<NetCrypto>,
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

        // Adding 2 fake friends with random public key. It serves two purposes:
        // - server will send NodesRequest packets with these 2 random keys
        //   periodically thereby it will fill Ktree with farther nodes and
        //   speed up bootstrap process.
        // - close nodes of these two friends can be used as pool of random
        //   nodes for onion client.
        // It's the same way as c-toxcore acts but it's not the best way. So it
        // has to be rewritten in a cleaner and safer manner. Most likely onion
        // will be replaced by DHT announcements:
        // https://github.com/zugz/tox-DHTAnnouncements/blob/master/DHTAnnouncements.md
        let friends = iter::repeat_with(|| {
            let pk = gen_keypair().0;
            (pk, DhtFriend::new(pk))
        }).take(FAKE_FRIENDS_NUMBER).collect();

        let precomputed_keys = PrecomputedCache::new(sk.clone(), PRECOMPUTED_LRU_CACHE_SIZE);

        Server {
            sk,
            pk,
            tx,
            friend_saddr_sink: None,
            request_queue: Arc::new(RwLock::new(RequestQueue::new(Duration::from_secs(PING_TIMEOUT)))),
            close_nodes: Arc::new(RwLock::new(Ktree::new(&pk))),
            onion_symmetric_key: Arc::new(RwLock::new(secretbox::gen_key())),
            onion_announce: Arc::new(RwLock::new(OnionAnnounce::new(pk))),
            friends: Arc::new(RwLock::new(friends)),
            nodes_to_bootstrap: Arc::new(RwLock::new(Kbucket::new(MAX_TO_BOOTSTRAP))),
            random_requests_count: Arc::new(RwLock::new(0)),
            last_nodes_req_time: Arc::new(RwLock::new(clock_now())),
            nodes_to_ping: Arc::new(RwLock::new(Kbucket::new(MAX_TO_PING))),
            bootstrap_info: None,
            tcp_onion_sink: None,
            net_crypto: None,
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

    /// Get closest nodes from both close_nodes and friend's close_nodes
    fn get_closest_inner(
        close_nodes: &Ktree,
        friends: &HashMap<PublicKey, DhtFriend>,
        base_pk: &PublicKey,
        only_global: bool
    ) -> Kbucket<PackedNode> {
        let mut kbucket = close_nodes.get_closest(base_pk, only_global);

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
    fn get_closest(&self, base_pk: &PublicKey, only_global: bool) -> Kbucket<PackedNode> {
        let close_nodes = self.close_nodes.read();
        let friends = self.friends.read();

        Server::get_closest_inner(&close_nodes, &friends, base_pk, only_global)
    }

    /// Add a friend to the DHT friends list to look for it's IP address. After
    /// IP address it will be sent to `friend_saddr_sink`.
    pub fn add_friend(&self, friend_pk: PublicKey) {
        let mut friends = self.friends.write();

        if friends.contains_key(&friend_pk) {
            return;
        }

        let close_nodes = self.close_nodes.read();

        let mut friend = DhtFriend::new(friend_pk);
        let close_nodes = Server::get_closest_inner(&close_nodes, &friends, &friend.pk, true);

        for &node in close_nodes.iter() {
            friend.nodes_to_bootstrap.try_add(&friend.pk, node, /* evict */ true);
        }

        friends.insert(friend_pk, friend);
    }

    /// The main loop of DHT server which should be called every second. This
    /// method iterates over all nodes from close nodes list, close nodes of
    /// friends and bootstrap nodes and sends `NodesRequest` packets if
    /// necessary.
    fn dht_main_loop(&self) -> impl Future<Item = (), Error = RunError> + Send {
        // Check if we should send `NodesRequest` packet to a random node. This
        // request is sent every second 5 times and then every 20 seconds.
        fn send_random_request(last_nodes_req_time: &mut Instant, random_requests_count: &mut u32) -> bool {
            if clock_elapsed(*last_nodes_req_time) > Duration::from_secs(NODES_REQ_INTERVAL) || *random_requests_count < MAX_BOOTSTRAP_TIMES {
                *random_requests_count = random_requests_count.saturating_add(1);
                *last_nodes_req_time = clock_now();
                true
            } else {
                false
            }
        }

        let mut request_queue = self.request_queue.write();
        let mut nodes_to_bootstrap = self.nodes_to_bootstrap.write();
        let mut close_nodes = self.close_nodes.write();
        let mut friends = self.friends.write();

        request_queue.clear_timed_out();

        // Send NodesRequest packets to nodes from the Server
        let ping_nodes_to_bootstrap = self.ping_nodes_to_bootstrap(&mut request_queue, &mut nodes_to_bootstrap, self.pk)
            .map_err(|e| RunError::from(e));
        let ping_close_nodes = self.ping_close_nodes(&mut request_queue, close_nodes.iter_mut(), self.pk)
            .map_err(|e| RunError::from(e));
        let send_nodes_req_random = if send_random_request(&mut self.last_nodes_req_time.write(), &mut self.random_requests_count.write()) {
            Either::A(self.send_nodes_req_random(&mut request_queue, close_nodes.iter(), self.pk)
                .map_err(|e| RunError::from(e)))
        } else {
            Either::B(future::ok(()))
        };

        // Send NodesRequest packets to nodes from every DhtFriend
        let send_nodes_req_to_friends = friends.values_mut().map(|friend| {
            let ping_nodes_to_bootstrap = self.ping_nodes_to_bootstrap(&mut request_queue, &mut friend.nodes_to_bootstrap, friend.pk)
                .map_err(|e| RunError::from(e));
            let ping_close_nodes = self.ping_close_nodes(&mut request_queue, friend.close_nodes.nodes.iter_mut(), friend.pk)
                .map_err(|e| RunError::from(e));
            let send_nodes_req_random = if send_random_request(&mut friend.last_nodes_req_time, &mut friend.random_requests_count) {
                Either::A(self.send_nodes_req_random(&mut request_queue, friend.close_nodes.nodes.iter(), friend.pk)
                    .map_err(|e| RunError::from(e)))
            } else {
                Either::B(future::ok(()))
            };
            ping_nodes_to_bootstrap.join3(ping_close_nodes, send_nodes_req_random)
        }).collect::<Vec<_>>();

        let send_nat_ping_req = self.send_nat_ping_req(&mut request_queue, &mut friends)
            .map_err(|e| RunError::from(e));

        ping_nodes_to_bootstrap.join5(
            ping_close_nodes,
            send_nodes_req_random,
            future::join_all(send_nodes_req_to_friends),
            send_nat_ping_req
        ).map(|_| ())
    }

    /// Run DHT periodical tasks. Result future will never be completed
    /// successfully.
    pub fn run(self) -> impl Future<Item = (), Error = RunError> + Send {
        self.clone().run_pings_sending().join4(
            self.clone().run_onion_key_refreshing(),
            self.clone().run_main_loop(),
            self.run_bootstrap_requests_sending()
        ).map(|_| ())
    }

    /// Store bootstap nodes
    pub fn add_initial_bootstrap(&mut self, pn: PackedNode) {
        self.initial_bootstrap.push(pn);
    }

    /// Run initial bootstrapping. It sends `NodesRequest` packet to bootstrap
    /// nodes periodically if all nodes in Ktree are discarded (including the
    /// case when it's empty). It has to be an endless loop because we might
    /// loose the network connection and thereby loose all nodes in Ktree.
    fn run_bootstrap_requests_sending(self) -> impl Future<Item = (), Error = RunError> + Send {
        let interval = Duration::from_secs(BOOTSTRAP_INTERVAL);
        let wakeups = Interval::new(Instant::now(), interval);

        wakeups
            .map_err(|e| RunError::from(e))
            .for_each(move |_instant| {
                trace!("Bootstrap wake up");
                self.send_bootstrap_requests()
                    .map_err(|e| RunError::from(e))
            })
    }

    /// Check if all nodes in Ktree are discarded (including the case when
    /// it's empty) and if so then send `NodesRequest` packet to nodes from
    /// initial bootstrap list and from Ktree.
    fn send_bootstrap_requests(&self) -> impl Future<Item = (), Error = TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> + Send {
        let mut request_queue = self.request_queue.write();
        let close_nodes = self.close_nodes.read();

        if !close_nodes.is_all_discarded() {
            return Either::A(future::ok(()));
        }

        let futures = close_nodes
            .iter()
            .flat_map(|node| node.to_all_packed_nodes())
            .chain(self.initial_bootstrap.iter().cloned())
            .map(|node| self.send_nodes_req(&node, &mut request_queue, self.pk))
            .collect::<Vec<_>>();

        Either::B(join_all(futures).map(|_| ()))
    }

    /// Run DHT main loop periodically. Result future will never be completed
    /// successfully.
    fn run_main_loop(self) -> impl Future<Item = (), Error = RunError> + Send {
        let interval = Duration::from_secs(MAIN_LOOP_INTERVAL);
        let wakeups = Interval::new(Instant::now(), interval);
        wakeups
            .map_err(|e| RunError::from(e))
            .for_each(move |_instant| {
                trace!("DHT server wake up");
                self.dht_main_loop().then(|res| {
                    if let Err(e) = res {
                        warn!("Failed to send DHT periodical packets: {}", e);
                    }
                    future::ok(())
                })
            })
    }

    /// Refresh onion symmetric key periodically. Result future will never be
    /// completed successfully.
    fn run_onion_key_refreshing(self) -> impl Future<Item = (), Error = RunError> + Send {
        let interval = Duration::from_secs(ONION_REFRESH_KEY_INTERVAL);
        let wakeups = Interval::new(Instant::now() + interval, interval);
        wakeups
            .map_err(|e| RunError::from(e))
            .for_each(move |_instant| {
                trace!("Refreshing onion key");
                self.refresh_onion_key();
                future::ok(())
            })
    }

    /// Run ping sending periodically. Result future will never be completed
    /// successfully.
    fn run_pings_sending(self) -> impl Future<Item = (), Error = RunError> + Send {
        let interval = Duration::from_secs(TIME_TO_PING);
        let wakeups = Interval::new(Instant::now() + interval, interval);
        wakeups
            .map_err(|e| RunError::from(e))
            .for_each(move |_instant| {
                trace!("Pings sending wake up");
                self.send_pings()
                    .map_err(|e| RunError::from(e))
            })
    }

    /// Send `PingRequest` packets to nodes from `nodes_to_ping` list.
    fn send_pings(&self) -> impl Future<Item = (), Error = TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> + Send {
        let nodes_to_ping = mem::replace(
            &mut *self.nodes_to_ping.write(),
            Kbucket::<PackedNode>::new(MAX_TO_PING)
        );

        if nodes_to_ping.is_empty() {
            return Either::A(future::ok(()))
        }

        let mut request_queue = self.request_queue.write();

        let futures = nodes_to_ping.iter().map(|node|
            self.send_ping_req(node, &mut request_queue)
        ).collect::<Vec<_>>();

        Either::B(future::join_all(futures).map(|_| ()))
    }

    /// Add node to a `nodes_to_ping` list to send ping later. If node is
    /// a friend and we don't know it's address then this method will send
    /// `PingRequest` immediately instead of adding to a `nodes_to_ping`
    /// list.
    fn ping_add(&self, node: &PackedNode) -> impl Future<Item = (), Error = TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> + Send {
        let close_nodes = self.close_nodes.read();

        if !close_nodes.can_add(&node) {
            return Either::A(future::ok(()))
        }

        let friends = self.friends.read();

        // If node is friend and we don't know friend's IP address yet then send
        // PingRequest immediately and unconditionally
        if friends.get(&node.pk).map_or(false, |friend| !friend.is_addr_known()) {
            return Either::B(self.send_ping_req(&node, &mut self.request_queue.write()))
        }

        self.nodes_to_ping.write().try_add(&self.pk, *node, /* evict */ true);

        Either::A(future::ok(()))
    }

    /// Send `NodesRequest` packets to nodes from bootstrap list. This is
    /// necessary to check whether node is alive before adding it to close
    /// nodes lists.
    fn ping_nodes_to_bootstrap(&self, request_queue: &mut RequestQueue, nodes_to_bootstrap: &mut Kbucket<PackedNode>, pk: PublicKey)
        -> impl Future<Item = (), Error = TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> + Send {
        let capacity = nodes_to_bootstrap.capacity() as u8;
        let nodes_to_bootstrap = mem::replace(nodes_to_bootstrap, Kbucket::new(capacity));

        let futures = nodes_to_bootstrap.iter()
            .map(|node| self.send_nodes_req(&node, request_queue, pk))
            .collect::<Vec<_>>();

        future::join_all(futures).map(|_| ())
    }

    /// Iterate over nodes from close nodes list and send `NodesRequest` packets
    /// to them if necessary.
    fn ping_close_nodes<'a, T>(&self, request_queue: &mut RequestQueue, nodes: T, pk: PublicKey)
        -> Box<dyn Future<Item = (), Error = TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> + Send>
        where T: Iterator<Item = &'a mut DhtNode> // if change to impl Future the result will be dependent on nodes lifetime
    {
        let futures = nodes
            .flat_map(|node| {
                let ping_addr_v4 = node.assoc4
                    .ping_addr()
                    .map(|addr| PackedNode::new(addr.into(), &node.pk));
                let ping_addr_v6 = node.assoc6
                    .ping_addr()
                    .map(|addr| PackedNode::new(addr.into(), &node.pk));
                ping_addr_v4.into_iter().chain(ping_addr_v6.into_iter())
            })
            .map(|node| self.send_nodes_req(&node, request_queue, pk))
            .collect::<Vec<_>>();

        Box::new(future::join_all(futures).map(|_| ()))
    }

    /// Send `NodesRequest` packet to a random good node every 20 seconds or if
    /// it was sent less than `NODES_REQ_INTERVAL`. This function should be
    /// called every second.
    fn send_nodes_req_random<'a, T>(&self, request_queue: &mut RequestQueue, nodes: T, pk: PublicKey)
        -> Box<dyn Future<Item = (), Error = TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> + Send>
        where T: Iterator<Item = &'a DhtNode> // if change to impl Future the result will be dependent on nodes lifetime
    {
        let good_nodes = nodes
            .filter(|&node| !node.is_bad())
            .flat_map(|node| node.to_all_packed_nodes())
            .collect::<Vec<_>>();

        if good_nodes.is_empty() {
            // Random request should be sent only to good nodes
            return Box::new(future::ok(()))
        }

        let mut random_node_idx = random_limit_usize(good_nodes.len());
        // Increase probability of sending packet to a close node (has lower index)
        if random_node_idx != 0 {
            random_node_idx -= random_limit_usize(random_node_idx + 1);
        }

        let random_node = &good_nodes[random_node_idx];

        Box::new(self.send_nodes_req(&random_node, request_queue, pk))
    }

    /// Ping node with `NodesRequest` packet with self DHT `PublicKey`.
    pub fn ping_node(&self, node: &PackedNode) -> impl Future<Item = (), Error = PingError> + Send {
        let mut request_queue = self.request_queue.write();
        self.send_nodes_req(node, &mut request_queue, self.pk).map_err(PingError::from)
    }

    /// Send `PingRequest` packet to the node.
    fn send_ping_req(&self, node: &PackedNode, request_queue: &mut RequestQueue)
        -> impl Future<Item = (), Error = TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> + Send {
        let payload = PingRequestPayload {
            id: request_queue.new_ping_id(node.pk),
        };
        let ping_req = Packet::PingRequest(PingRequest::new(
            &self.precomputed_keys.get(node.pk),
            &self.pk,
            &payload
        ));
        self.send_to(node.saddr, ping_req)
    }

    /// Send `NodesRequest` packet to the node.
    fn send_nodes_req(&self, node: &PackedNode, request_queue: &mut RequestQueue, search_pk: PublicKey)
        -> impl Future<Item = (), Error = TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> + Send {
        // Check if packet is going to be sent to ourselves.
        if self.pk == node.pk {
            trace!("Attempt to send NodesRequest to ourselves.");
            return Either::A(future::ok(()))
        }

        let payload = NodesRequestPayload {
            pk: search_pk,
            id: request_queue.new_ping_id(node.pk),
        };
        let nodes_req = Packet::NodesRequest(NodesRequest::new(
            &self.precomputed_keys.get(node.pk),
            &self.pk,
            &payload
        ));
        Either::B(self.send_to(node.saddr, nodes_req))
    }

    /// Send `NatPingRequest` packet to all friends and try to punch holes.
    fn send_nat_ping_req(&self, request_queue: &mut RequestQueue, friends: &mut HashMap<PublicKey, DhtFriend>)
        -> impl Future<Item = (), Error = TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> + Send {
        let futures = friends.values_mut()
            .filter(|friend| !friend.is_addr_known())
            .map(|friend| {
                let addrs = friend.get_returned_addrs();
                (friend, addrs)
            })
            // Send NatPingRequest and try to punch holes only if we have enough
            // close nodes connected to a friend
            .filter(|(_, addrs)| addrs.len() >= FRIEND_CLOSE_NODES_COUNT as usize / 2)
            .map(|(friend, addrs)| {
                let punch_future = self.punch_holes(request_queue, friend, &addrs);

                if friend.hole_punch.last_send_ping_time.map_or(true, |time| clock_elapsed(time) >= Duration::from_secs(PUNCH_INTERVAL)) {
                    friend.hole_punch.last_send_ping_time = Some(clock_now());
                    let payload = DhtRequestPayload::NatPingRequest(NatPingRequest {
                        id: friend.hole_punch.ping_id,
                    });
                    let nat_ping_req_packet = DhtRequest::new(
                        &self.precomputed_keys.get(friend.pk),
                        &friend.pk,
                        &self.pk,
                        &payload
                    );
                    let nat_ping_future = self.send_nat_ping_req_inner(friend, nat_ping_req_packet);

                    Either::A(punch_future.join(nat_ping_future).map(|_| ()))
                } else {
                    Either::B(punch_future)
                }
            })
            .collect::<Vec<_>>();

        join_all(futures).map(|_| ())
    }

    /// Try to punch holes to specified friend.
    fn punch_holes(&self, request_queue: &mut RequestQueue, friend: &mut DhtFriend, returned_addrs: &[SocketAddr])
        -> impl Future<Item = (), Error = TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> + Send {
        let punch_addrs = friend.hole_punch.next_punch_addrs(returned_addrs);

        let packets = punch_addrs.into_iter().map(|addr| {
            let payload = PingRequestPayload {
                id: request_queue.new_ping_id(friend.pk),
            };
            let packet = Packet::PingRequest(PingRequest::new(
                &self.precomputed_keys.get(friend.pk),
                &self.pk,
                &payload
            ));

            (packet, addr)
        }).collect::<Vec<_>>();

        send_all_to_bounded(&self.tx, stream::iter_ok(packets), Duration::from_secs(DHT_SEND_TIMEOUT))
    }

    /// Send `NatPingRequest` packet to all close nodes of friend in the hope
    /// that they will redirect it to this friend.
    fn send_nat_ping_req_inner(&self, friend: &DhtFriend, nat_ping_req_packet: DhtRequest)
        -> impl Future<Item = (), Error = TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> + Send {
        let packet = Packet::DhtRequest(nat_ping_req_packet);
        let futures = friend.close_nodes.nodes
            .iter()
            .flat_map(|node| node.to_packed_node().into_iter())
            .map(|node| self.send_to(node.saddr, packet.clone()))
            .collect::<Vec<_>>();

        join_all(futures).map(|_| ())
    }

    /// Function to handle incoming packets and send responses if necessary.
    pub fn handle_packet(&self, packet: Packet, addr: SocketAddr) -> impl Future<Item = (), Error = HandlePacketError> + Send {
        match packet {
            Packet::PingRequest(packet) => Box::new(self.handle_ping_req(&packet, addr)) as Box<dyn Future<Item=_, Error=_> + Send>,
            Packet::PingResponse(packet) => Box::new(self.handle_ping_resp(&packet, addr)),
            Packet::NodesRequest(packet) => Box::new(self.handle_nodes_req(&packet, addr)),
            Packet::NodesResponse(packet) => Box::new(self.handle_nodes_resp(&packet, addr)),
            Packet::CookieRequest(packet) => Box::new(self.handle_cookie_request(&packet, addr)),
            Packet::CookieResponse(packet) => Box::new(self.handle_cookie_response(&packet, addr)),
            Packet::CryptoHandshake(packet) => Box::new(self.handle_crypto_handshake(&packet, addr)),
            Packet::DhtRequest(packet) => Box::new(self.handle_dht_req(packet, addr)),
            Packet::LanDiscovery(packet) => Box::new(self.handle_lan_discovery(&packet, addr)),
            Packet::OnionRequest0(packet) => Box::new(self.handle_onion_request_0(&packet, addr)),
            Packet::OnionRequest1(packet) => Box::new(self.handle_onion_request_1(&packet, addr)),
            Packet::OnionRequest2(packet) => Box::new(self.handle_onion_request_2(&packet, addr)),
            Packet::OnionAnnounceRequest(packet) => Box::new(self.handle_onion_announce_request(packet, addr)),
            Packet::OnionDataRequest(packet) => Box::new(self.handle_onion_data_request(packet)),
            Packet::OnionResponse3(packet) => Box::new(self.handle_onion_response_3(packet)),
            Packet::OnionResponse2(packet) => Box::new(self.handle_onion_response_2(packet)),
            Packet::OnionResponse1(packet) => Box::new(self.handle_onion_response_1(packet)),
            Packet::BootstrapInfo(packet) => Box::new(self.handle_bootstrap_info(&packet, addr)
                .map_err(|e| HandlePacketError::from(e))),
            // This packet should be handled in client only
            Packet::CryptoData(_packet) => Box::new(future::err(
                HandlePacketError::from(HandlePacketErrorKind::NotHandled)
            )),
            // This packet should be handled in client only
            Packet::OnionDataResponse(_packet) => Box::new(future::err(
                HandlePacketError::from(HandlePacketErrorKind::NotHandled)
            )),
            // This packet should be handled in client only
            Packet::OnionAnnounceResponse(_packet) => Box::new(future::err(
                HandlePacketError::from(HandlePacketErrorKind::NotHandled)
            )),
        }
    }

    /// Send UDP packet to specified address.
    fn send_to(&self, addr: SocketAddr, packet: Packet)
        -> impl Future<Item = (), Error = TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> + Send {
        send_to_bounded(&self.tx, (packet, addr), Duration::from_secs(DHT_SEND_TIMEOUT))
    }

    /// Handle received `PingRequest` packet and response with `PingResponse`
    /// packet. If node that sent this packet is not present in close nodes list
    /// and can be added there then it will be added to ping list.
    fn handle_ping_req(&self, packet: &PingRequest, addr: SocketAddr)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let precomputed_key = self.precomputed_keys.get(packet.pk);
        let payload = match packet.get_payload(&precomputed_key) {
            Err(e) => return Either::A(future::err(HandlePacketError::from(e))),
            Ok(payload) => payload,
        };

        let resp_payload = PingResponsePayload {
            id: payload.id,
        };
        let ping_resp = Packet::PingResponse(PingResponse::new(
            &precomputed_key,
            &self.pk,
            &resp_payload
        ));

        Either::B(self.ping_add(&PackedNode::new(addr, &packet.pk))
            .join(self.send_to(addr, ping_resp))
            .map(|_| ())
            .map_err(|e| HandlePacketError::from(e))
        )
    }

    /// Add node to close list after we received a response from it. If it's a
    /// friend then send it's IP address to appropriate sink.
    fn try_add_to_close(&self, close_nodes: &mut Ktree, friends: &mut HashMap<PublicKey, DhtFriend>, node: PackedNode) -> impl Future<Item = (), Error = HandlePacketError> {
        close_nodes.try_add(node);
        for friend in friends.values_mut() {
            friend.try_add_to_close(node);
        }
        if let Some(ref friend_saddr_sink) = self.friend_saddr_sink {
            if friends.contains_key(&node.pk) {
                Either::A(send_to(friend_saddr_sink, node)
                    .map_err(|e| e.context(HandlePacketErrorKind::FriendSaddr).into()))
            } else {
                Either::B(future::ok(()))
            }
        } else {
            Either::B(future::ok(()))
        }
    }

    /// Handle received `PingResponse` packet and if it's correct add the node
    /// that sent this packet to close nodes lists.
    fn handle_ping_resp(&self, packet: &PingResponse, addr: SocketAddr) -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let precomputed_key = self.precomputed_keys.get(packet.pk);
        let payload = match packet.get_payload(&precomputed_key) {
            Err(e) => return Either::A(future::err(HandlePacketError::from(e))),
            Ok(payload) => payload,
        };

        if payload.id == 0u64 {
            return Either::A(future::err(
                HandlePacketError::from(HandlePacketErrorKind::ZeroPingId)
            ))
        }

        let mut request_queue = self.request_queue.write();

        if request_queue.check_ping_id(packet.pk, payload.id) {
            let mut close_nodes = self.close_nodes.write();
            let mut friends = self.friends.write();

            Either::B(self.try_add_to_close(&mut close_nodes, &mut friends, PackedNode::new(addr, &packet.pk)))
        } else {
            Either::A(future::err(
                HandlePacketError::from(HandlePacketErrorKind::PingIdMismatch)
            ))
        }
    }

    /// Handle received `NodesRequest` packet and respond with `NodesResponse`
    /// packet. If node that sent this packet is not present in close nodes list
    /// and can be added there then it will be added to ping list.
    fn handle_nodes_req(&self, packet: &NodesRequest, addr: SocketAddr)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let precomputed_key = self.precomputed_keys.get(packet.pk);
        let payload = match packet.get_payload(&precomputed_key) {
            Err(e) => return Either::A(future::err(HandlePacketError::from(e))),
            Ok(payload) => payload,
        };

        let close_nodes = self.get_closest(&payload.pk, IsGlobal::is_global(&addr.ip()));

        let resp_payload = NodesResponsePayload {
            nodes: close_nodes.into(),
            id: payload.id,
        };
        let nodes_resp = Packet::NodesResponse(NodesResponse::new(
            &precomputed_key,
            &self.pk,
            &resp_payload
        ));

        Either::B(self.ping_add(&PackedNode::new(addr, &packet.pk))
            .join(self.send_to(addr, nodes_resp))
            .map(|_| ())
            .map_err(|e| HandlePacketError::from(e))
        )
    }

    /// Handle received `NodesResponse` packet and if it's correct add the node
    /// that sent this packet to close nodes lists. Nodes from response will be
    /// added to bootstrap nodes list to send `NodesRequest` packet to them
    /// later.
    fn handle_nodes_resp(&self, packet: &NodesResponse, addr: SocketAddr)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let precomputed_key = self.precomputed_keys.get(packet.pk);
        let payload = match packet.get_payload(&precomputed_key) {
            Err(e) => return Either::A(future::err(HandlePacketError::from(e))),
            Ok(payload) => payload,
        };

        let mut request_queue = self.request_queue.write();

        if request_queue.check_ping_id(packet.pk, payload.id) {
            trace!("Received nodes with NodesResponse from {}: {:?}", addr, payload.nodes);

            let mut close_nodes = self.close_nodes.write();
            let mut friends = self.friends.write();
            let mut nodes_to_bootstrap = self.nodes_to_bootstrap.write();

            let future = self.try_add_to_close(&mut close_nodes, &mut friends, PackedNode::new(addr, &packet.pk));

            // Process nodes from NodesResponse
            for &node in &payload.nodes {
                if !self.is_ipv6_enabled && node.saddr.is_ipv6() {
                    continue;
                }

                if close_nodes.can_add(&node) {
                    nodes_to_bootstrap.try_add(&self.pk, node, /* evict */ true);
                }

                for friend in friends.values_mut() {
                    if friend.can_add_to_close(&node) {
                        friend.nodes_to_bootstrap.try_add(&friend.pk, node, /* evict */ true);
                    }
                }

                self.update_returned_addr(&node, &packet.pk, &mut close_nodes, &mut friends);
            }

            Either::B(future)
        } else {
            // Some old version toxcore responds with wrong ping_id.
            // So we do not treat this as our own error.
            trace!("NodesResponse.ping_id does not match");
            Either::A(future::ok(()))
        }
    }

    /// Update returned socket address and time of receiving packet
    fn update_returned_addr(&self, node: &PackedNode, packet_pk: &PublicKey, close_nodes: &mut Ktree, friends: &mut HashMap<PublicKey, DhtFriend>) {
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

    /// Handle received `CookieRequest` packet and pass it to `net_crypto`
    /// module.
    fn handle_cookie_request(&self, packet: &CookieRequest, addr: SocketAddr)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        if let Some(ref net_crypto) = self.net_crypto {
            Either::A(net_crypto.handle_udp_cookie_request(packet, addr)
                .map_err(|e| HandlePacketError::from(e)))
        } else {
            Either::B( future::err(
                HandlePacketError::from(HandlePacketErrorKind::NetCrypto)
            ))
        }
    }

    /// Handle received `CookieResponse` packet and pass it to `net_crypto`
    /// module.
    fn handle_cookie_response(&self, packet: &CookieResponse, addr: SocketAddr)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        if let Some(ref net_crypto) = self.net_crypto {
            Either::A(net_crypto.handle_udp_cookie_response(packet, addr)
                .map_err(|e| HandlePacketError::from(e)))
        } else {
            Either::B( future::err(
                HandlePacketError::from(HandlePacketErrorKind::NetCrypto)
            ))
        }
    }

    /// Handle received `CryptoHandshake` packet and pass it to `net_crypto`
    /// module.
    fn handle_crypto_handshake(&self, packet: &CryptoHandshake, addr: SocketAddr)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        if let Some(ref net_crypto) = self.net_crypto {
            Either::A(net_crypto.handle_udp_crypto_handshake(packet, addr)
                .map_err(|e| HandlePacketError::from(e)))
        } else {
            Either::B( future::err(
                HandlePacketError::from(HandlePacketErrorKind::NetCrypto)
            ))
        }
    }

    /// Handle received `DhtRequest` packet, redirect it if it's sent for
    /// someone else or parse it and handle the payload if it's sent for us.
    fn handle_dht_req(&self, packet: DhtRequest, addr: SocketAddr)
        -> impl Future<Item = (), Error = HandlePacketError> + Send { // TODO: split to functions
        if packet.rpk == self.pk { // the target peer is me
            Either::A(self.handle_dht_req_for_us(&packet, addr))
        } else {
            Either::B(self.handle_dht_req_for_others(packet))
        }
    }

    /// Parse received `DhtRequest` packet and handle the payload.
    fn handle_dht_req_for_us(&self, packet: &DhtRequest, addr: SocketAddr)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let precomputed_key = self.precomputed_keys.get(packet.spk);
        let payload = packet.get_payload(&precomputed_key);
        let payload = match payload {
            Err(e) => return Box::new(future::err(HandlePacketError::from(e))) as Box<dyn Future<Item = _, Error = _> + Send>,
            Ok(payload) => payload,
        };

        match payload {
            DhtRequestPayload::NatPingRequest(nat_payload) => {
                debug!("Received nat ping request");
                Box::new(self.handle_nat_ping_req(nat_payload, &packet.spk, addr)) as Box<dyn Future<Item = _, Error = _> + Send>
            },
            DhtRequestPayload::NatPingResponse(nat_payload) => {
                debug!("Received nat ping response");
                Box::new(self.handle_nat_ping_resp(nat_payload, &packet.spk))
            },
            DhtRequestPayload::DhtPkAnnounce(_dht_pk_payload) => {
                debug!("Received DHT PublicKey Announce");
                // TODO: handle this packet in onion client
                Box::new( future::ok(()) )
            },
            DhtRequestPayload::HardeningRequest(_dht_pk_payload) => {
                debug!("Received Hardening request");
                // TODO: implement handler
                Box::new( future::ok(()) )
            },
            DhtRequestPayload::HardeningResponse(_dht_pk_payload) => {
                debug!("Received Hardening response");
                // TODO: implement handler
                Box::new( future::ok(()) )
            },
        }
    }

    /// Redirect received `DhtRequest` packet.
    fn handle_dht_req_for_others(&self, packet: DhtRequest)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let close_nodes = self.close_nodes.read();
        if let Some(node) = close_nodes.get_node(&packet.rpk).and_then(|node| node.to_packed_node()) {
            let packet = Packet::DhtRequest(packet);
            Either::A(self.send_to(node.saddr, packet)
                .map_err(|e| HandlePacketError::from(e)))
        } else {
            Either::B(future::ok(()))
        }
    }

    /// Handle received `NatPingRequest` packet and respond with
    /// `NatPingResponse` packet.
    fn handle_nat_ping_req(&self, payload: NatPingRequest, spk: &PublicKey, addr: SocketAddr)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let mut friends = self.friends.write();

        let friend = match friends.get_mut(spk) {
            None => return Either::A( future::err(
                HandlePacketError::from(HandlePacketErrorKind::NoFriend))),
            Some(friend) => friend,
        };

        friend.hole_punch.last_recv_ping_time = clock_now();

        let resp_payload = DhtRequestPayload::NatPingResponse(NatPingResponse {
            id: payload.id,
        });
        let nat_ping_resp = Packet::DhtRequest(DhtRequest::new(
            &self.precomputed_keys.get(*spk),
            spk,
            &self.pk,
            &resp_payload
        ));
        Either::B(self.send_to(addr, nat_ping_resp)
            .map_err(|e| HandlePacketError::from(e)))
    }

    /// Handle received `NatPingResponse` packet and enable hole punching if
    /// it's correct.
    fn handle_nat_ping_resp(&self, payload: NatPingResponse, spk: &PublicKey)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        if payload.id == 0 {
            return future::err(
                HandlePacketError::from(HandlePacketErrorKind::ZeroPingId
            ))
        }

        let mut friends = self.friends.write();

        let friend = match friends.get_mut(spk) {
            None => return future::err(
                HandlePacketError::from(HandlePacketErrorKind::NoFriend
                )),
            Some(friend) => friend,
        };

        if friend.hole_punch.ping_id == payload.id {
            // Refresh ping id for the next NatPingRequest
            friend.hole_punch.ping_id = gen_ping_id();
            // We send NatPingRequest packet only if we are not directly
            // connected to a friend but we have several nodes that connected
            // to him. If we received NatPingResponse that means that this
            // friend is likely behind NAT so we should try to punch holes.
            friend.hole_punch.is_punching_done = false;
            future::ok(())
        } else {
            future::err(
                HandlePacketError::from(HandlePacketErrorKind::PingIdMismatch)
            )
        }
    }

    /// Handle received `LanDiscovery` packet and response with `NodesRequest`
    /// packet.
    fn handle_lan_discovery(&self, packet: &LanDiscovery, addr: SocketAddr)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        // LanDiscovery is optional
        if !self.lan_discovery_enabled {
            return Either::A(future::ok(()));
        }

        // if Lan Discovery packet has my PK, then it is sent by myself.
        if packet.pk == self.pk {
            return Either::A(future::ok(()));
        }

        Either::B(self.send_nodes_req(&PackedNode::new(addr, &packet.pk), &mut self.request_queue.write(), self.pk)
            .map_err(|e| HandlePacketError::from(e)))
    }

    /// Handle received `OnionRequest0` packet and send `OnionRequest1` packet
    /// to the next peer.
    fn handle_onion_request_0(&self, packet: &OnionRequest0, addr: SocketAddr)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        let shared_secret = self.precomputed_keys.get(packet.temporary_pk);
        let payload = packet.get_payload(&shared_secret);
        let payload = match payload {
            Err(e) => return Either::A(future::err(HandlePacketError::from(e))),
            Ok(payload) => payload,
        };

        let onion_return = OnionReturn::new(
            &onion_symmetric_key,
            &IpPort::from_udp_saddr(addr),
            None // no previous onion return
        );
        let next_packet = Packet::OnionRequest1(OnionRequest1 {
            nonce: packet.nonce,
            temporary_pk: payload.temporary_pk,
            payload: payload.inner,
            onion_return
        });
        Either::B(self.send_to(payload.ip_port.to_saddr(), next_packet)
            .map_err(|e| HandlePacketError::from(e)))
    }

    /// Handle received `OnionRequest1` packet and send `OnionRequest2` packet
    /// to the next peer.
    fn handle_onion_request_1(&self, packet: &OnionRequest1, addr: SocketAddr)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        let shared_secret = self.precomputed_keys.get(packet.temporary_pk);
        let payload = packet.get_payload(&shared_secret);
        let payload = match payload {
            Err(e) => return Either::A(future::err(HandlePacketError::from(e))),
            Ok(payload) => payload,
        };

        let onion_return = OnionReturn::new(
            &onion_symmetric_key,
            &IpPort::from_udp_saddr(addr),
            Some(&packet.onion_return)
        );
        let next_packet = Packet::OnionRequest2(OnionRequest2 {
            nonce: packet.nonce,
            temporary_pk: payload.temporary_pk,
            payload: payload.inner,
            onion_return
        });
        Either::B(self.send_to(payload.ip_port.to_saddr(), next_packet)
            .map_err(|e| HandlePacketError::from(e)))
    }

    /// Handle received `OnionRequest2` packet and send `OnionAnnounceRequest`
    /// or `OnionDataRequest` packet to the next peer.
    fn handle_onion_request_2(&self, packet: &OnionRequest2, addr: SocketAddr)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        let shared_secret = self.precomputed_keys.get(packet.temporary_pk);
        let payload = packet.get_payload(&shared_secret);
        let payload = match payload {
            Err(e) => return Either::A(future::err(HandlePacketError::from(e))),
            Ok(payload) => payload,
        };

        let onion_return = OnionReturn::new(
            &onion_symmetric_key,
            &IpPort::from_udp_saddr(addr),
            Some(&packet.onion_return)
        );
        let next_packet = match payload.inner {
            InnerOnionRequest::InnerOnionAnnounceRequest(inner) => Packet::OnionAnnounceRequest(OnionAnnounceRequest {
                inner,
                onion_return
            }),
            InnerOnionRequest::InnerOnionDataRequest(inner) => Packet::OnionDataRequest(OnionDataRequest {
                inner,
                onion_return
            }),
        };
        Either::B(self.send_to(payload.ip_port.to_saddr(), next_packet)
            .map_err(|e| HandlePacketError::from(e))
        )
    }

    /// Handle received `OnionAnnounceRequest` packet and response with
    /// `OnionAnnounceResponse` packet if the request succeed.
    ///
    /// The response packet will contain up to 4 closest to `search_pk` nodes
    /// from ktree. They are used to search closest to long term `PublicKey`
    /// nodes to announce.
    fn handle_onion_announce_request(&self, packet: OnionAnnounceRequest, addr: SocketAddr)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let mut onion_announce = self.onion_announce.write();

        let shared_secret = self.precomputed_keys.get(packet.inner.pk);
        let payload = match packet.inner.get_payload(&shared_secret) {
            Err(e) => return Either::A(future::err(HandlePacketError::from(e))),
            Ok(payload) => payload,
        };

        let (announce_status, ping_id_or_pk) = onion_announce.handle_onion_announce_request(
            &payload,
            packet.inner.pk,
            packet.onion_return.clone(),
            addr
        );

        let close_nodes = self.get_closest(&payload.search_pk, IsGlobal::is_global(&addr.ip()));

        let response_payload = OnionAnnounceResponsePayload {
            announce_status,
            ping_id_or_pk,
            nodes: close_nodes.into()
        };
        let response = OnionAnnounceResponse::new(&shared_secret, payload.sendback_data, &response_payload);

        Either::B(self.send_to(addr, Packet::OnionResponse3(OnionResponse3 {
            onion_return: packet.onion_return,
            payload: InnerOnionResponse::OnionAnnounceResponse(response)
        }))
            .map_err(|e| HandlePacketError::from(e))
        )
    }

    /// Handle received `OnionDataRequest` packet and send `OnionResponse3`
    /// packet with inner `OnionDataResponse` to destination node through its
    /// onion path.
    fn handle_onion_data_request(&self, packet: OnionDataRequest)
        -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let onion_announce = self.onion_announce.read();
        match onion_announce.handle_data_request(packet) {
            Ok((response, addr)) => Either::A(self.send_to(addr, Packet::OnionResponse3(response))
                .map_err(|e| HandlePacketError::from(e))
            ),
            Err(e) => Either::B(future::err(HandlePacketError::from(e)))
        }
    }

    /// Handle received `OnionResponse3` packet and send `OnionResponse2` packet
    /// to the next peer which address is stored in encrypted onion return.
    fn handle_onion_response_3(&self, packet: OnionResponse3) -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        let payload = packet.onion_return.get_payload(&onion_symmetric_key);
        let payload = match payload {
            Err(e) => {
                // Onion symmetric key is changed every 2 hours to enforce onion
                // paths expiration. It means that we can get packets with old
                // onion key. So we do not consider this as error.
                trace!("Failed to decrypt onion_return from OnionResponse3: {}", e);
                return Either::A(future::ok(()));
            },
            Ok(payload) => payload,
        };

        if let (ip_port, Some(next_onion_return)) = payload {
            let next_packet = Packet::OnionResponse2(OnionResponse2 {
                onion_return: next_onion_return,
                payload: packet.payload
            });
            Either::B(self.send_to(ip_port.to_saddr(), next_packet)
                .map_err(|e| HandlePacketError::from(e))
            )
        } else {
            Either::A(future::err(HandlePacketError::from(OnionResponseError::from(OnionResponseErrorKind::Next))))
        }
    }

    /// Handle received `OnionResponse2` packet and send `OnionResponse1` packet
    /// to the next peer which address is stored in encrypted onion return.
    fn handle_onion_response_2(&self, packet: OnionResponse2) -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        let payload = packet.onion_return.get_payload(&onion_symmetric_key);
        let payload = match payload {
            Err(e) => {
                // Onion symmetric key is changed every 2 hours to enforce onion
                // paths expiration. It means that we can get packets with old
                // onion key. So we do not consider this as error.
                trace!("Failed to decrypt onion_return from OnionResponse2: {}", e);
                return Either::A(future::ok(()));
            },
            Ok(payload) => payload,
        };

        if let (ip_port, Some(next_onion_return)) = payload {
            let next_packet = Packet::OnionResponse1(OnionResponse1 {
                onion_return: next_onion_return,
                payload: packet.payload
            });
            Either::B(self.send_to(ip_port.to_saddr(), next_packet)
                .map_err(|e| HandlePacketError::from(e))
            )
        } else {
            Either::A(future::err(HandlePacketError::from(OnionResponseError::from(OnionResponseErrorKind::Next))))
        }
    }

    /// Handle received `OnionResponse1` packet and send `OnionAnnounceResponse`
    /// or `OnionDataResponse` packet to the next peer which address is stored
    /// in encrypted onion return.
    fn handle_onion_response_1(&self, packet: OnionResponse1) -> impl Future<Item = (), Error = HandlePacketError> + Send {
        let onion_symmetric_key = self.onion_symmetric_key.read();
        let payload = packet.onion_return.get_payload(&onion_symmetric_key);
        let payload = match payload {
            Err(e) => {
                // Onion symmetric key is changed every 2 hours to enforce onion
                // paths expiration. It means that we can get packets with old
                // onion key. So we do not consider this as error.
                trace!("Failed to decrypt onion_return from OnionResponse1: {}", e);
                return Box::new(future::ok(())) as Box<dyn Future<Item = _, Error = _> + Send>;
            },
            Ok(payload) => payload,
        };

        if let (ip_port, None) = payload {
            match ip_port.protocol {
                ProtocolType::UDP => {
                    let next_packet = match packet.payload {
                        InnerOnionResponse::OnionAnnounceResponse(inner) => Packet::OnionAnnounceResponse(inner),
                        InnerOnionResponse::OnionDataResponse(inner) => Packet::OnionDataResponse(inner),
                    };
                    Box::new(self.send_to(ip_port.to_saddr(), next_packet)
                        .map_err(|e| HandlePacketError::from(e))
                    ) as Box<dyn Future<Item = _, Error = _> + Send>
                },
                ProtocolType::TCP => {
                    if let Some(ref tcp_onion_sink) = self.tcp_onion_sink {
                        Box::new(tcp_onion_sink.clone() // clone sink for 1 send only
                            .send((packet.payload, ip_port.to_saddr()))
                            .map(|_sink| ()) // ignore sink because it was cloned
                            .map_err(|e| HandlePacketError::from(OnionResponseError::from(e)))
                        )
                    } else {
                        Box::new( future::err(
                            HandlePacketError::from(OnionResponseError::from(OnionResponseErrorKind::Redirect))
                        ))
                    }
                },
            }
        } else {
            Box::new(future::err(HandlePacketError::from(OnionResponseError::from(OnionResponseErrorKind::Next))))
        }
    }

    /// Refresh onion symmetric key to enforce onion paths expiration.
    fn refresh_onion_key(&self) {
        *self.onion_symmetric_key.write() = secretbox::gen_key();
    }

    /// Handle `OnionRequest` from TCP relay and send `OnionRequest1` packet
    /// to the next node in the onion path.
    pub fn handle_tcp_onion_request(&self, packet: OnionRequest, addr: SocketAddr)
        -> impl Future<Item = (), Error = TimeoutError<mpsc::SendError<(Packet, SocketAddr)>>> + Send {
        let onion_symmetric_key = self.onion_symmetric_key.read();

        let onion_return = OnionReturn::new(
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
        self.send_to(packet.ip_port.to_saddr(), next_packet)
    }

    /// Handle `BootstrapInfo` packet and response with `BootstrapInfo` packet.
    fn handle_bootstrap_info(&self, packet: &BootstrapInfo, addr: SocketAddr) -> impl Future<Item = (), Error = HandleBootstrapInfoError> + Send {
        if packet.motd.len() != BOOSTRAP_CLIENT_MAX_MOTD_LENGTH {
            return Either::A( future::err(
                HandleBootstrapInfoError::from(HandleBootstrapInfoErrorKind::Length)
            ))
        }

        if let Some(ref bootstrap_info) = self.bootstrap_info {
            let mut motd = (bootstrap_info.motd_cb)(&self);
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
            Either::B(self.send_to(addr, packet)
                .map_err(|e| HandleBootstrapInfoError::from(e))
            )
        } else {
            // Do not respond to BootstrapInfo packets if bootstrap_info not defined
            Either::A(future::ok(()))
        }
    }

    /// Set toxcore version and message of the day callback.
    pub fn set_bootstrap_info(&mut self, version: u32, motd_cb: Box<Fn(&Server) -> Vec<u8> + Send + Sync>) {
        self.bootstrap_info = Some(ServerBootstrapInfo {
            version,
            motd_cb: motd_cb.into(),
        });
    }

    /// Set TCP sink for onion packets.
    pub fn set_tcp_onion_sink(&mut self, tcp_onion_sink: TcpOnionTx) {
        self.tcp_onion_sink = Some(tcp_onion_sink)
    }

    /// Set `net_crypto` module.
    pub fn set_net_crypto(&mut self, net_crypto: NetCrypto) {
        self.net_crypto = Some(net_crypto);
    }

    /// Set sink to send friend's `SocketAddr` when it gets known.
    pub fn set_friend_saddr_sink(&mut self, friend_saddr_sink: mpsc::UnboundedSender<PackedNode>) {
        self.friend_saddr_sink = Some(friend_saddr_sink);
    }

    /// Get `PrecomputedKey`s cache.
    pub fn get_precomputed_keys(&self) -> PrecomputedCache {
        self.precomputed_keys.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::Future;
    use std::net::SocketAddr;

    use tokio_executor;
    use tokio_timer::clock::*;

    use crate::toxcore::time::ConstNow;

    const ONION_RETURN_1_PAYLOAD_SIZE: usize = ONION_RETURN_1_SIZE - secretbox::NONCEBYTES;
    const ONION_RETURN_2_PAYLOAD_SIZE: usize = ONION_RETURN_2_SIZE - secretbox::NONCEBYTES;
    const ONION_RETURN_3_PAYLOAD_SIZE: usize = ONION_RETURN_3_SIZE - secretbox::NONCEBYTES;

    fn create_node() -> (Server, PrecomputedKey, PublicKey, SecretKey,
            mpsc::Receiver<(Packet, SocketAddr)>, SocketAddr) {
        crypto_init().unwrap();

        let (pk, sk) = gen_keypair();
        let (tx, rx) = mpsc::channel(32);
        let alice = Server::new(tx, pk, sk);
        let (bob_pk, bob_sk) = gen_keypair();
        let precomp = precompute(&alice.pk, &bob_sk);

        let addr: SocketAddr = "127.0.0.1:12346".parse().unwrap();
        (alice, precomp, bob_pk, bob_sk, rx, addr)
    }

    #[test]
    fn server_is_clonable() {
        crypto_init().unwrap();
        let (pk, sk) = gen_keypair();
        let (tx, _rx) = mpsc::channel(1);
        let server = Server::new(tx, pk, sk);

        let _ = server.clone();
    }

    #[test]
    fn add_friend() {
        let (alice, _precomp, bob_pk, _bob_sk, _rx, _addr) = create_node();

        let packed_node = PackedNode::new("211.192.153.67:33445".parse().unwrap(), &bob_pk);
        assert!(alice.close_nodes.write().try_add(packed_node));

        let friend_pk = gen_keypair().0;
        alice.add_friend(friend_pk);

        let inserted_friend = &alice.friends.read()[&friend_pk];
        assert!(inserted_friend.nodes_to_bootstrap.contains(&friend_pk, &bob_pk));
    }

    #[test]
    fn readd_friend() {
        let (alice, _precomp, bob_pk, _bob_sk, _rx, _addr) = create_node();

        let friend_pk = gen_keypair().0;
        alice.add_friend(friend_pk);

        let packed_node = PackedNode::new("127.0.0.1:33445".parse().unwrap(), &bob_pk);
        assert!(alice.friends.write().get_mut(&friend_pk).unwrap().try_add_to_close(packed_node));

        // adding the same friend shouldn't replace existing `DhtFriend`
        alice.add_friend(friend_pk);

        // so it should still contain the added node
        assert!(alice.friends.read()[&friend_pk].close_nodes.contains(&friend_pk, &bob_pk));
    }

    // handle_bootstrap_info
    #[test]
    fn handle_bootstrap_info() {
        let (mut alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let version = 42;
        let motd = b"motd".to_vec();
        let motd_c = motd.clone();

        alice.set_bootstrap_info(version, Box::new(move |_| motd_c.clone()));

        let packet = Packet::BootstrapInfo(BootstrapInfo {
            version: 00,
            motd: vec![0; BOOSTRAP_CLIENT_MAX_MOTD_LENGTH],
        });

        alice.handle_packet(packet, addr).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let bootstrap_info = unpack!(packet, Packet::BootstrapInfo);

        assert_eq!(bootstrap_info.version, version);
        assert_eq!(bootstrap_info.motd, motd);
    }

    #[test]
    fn handle_bootstrap_info_wrong_length() {
        let (mut alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let version = 42;
        let motd = b"motd".to_vec();

        alice.set_bootstrap_info(version, Box::new(move |_| motd.clone()));

        let packet = Packet::BootstrapInfo(BootstrapInfo {
            version: 00,
            motd: Vec::new(),
        });

        let res = alice.handle_packet(packet, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::BootstrapInfo);

        // Necessary to drop tx so that rx.collect() can be finished
        drop(alice);

        assert!(rx.collect().wait().unwrap().is_empty());
    }

    // handle_ping_req
    #[test]
    fn handle_ping_req() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();

        let req_payload = PingRequestPayload { id: 42 };
        let ping_req = Packet::PingRequest(PingRequest::new(&precomp, &bob_pk, &req_payload));

        alice.handle_packet(ping_req, addr).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let ping_resp = unpack!(packet, Packet::PingResponse);
        let precomputed_key = precompute(&ping_resp.pk, &bob_sk);
        let ping_resp_payload = ping_resp.get_payload(&precomputed_key).unwrap();

        assert_eq!(ping_resp_payload.id, req_payload.id);

        assert!(alice.nodes_to_ping.read().contains(&alice.pk, &bob_pk));
    }

    #[test]
    fn handle_ping_req_from_friend_with_unknown_addr() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();

        alice.add_friend(bob_pk);

        let req_payload = PingRequestPayload { id: 42 };
        let ping_req = Packet::PingRequest(PingRequest::new(&precomp, &bob_pk, &req_payload));

        alice.handle_packet(ping_req, addr).wait().unwrap();

        let mut request_queue = alice.request_queue.write();

        rx.take(2).map(|(packet, addr_to_send)| {
            assert_eq!(addr_to_send, addr);

            if let Packet::PingResponse(ping_resp) = packet {
                let precomputed_key = precompute(&ping_resp.pk, &bob_sk);
                let ping_resp_payload = ping_resp.get_payload(&precomputed_key).unwrap();
                assert_eq!(ping_resp_payload.id, req_payload.id);
            } else {
                let ping_req = unpack!(packet, Packet::PingRequest);
                let precomputed_key = precompute(&ping_req.pk, &bob_sk);
                let ping_req_payload = ping_req.get_payload(&precomputed_key).unwrap();
                assert!(request_queue.check_ping_id(bob_pk, ping_req_payload.id));
            }
        }).collect().wait().unwrap();

        // In case of friend with yet unknown address we should send ping
        // request immediately instead of adding node to nodes_to_ping list
        assert!(!alice.nodes_to_ping.read().contains(&alice.pk, &bob_pk));
    }

    #[test]
    fn handle_ping_req_invalid_payload() {
        let (alice, precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        // can't be decrypted payload since packet contains wrong key
        let req_payload = PingRequestPayload { id: 42 };
        let ping_req = Packet::PingRequest(PingRequest::new(&precomp, &alice.pk, &req_payload));

        let res = alice.handle_packet(ping_req, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::GetPayload);
    }

    // handle_ping_resp
    #[test]
    fn handle_ping_resp() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        alice.add_friend(bob_pk);

        let packed_node = PackedNode::new(addr, &bob_pk);
        assert!(alice.close_nodes.write().try_add(packed_node));

        let ping_id = alice.request_queue.write().new_ping_id(bob_pk);

        let resp_payload = PingResponsePayload { id: ping_id };
        let ping_resp = Packet::PingResponse(PingResponse::new(&precomp, &bob_pk, &resp_payload));

        let time = Instant::now() + Duration::from_secs(1);

        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(time));

        with_default(&clock, &mut enter, |_| {
            alice.handle_packet(ping_resp, addr).wait().unwrap();
        });

        let friends = alice.friends.read();
        let friend = friends.values().next().unwrap();

        // All nodes from PingResponse should be added to bootstrap nodes list
        // of each friend
        assert!(friend.close_nodes.contains(&bob_pk, &bob_pk));

        let close_nodes = alice.close_nodes.read();
        let node = close_nodes.get_node(&bob_pk).unwrap();

        // Node that sent PingResponse should be added to close nodes list and
        // have updated last_resp_time
        assert_eq!(node.assoc4.last_resp_time.unwrap(), time);
    }

    #[test]
    fn handle_ping_resp_not_a_friend() {
        let (mut alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let (friend_saddr_tx, friend_saddr_rx) = mpsc::unbounded();
        alice.set_friend_saddr_sink(friend_saddr_tx);

        let packed_node = PackedNode::new(addr, &bob_pk);
        assert!(alice.close_nodes.write().try_add(packed_node));

        let ping_id = alice.request_queue.write().new_ping_id(bob_pk);

        let resp_payload = PingResponsePayload { id: ping_id };
        let ping_resp = Packet::PingResponse(PingResponse::new(&precomp, &bob_pk, &resp_payload));

        alice.handle_packet(ping_resp, addr).wait().unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(alice);

        assert!(friend_saddr_rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn handle_ping_resp_friend_saddr() {
        let (mut alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let (friend_saddr_tx, friend_saddr_rx) = mpsc::unbounded();
        alice.set_friend_saddr_sink(friend_saddr_tx);

        alice.add_friend(bob_pk);

        let packed_node = PackedNode::new(addr, &bob_pk);
        assert!(alice.close_nodes.write().try_add(packed_node));

        let ping_id = alice.request_queue.write().new_ping_id(bob_pk);

        let resp_payload = PingResponsePayload { id: ping_id };
        let ping_resp = Packet::PingResponse(PingResponse::new(&precomp, &bob_pk, &resp_payload));

        alice.handle_packet(ping_resp, addr).wait().unwrap();

        let (received_node, _friend_saddr_rx) = friend_saddr_rx.into_future().wait().unwrap();
        let received_node = received_node.unwrap();

        assert_eq!(received_node.pk, bob_pk);
        assert_eq!(received_node.saddr, addr);
    }

    #[test]
    fn handle_ping_resp_invalid_payload() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let packed_node = PackedNode::new(addr, &bob_pk);
        assert!(alice.close_nodes.write().try_add(packed_node));

        let ping_id = alice.request_queue.write().new_ping_id(bob_pk);

        // can't be decrypted payload since packet contains wrong key
        let payload = PingResponsePayload { id: ping_id };
        let ping_resp = Packet::PingResponse(PingResponse::new(&precomp, &alice.pk, &payload));

        let res = alice.handle_packet(ping_resp, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::GetPayload);
    }

    #[test]
    fn handle_ping_resp_ping_id_is_0() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let packed_node = PackedNode::new(addr, &bob_pk);
        assert!(alice.close_nodes.write().try_add(packed_node));

        let payload = PingResponsePayload { id: 0 };
        let ping_resp = Packet::PingResponse(PingResponse::new(&precomp, &bob_pk, &payload));

        let res = alice.handle_packet(ping_resp, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::ZeroPingId);
    }

    #[test]
    fn handle_ping_resp_invalid_ping_id() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let packed_node = PackedNode::new(addr, &bob_pk);
        assert!(alice.close_nodes.write().try_add(packed_node));

        let ping_id = alice.request_queue.write().new_ping_id(bob_pk);

        let payload = PingResponsePayload { id: ping_id + 1 };
        let ping_resp = Packet::PingResponse(PingResponse::new(&precomp, &bob_pk, &payload));

        let res = alice.handle_packet(ping_resp, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::PingIdMismatch);
    }

    // handle_nodes_req
    #[test]
    fn handle_nodes_req() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();

        let packed_node = PackedNode::new("127.0.0.1:12345".parse().unwrap(), &bob_pk);

        assert!(alice.close_nodes.write().try_add(packed_node));

        let req_payload = NodesRequestPayload { pk: bob_pk, id: 42 };
        let nodes_req = Packet::NodesRequest(NodesRequest::new(&precomp, &bob_pk, &req_payload));

        alice.handle_packet(nodes_req, addr).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let nodes_resp = unpack!(packet, Packet::NodesResponse);
        let precomputed_key = precompute(&nodes_resp.pk, &bob_sk);
        let nodes_resp_payload = nodes_resp.get_payload(&precomputed_key).unwrap();

        assert_eq!(nodes_resp_payload.id, req_payload.id);
        assert_eq!(nodes_resp_payload.nodes, vec!(packed_node));

        assert!(alice.nodes_to_ping.read().contains(&alice.pk, &bob_pk));
    }

    #[test]
    fn handle_nodes_req_should_return_nodes_from_friends() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();

        alice.add_friend(bob_pk);

        let packed_node = PackedNode::new("127.0.0.1:12345".parse().unwrap(), &bob_pk);
        assert!(alice.friends.write().get_mut(&bob_pk).unwrap().try_add_to_close(packed_node));

        let req_payload = NodesRequestPayload { pk: bob_pk, id: 42 };
        let nodes_req = Packet::NodesRequest(NodesRequest::new(&precomp, &bob_pk, &req_payload));

        alice.handle_packet(nodes_req, addr).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let nodes_resp = unpack!(packet, Packet::NodesResponse);
        let precomputed_key = precompute(&nodes_resp.pk, &bob_sk);
        let nodes_resp_payload = nodes_resp.get_payload(&precomputed_key).unwrap();

        assert_eq!(nodes_resp_payload.id, req_payload.id);
        assert_eq!(nodes_resp_payload.nodes, vec!(packed_node));

        assert!(alice.nodes_to_ping.read().contains(&alice.pk, &bob_pk));
    }

    #[test]
    fn handle_nodes_req_should_not_return_bad_nodes() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();

        let packed_node = PackedNode::new("127.0.0.1:12345".parse().unwrap(), &bob_pk);

        assert!(alice.close_nodes.write().try_add(packed_node));

        let req_payload = NodesRequestPayload { pk: bob_pk, id: 42 };
        let nodes_req = Packet::NodesRequest(NodesRequest::new(&precomp, &bob_pk, &req_payload));

        let time = Instant::now() + Duration::from_secs(BAD_NODE_TIMEOUT + 1);

        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(time));

        with_default(&clock, &mut enter, |_| {
            alice.handle_packet(nodes_req, addr).wait().unwrap();
        });

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let nodes_resp = unpack!(packet, Packet::NodesResponse);
        let precomputed_key = precompute(&nodes_resp.pk, &bob_sk);
        let nodes_resp_payload = nodes_resp.get_payload(&precomputed_key).unwrap();

        assert_eq!(nodes_resp_payload.id, req_payload.id);
        assert!(nodes_resp_payload.nodes.is_empty());

        assert!(alice.nodes_to_ping.read().contains(&alice.pk, &bob_pk));
    }

    #[test]
    fn handle_nodes_req_should_not_return_lan_nodes_when_address_is_global() {
        let (alice, precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let addr = "8.10.8.10:12345".parse().unwrap();

        let packed_node = PackedNode::new("192.168.42.42:12345".parse().unwrap(), &bob_pk);

        assert!(alice.close_nodes.write().try_add(packed_node));

        let req_payload = NodesRequestPayload { pk: bob_pk, id: 42 };
        let nodes_req = Packet::NodesRequest(NodesRequest::new(&precomp, &bob_pk, &req_payload));

        alice.handle_packet(nodes_req, addr).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let nodes_resp = unpack!(packet, Packet::NodesResponse);
        let precomputed_key = precompute(&nodes_resp.pk, &bob_sk);
        let nodes_resp_payload = nodes_resp.get_payload(&precomputed_key).unwrap();

        assert_eq!(nodes_resp_payload.id, req_payload.id);
        assert!(nodes_resp_payload.nodes.is_empty());

        assert!(alice.nodes_to_ping.read().contains(&alice.pk, &bob_pk));
    }

    #[test]
    fn handle_nodes_req_invalid_payload() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        // can't be decrypted payload since packet contains wrong key
        let req_payload = NodesRequestPayload { pk: bob_pk, id: 42 };
        let nodes_req = Packet::NodesRequest(NodesRequest::new(&precomp, &alice.pk, &req_payload));

        let res = alice.handle_packet(nodes_req, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::GetPayload);
    }

    // handle_nodes_resp
    #[test]
    fn handle_nodes_resp() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        alice.add_friend(bob_pk);

        let node = PackedNode::new("127.0.0.1:12345".parse().unwrap(), &gen_keypair().0);

        let ping_id = alice.request_queue.write().new_ping_id(bob_pk);

        let resp_payload = NodesResponsePayload { nodes: vec![node], id: ping_id };
        let nodes_resp = Packet::NodesResponse(NodesResponse::new(&precomp, &bob_pk, &resp_payload));

        let time = Instant::now() + Duration::from_secs(1);

        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(time));

        with_default(&clock, &mut enter, |_| {
            alice.handle_packet(nodes_resp, addr).wait().unwrap();
        });

        // All nodes from NodesResponse should be added to bootstrap nodes list
        assert!(alice.nodes_to_bootstrap.read().contains(&alice.pk, &node.pk));

        let friends = alice.friends.read();
        let friend = friends.values().next().unwrap();

        // Node that sent NodesResponse should be added to close nodes list of
        // each friend
        assert!(friend.nodes_to_bootstrap.contains(&bob_pk, &node.pk));
        // All nodes from NodesResponse should be added to bootstrap nodes list
        // of each friend
        assert!(friend.close_nodes.contains(&bob_pk, &bob_pk));

        let close_nodes = alice.close_nodes.read();
        let node = close_nodes.get_node(&bob_pk).unwrap();

        // Node that sent NodesResponse should be added to close nodes list and
        // have updated last_resp_time
        assert_eq!(node.assoc4.last_resp_time.unwrap(), time);
    }

    #[test]
    fn handle_nodes_resp_friend_saddr() {
        let (mut alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let (friend_saddr_tx, friend_saddr_rx) = mpsc::unbounded();
        alice.set_friend_saddr_sink(friend_saddr_tx);

        alice.add_friend(bob_pk);

        let packed_node = PackedNode::new(addr, &bob_pk);
        assert!(alice.close_nodes.write().try_add(packed_node));

        let node = PackedNode::new("127.0.0.1:12345".parse().unwrap(), &gen_keypair().0);

        let ping_id = alice.request_queue.write().new_ping_id(bob_pk);

        let resp_payload = NodesResponsePayload { nodes: vec![node], id: ping_id };
        let nodes_resp = Packet::NodesResponse(NodesResponse::new(&precomp, &bob_pk, &resp_payload));

        alice.handle_packet(nodes_resp, addr).wait().unwrap();

        let (received_node, _friend_saddr_rx) = friend_saddr_rx.into_future().wait().unwrap();
        let received_node = received_node.unwrap();

        assert_eq!(received_node.pk, bob_pk);
        assert_eq!(received_node.saddr, addr);
    }

    #[test]
    fn handle_nodes_resp_invalid_payload() {
        let (alice, precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        // can't be decrypted payload since packet contains wrong key
        let resp_payload = NodesResponsePayload { nodes: vec![
            PackedNode::new("127.0.0.1:12345".parse().unwrap(), &gen_keypair().0)
        ], id: 38 };
        let nodes_resp = Packet::NodesResponse(NodesResponse::new(&precomp, &alice.pk, &resp_payload));

        let res = alice.handle_packet(nodes_resp, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::GetPayload);
    }

    #[test]
    fn handle_nodes_resp_ping_id_is_0() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let resp_payload = NodesResponsePayload { nodes: vec![
            PackedNode::new("127.0.0.1:12345".parse().unwrap(), &gen_keypair().0)
        ], id: 0 };
        let nodes_resp = Packet::NodesResponse(NodesResponse::new(&precomp, &bob_pk, &resp_payload));

        alice.handle_packet(nodes_resp, addr).wait().unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(alice);

        assert!(rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn handle_nodes_resp_invalid_ping_id() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let ping_id = alice.request_queue.write().new_ping_id(bob_pk);

        let resp_payload = NodesResponsePayload {
            nodes: vec![
                PackedNode::new("127.0.0.1:12345".parse().unwrap(), &gen_keypair().0)
            ],
            id: ping_id + 1
        };
        let nodes_resp = Packet::NodesResponse(NodesResponse::new(&precomp, &bob_pk, &resp_payload));

        alice.handle_packet(nodes_resp, addr).wait().unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(alice);

        assert!(rx.collect().wait().unwrap().is_empty());
    }

    // handle_cookie_request
    #[test]
    fn handle_cookie_request() {
        crypto_init().unwrap();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (dht_pk, dht_sk) = gen_keypair();
        let mut alice = Server::new(udp_tx.clone(), dht_pk, dht_sk.clone());

        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let (lossless_tx, _lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let (real_pk, real_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();
        let (bob_real_pk, _bob_real_sk) = gen_keypair();
        let precomp = precompute(&alice.pk, &bob_sk);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            dht_pk_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys: alice.get_precomputed_keys(),
        });

        alice.set_net_crypto(net_crypto);

        let addr = "127.0.0.1:12346".parse().unwrap();

        let cookie_request_id = 12345;
        let cookie_request_payload = CookieRequestPayload {
            pk: bob_real_pk,
            id: cookie_request_id,
        };
        let cookie_request = Packet::CookieRequest(CookieRequest::new(&precomp, &bob_pk, &cookie_request_payload));

        alice.handle_packet(cookie_request, addr).wait().unwrap();

        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let packet = unpack!(packet, Packet::CookieResponse);
        let payload = packet.get_payload(&precomp).unwrap();

        assert_eq!(payload.id, cookie_request_id);
    }

    #[test]
    fn handle_cookie_request_uninitialized() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let (bob_real_pk, _bob_real_sk) = gen_keypair();

        let cookie_request_payload = CookieRequestPayload {
            pk: bob_real_pk,
            id: 12345,
        };
        let cookie_request = Packet::CookieRequest(CookieRequest::new(&precomp, &bob_pk, &cookie_request_payload));

        let res = alice.handle_packet(cookie_request, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::NetCrypto);
    }

    // handle_cookie_response
    #[test]
    fn handle_cookie_response_uninitialized() {
        let (alice, precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let cookie_response_payload = CookieResponsePayload {
            cookie: cookie.clone(),
            id: 12345
        };
        let cookie_response = Packet::CookieResponse(CookieResponse::new(&precomp, &cookie_response_payload));

        let res = alice.handle_packet(cookie_response, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::NetCrypto);
    }

    // handle_crypto_handshake
    #[test]
    fn handle_crypto_handshake_uninitialized() {
        let (alice, precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![43; 88]
        };
        let crypto_handshake_payload = CryptoHandshakePayload {
            base_nonce: gen_nonce(),
            session_pk: gen_keypair().0,
            cookie_hash: cookie.hash(),
            cookie: cookie.clone()
        };
        let crypto_handshake = Packet::CryptoHandshake(CryptoHandshake::new(&precomp, &crypto_handshake_payload, cookie));

        let res = alice.handle_packet(crypto_handshake, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::NetCrypto);
    }

    // handle_dht_req
    #[test]
    fn handle_dht_req_for_unknown_node() {
        let (alice, _precomp, bob_pk, bob_sk, rx, addr) = create_node();

        let (charlie_pk, _charlie_sk) = gen_keypair();
        let precomp = precompute(&charlie_pk, &bob_sk);

        // if receiver' pk != node's pk just returns ok()
        let nat_req = NatPingRequest { id: 42 };
        let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
        let dht_req = Packet::DhtRequest(DhtRequest::new(&precomp, &charlie_pk, &bob_pk, &nat_payload));

        alice.handle_packet(dht_req, addr).wait().unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(alice);

        assert!(rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn handle_dht_req_for_known_node() {
        let (alice, _precomp, bob_pk, bob_sk, rx, addr) = create_node();

        let charlie_addr = "1.2.3.4:12345".parse().unwrap();
        let (charlie_pk, _charlie_sk) = gen_keypair();
        let precomp = precompute(&charlie_pk, &bob_sk);

        // if receiver' pk != node's pk and receiver's pk exists in close_nodes, returns ok()
        let pn = PackedNode::new(charlie_addr, &charlie_pk);
        assert!(alice.close_nodes.write().try_add(pn));

        let nat_req = NatPingRequest { id: 42 };
        let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
        let dht_req = Packet::DhtRequest(DhtRequest::new(&precomp, &charlie_pk, &bob_pk, &nat_payload));

        alice.handle_packet(dht_req.clone(), addr).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, charlie_addr);
        assert_eq!(packet, dht_req);
    }

    #[test]
    fn handle_dht_req_invalid_payload() {
        let (alice, _precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let dht_req = Packet::DhtRequest(DhtRequest {
            rpk: alice.pk,
            spk: bob_pk,
            nonce: gen_nonce(),
            payload: vec![42; 123]
        });

        let res = alice.handle_packet(dht_req, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::GetPayload);
    }

    // handle_nat_ping_request
    #[test]
    fn handle_nat_ping_req() {
        let (alice, precomp, bob_pk, bob_sk, rx, addr) = create_node();

        alice.add_friend(bob_pk);

        let nat_req = NatPingRequest { id: 42 };
        let nat_payload = DhtRequestPayload::NatPingRequest(nat_req);
        let dht_req = Packet::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &bob_pk, &nat_payload));

        let mut enter = tokio_executor::enter().unwrap();
        let time = Instant::now() + Duration::from_secs(1);
        let clock = Clock::new_with_now(ConstNow(time));

        with_default(&clock, &mut enter, |_| {
            alice.handle_packet(dht_req, addr).wait().unwrap();
        });

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let dht_req = unpack!(packet, Packet::DhtRequest);
        let precomputed_key = precompute(&dht_req.spk, &bob_sk);
        let dht_payload = dht_req.get_payload(&precomputed_key).unwrap();
        let nat_ping_resp_payload = unpack!(dht_payload, DhtRequestPayload::NatPingResponse);

        assert_eq!(nat_ping_resp_payload.id, nat_req.id);

        let friends = alice.friends.read();

        assert_eq!(friends[&bob_pk].hole_punch.last_recv_ping_time, time);
    }

    // handle_nat_ping_response
    #[test]
    fn handle_nat_ping_resp() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        alice.add_friend(bob_pk);
        let ping_id = alice.friends.read()[&bob_pk].hole_punch.ping_id;

        let nat_res = NatPingResponse { id: ping_id };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = Packet::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &bob_pk, &nat_payload));

        alice.handle_packet(dht_req, addr).wait().unwrap();

        let friends = alice.friends.read();

        assert!(!friends[&bob_pk].hole_punch.is_punching_done);
    }

    #[test]
    fn handle_nat_ping_resp_ping_id_is_0() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        // error case, ping_id = 0
        let nat_res = NatPingResponse { id: 0 };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = Packet::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &bob_pk, &nat_payload));

        let res = alice.handle_packet(dht_req, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::ZeroPingId);
    }

    #[test]
    fn handle_nat_ping_resp_invalid_ping_id() {
        let (alice, precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        // error case, incorrect ping_id
        let ping_id = alice.request_queue.write().new_ping_id(bob_pk);

        let nat_res = NatPingResponse { id: ping_id + 1 };
        let nat_payload = DhtRequestPayload::NatPingResponse(nat_res);
        let dht_req = Packet::DhtRequest(DhtRequest::new(&precomp, &alice.pk, &bob_pk, &nat_payload));

        let res = alice.handle_packet(dht_req, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::NoFriend);
    }

    // handle_onion_request_0
    #[test]
    fn handle_onion_request_0() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let temporary_pk = gen_keypair().0;
        let inner = vec![42; 123];
        let ip_port = IpPort {
            protocol: ProtocolType::UDP,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let payload = OnionRequest0Payload {
            ip_port: ip_port.clone(),
            temporary_pk,
            inner: inner.clone()
        };
        let packet = Packet::OnionRequest0(OnionRequest0::new(&precomp, &bob_pk, &payload));

        alice.handle_packet(packet, addr).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionRequest1);

        assert_eq!(next_packet.temporary_pk, temporary_pk);
        assert_eq!(next_packet.payload, inner);

        let onion_symmetric_key = alice.onion_symmetric_key.read();
        let onion_return_payload = next_packet.onion_return.get_payload(&onion_symmetric_key).unwrap();

        assert_eq!(onion_return_payload.0, IpPort::from_udp_saddr(addr));
    }

    #[test]
    fn handle_onion_request_0_invalid_payload() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let packet = Packet::OnionRequest0(OnionRequest0 {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123] // not encrypted with dht pk
        });

        let res = alice.handle_packet(packet, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::GetPayload);
    }

    // handle_onion_request_1
    #[test]
    fn handle_onion_request_1() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let temporary_pk = gen_keypair().0;
        let inner = vec![42; 123];
        let ip_port = IpPort {
            protocol: ProtocolType::UDP,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let payload = OnionRequest1Payload {
            ip_port: ip_port.clone(),
            temporary_pk,
            inner: inner.clone()
        };
        let onion_return = OnionReturn {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
        };
        let packet = Packet::OnionRequest1(OnionRequest1::new(&precomp, &bob_pk, &payload, onion_return));

        alice.handle_packet(packet, addr).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionRequest2);

        assert_eq!(next_packet.temporary_pk, temporary_pk);
        assert_eq!(next_packet.payload, inner);

        let onion_symmetric_key = alice.onion_symmetric_key.read();
        let onion_return_payload = next_packet.onion_return.get_payload(&onion_symmetric_key).unwrap();

        assert_eq!(onion_return_payload.0, IpPort::from_udp_saddr(addr));
    }

    #[test]
    fn handle_onion_request_1_invalid_payload() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let packet = Packet::OnionRequest1(OnionRequest1 {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123], // not encrypted with dht pk
            onion_return: OnionReturn {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
            }
        });

        let res = alice.handle_packet(packet, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::GetPayload);
    }

    // handle_onion_request_2
    #[test]
    fn handle_onion_request_2_with_onion_announce_request() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let inner = InnerOnionAnnounceRequest {
            nonce: gen_nonce(),
            pk: gen_keypair().0,
            payload: vec![42; 123]
        };
        let ip_port = IpPort {
            protocol: ProtocolType::UDP,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let payload = OnionRequest2Payload {
            ip_port: ip_port.clone(),
            inner: InnerOnionRequest::InnerOnionAnnounceRequest(inner.clone())
        };
        let onion_return = OnionReturn {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
        };
        let packet = Packet::OnionRequest2(OnionRequest2::new(&precomp, &bob_pk, &payload, onion_return));

        alice.handle_packet(packet, addr).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionAnnounceRequest);

        assert_eq!(next_packet.inner, inner);

        let onion_symmetric_key = alice.onion_symmetric_key.read();
        let onion_return_payload = next_packet.onion_return.get_payload(&onion_symmetric_key).unwrap();

        assert_eq!(onion_return_payload.0, IpPort::from_udp_saddr(addr));
    }

    #[test]
    fn handle_onion_request_2_with_onion_data_request() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let inner = InnerOnionDataRequest {
            destination_pk: gen_keypair().0,
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123]
        };
        let ip_port = IpPort {
            protocol: ProtocolType::UDP,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let payload = OnionRequest2Payload {
            ip_port: ip_port.clone(),
            inner: InnerOnionRequest::InnerOnionDataRequest(inner.clone())
        };
        let onion_return = OnionReturn {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
        };
        let packet = Packet::OnionRequest2(OnionRequest2::new(&precomp, &bob_pk, &payload, onion_return));

        alice.handle_packet(packet, addr).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionDataRequest);

        assert_eq!(next_packet.inner, inner);

        let onion_symmetric_key = alice.onion_symmetric_key.read();
        let onion_return_payload = next_packet.onion_return.get_payload(&onion_symmetric_key).unwrap();

        assert_eq!(onion_return_payload.0, IpPort::from_udp_saddr(addr));
    }

    #[test]
    fn handle_onion_request_2_invalid_payload() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let packet = Packet::OnionRequest2(OnionRequest2 {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123], // not encrypted with dht pk
            onion_return: OnionReturn {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
            }
        });

        let res = alice.handle_packet(packet, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::GetPayload);
    }

    // handle_onion_announce_request
    #[test]
    fn handle_onion_announce_request() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let sendback_data = 42;
        let payload = OnionAnnounceRequestPayload {
            ping_id: initial_ping_id(),
            search_pk: gen_keypair().0,
            data_pk: gen_keypair().0,
            sendback_data
        };
        let inner = InnerOnionAnnounceRequest::new(&precomp, &bob_pk, &payload);
        let onion_return = OnionReturn {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
        };
        let packet = Packet::OnionAnnounceRequest(OnionAnnounceRequest {
            inner,
            onion_return: onion_return.clone()
        });

        alice.handle_packet(packet, addr).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let response = unpack!(packet, Packet::OnionResponse3);

        assert_eq!(response.onion_return, onion_return);

        let response = unpack!(response.payload, InnerOnionResponse::OnionAnnounceResponse);

        assert_eq!(response.sendback_data, sendback_data);

        let payload = response.get_payload(&precomp).unwrap();

        assert_eq!(payload.announce_status, AnnounceStatus::Failed);
    }

    #[test]
    fn handle_onion_announce_request_invalid_payload() {
        let (alice, _precomp, bob_pk, _bob_sk, _rx, addr) = create_node();

        let inner = InnerOnionAnnounceRequest {
            nonce: gen_nonce(),
            pk: bob_pk,
            payload: vec![42; 123]
        };
        let onion_return = OnionReturn {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
        };
        let packet = Packet::OnionAnnounceRequest(OnionAnnounceRequest {
            inner,
            onion_return: onion_return.clone()
        });

        let res = alice.handle_packet(packet, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::GetPayload);
    }

    // handle_onion_data_request
    #[test]
    fn handle_onion_data_request() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        // get ping id

        let payload = OnionAnnounceRequestPayload {
            ping_id: initial_ping_id(),
            search_pk: gen_keypair().0,
            data_pk: gen_keypair().0,
            sendback_data: 42
        };
        let inner = InnerOnionAnnounceRequest::new(&precomp, &bob_pk, &payload);
        let onion_return = OnionReturn {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
        };
        let packet = Packet::OnionAnnounceRequest(OnionAnnounceRequest {
            inner,
            onion_return: onion_return.clone()
        });

        alice.handle_packet(packet, addr).wait().unwrap();

        let (received, rx) = rx.into_future().wait().unwrap();
        let (packet, _addr_to_send) = received.unwrap();
        let response = unpack!(packet, Packet::OnionResponse3);
        let response = unpack!(response.payload, InnerOnionResponse::OnionAnnounceResponse);
        let payload = response.get_payload(&precomp).unwrap();
        let ping_id = payload.ping_id_or_pk;

        // announce node

        let payload = OnionAnnounceRequestPayload {
            ping_id,
            search_pk: gen_keypair().0,
            data_pk: gen_keypair().0,
            sendback_data: 42
        };
        let inner = InnerOnionAnnounceRequest::new(&precomp, &bob_pk, &payload);
        let packet = Packet::OnionAnnounceRequest(OnionAnnounceRequest {
            inner,
            onion_return: onion_return.clone()
        });

        alice.handle_packet(packet, addr).wait().unwrap();

        // send onion data request

        let nonce = gen_nonce();
        let temporary_pk = gen_keypair().0;
        let payload = vec![42; 123];
        let inner = InnerOnionDataRequest {
            destination_pk: bob_pk,
            nonce,
            temporary_pk,
            payload: payload.clone()
        };
        let packet = Packet::OnionDataRequest(OnionDataRequest {
            inner,
            onion_return: onion_return.clone()
        });

        alice.handle_packet(packet, addr).wait().unwrap();

        let (received, _rx) = rx.skip(1).into_future().wait().unwrap();
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
    #[test]
    fn handle_onion_response_3() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read();

        let ip_port = IpPort {
            protocol: ProtocolType::UDP,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let next_onion_return = OnionReturn {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
        };
        let onion_return = OnionReturn::new(&onion_symmetric_key, &ip_port, Some(&next_onion_return));
        let payload = InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42; 123]
        });
        let packet = Packet::OnionResponse3(OnionResponse3 {
            onion_return,
            payload: payload.clone()
        });

        alice.handle_packet(packet, addr).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionResponse2);

        assert_eq!(next_packet.payload, payload);
        assert_eq!(next_packet.onion_return, next_onion_return);
    }

    #[test]
    fn handle_onion_response_3_invalid_onion_return() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let onion_return = OnionReturn {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE] // not encrypted with onion_symmetric_key
        };
        let payload = InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42; 123]
        });
        let packet = Packet::OnionResponse3(OnionResponse3 {
            onion_return,
            payload
        });

        alice.handle_packet(packet, addr).wait().unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(alice);

        assert!(rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn handle_onion_response_3_invalid_next_onion_return() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read();

        let ip_port = IpPort {
            protocol: ProtocolType::UDP,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let onion_return = OnionReturn::new(&onion_symmetric_key, &ip_port, None);
        let inner = OnionDataResponse {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123]
        };
        let packet = Packet::OnionResponse3(OnionResponse3 {
            onion_return,
            payload: InnerOnionResponse::OnionDataResponse(inner.clone())
        });

        let res = alice.handle_packet(packet, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::OnionResponse);
    }

    // handle_onion_response_2
    #[test]
    fn handle_onion_response_2() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read();

        let ip_port = IpPort {
            protocol: ProtocolType::UDP,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let next_onion_return = OnionReturn {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
        };
        let onion_return = OnionReturn::new(&onion_symmetric_key, &ip_port, Some(&next_onion_return));
        let payload = InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42; 123]
        });
        let packet = Packet::OnionResponse2(OnionResponse2 {
            onion_return,
            payload: payload.clone()
        });

        alice.handle_packet(packet, addr).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionResponse1);

        assert_eq!(next_packet.payload, payload);
        assert_eq!(next_packet.onion_return, next_onion_return);
    }

    #[test]
    fn handle_onion_response_2_invalid_onion_return() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let onion_return = OnionReturn {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE] // not encrypted with onion_symmetric_key
        };
        let payload = InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42; 123]
        });
        let packet = Packet::OnionResponse2(OnionResponse2 {
            onion_return,
            payload
        });

        alice.handle_packet(packet, addr).wait().unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(alice);

        assert!(rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn handle_onion_response_2_invalid_next_onion_return() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read();

        let ip_port = IpPort {
            protocol: ProtocolType::UDP,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let onion_return = OnionReturn::new(&onion_symmetric_key, &ip_port, None);
        let inner = OnionDataResponse {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123]
        };
        let packet = Packet::OnionResponse2(OnionResponse2 {
            onion_return,
            payload: InnerOnionResponse::OnionDataResponse(inner.clone())
        });

        let res = alice.handle_packet(packet, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::OnionResponse);
    }

    // handle_onion_response_1
    #[test]
    fn handle_onion_response_1_with_onion_announce_response() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read();

        let ip_port = IpPort {
            protocol: ProtocolType::UDP,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let onion_return = OnionReturn::new(&onion_symmetric_key, &ip_port, None);
        let inner = OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42; 123]
        };
        let packet = Packet::OnionResponse1(OnionResponse1 {
            onion_return,
            payload: InnerOnionResponse::OnionAnnounceResponse(inner.clone())
        });

        alice.handle_packet(packet, addr).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionAnnounceResponse);

        assert_eq!(next_packet, inner);
    }

    #[test]
    fn server_handle_onion_response_1_with_onion_data_response_test() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read();

        let ip_port = IpPort {
            protocol: ProtocolType::UDP,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let onion_return = OnionReturn::new(&onion_symmetric_key, &ip_port, None);
        let inner = OnionDataResponse {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123]
        };
        let packet = Packet::OnionResponse1(OnionResponse1 {
            onion_return,
            payload: InnerOnionResponse::OnionDataResponse(inner.clone())
        });

        alice.handle_packet(packet, addr).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionDataResponse);

        assert_eq!(next_packet, inner);
    }

    #[test]
    fn handle_onion_response_1_redirect_to_tcp() {
        let (mut alice, _precomp, _bob_pk, _bob_sk, _rx, _addr) = create_node();
        let (tcp_onion_tx, tcp_onion_rx) = mpsc::channel(1);
        alice.set_tcp_onion_sink(tcp_onion_tx);

        let addr: SocketAddr = "127.0.0.1:12346".parse().unwrap();

        let onion_symmetric_key = alice.onion_symmetric_key.read();

        let ip_port = IpPort {
            protocol: ProtocolType::TCP,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let onion_return = OnionReturn::new(&onion_symmetric_key, &ip_port, None);
        let inner = InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42; 123]
        });
        let packet = Packet::OnionResponse1(OnionResponse1 {
            onion_return,
            payload: inner.clone()
        });

        alice.handle_packet(packet, addr).wait().unwrap();

        let (received, _tcp_onion_rx) = tcp_onion_rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());
        assert_eq!(packet, inner);
    }

    #[test]
    fn handle_onion_response_1_can_not_redirect_to_tcp() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read();

        let ip_port = IpPort {
            protocol: ProtocolType::TCP,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let onion_return = OnionReturn::new(&onion_symmetric_key, &ip_port, None);
        let inner = OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42; 123]
        };
        let packet = Packet::OnionResponse1(OnionResponse1 {
            onion_return,
            payload: InnerOnionResponse::OnionAnnounceResponse(inner.clone())
        });

        let res = alice.handle_packet(packet, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::OnionResponse);
    }

    #[test]
    fn handle_onion_response_1_invalid_onion_return() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let onion_return = OnionReturn {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE] // not encrypted with onion_symmetric_key
        };
        let payload = InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42; 123]
        });
        let packet = Packet::OnionResponse1(OnionResponse1 {
            onion_return,
            payload
        });

        alice.handle_packet(packet, addr).wait().unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(alice);

        assert!(rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn handle_onion_response_1_invalid_next_onion_return() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let onion_symmetric_key = alice.onion_symmetric_key.read();

        let ip_port = IpPort {
            protocol: ProtocolType::UDP,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let next_onion_return = OnionReturn {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
        };
        let onion_return = OnionReturn::new(&onion_symmetric_key, &ip_port, Some(&next_onion_return));
        let inner = OnionDataResponse {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123]
        };
        let packet = Packet::OnionResponse1(OnionResponse1 {
            onion_return,
            payload: InnerOnionResponse::OnionDataResponse(inner.clone())
        });

        let res = alice.handle_packet(packet, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::OnionResponse);
    }

    // send_nat_ping_req()
    #[test]
    fn send_nat_ping_req() {
        let (alice, _precomp, _bob_pk, _bob_sk, mut rx, _addr) = create_node();

        let (friend_pk, friend_sk) = gen_keypair();

        let nodes = [
            PackedNode::new("127.1.1.1:12345".parse().unwrap(), &gen_keypair().0),
            PackedNode::new("127.1.1.2:12345".parse().unwrap(), &gen_keypair().0),
            PackedNode::new("127.1.1.3:12345".parse().unwrap(), &gen_keypair().0),
            PackedNode::new("127.1.1.4:12345".parse().unwrap(), &gen_keypair().0),
        ];
        alice.add_friend(friend_pk);

        let mut friends = alice.friends.write();
        for &node in &nodes {
            let friend = friends.get_mut(&friend_pk).unwrap();
            friend.try_add_to_close(node);
            let dht_node = friend.close_nodes.get_node_mut(&friend_pk, &node.pk).unwrap();
            dht_node.update_returned_addr(node.saddr);
        }
        drop(friends);

        alice.dht_main_loop().wait().unwrap();

        loop {
            let (received, rx1) = rx.into_future().wait().unwrap();
            let (packet, _addr_to_send) = received.unwrap();

            if let Packet::DhtRequest(nat_ping_req) = packet {
                let precomputed_key = precompute(&nat_ping_req.spk, &friend_sk);
                let nat_ping_req_payload = nat_ping_req.get_payload(&precomputed_key).unwrap();
                let nat_ping_req_payload = unpack!(nat_ping_req_payload, DhtRequestPayload::NatPingRequest);

                assert_eq!(alice.friends.read()[&friend_pk].hole_punch.ping_id, nat_ping_req_payload.id);
                break;
            }
            rx = rx1;
        }
    }

    // handle_lan_discovery
    #[test]
    fn handle_lan_discovery() {
        let (alice, _precomp, bob_pk, bob_sk, rx, addr) = create_node();

        let lan = Packet::LanDiscovery(LanDiscovery { pk: bob_pk });

        alice.handle_packet(lan, addr).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let nodes_req = unpack!(packet, Packet::NodesRequest);
        let precomputed_key = precompute(&nodes_req.pk, &bob_sk);
        let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();

        assert_eq!(nodes_req_payload.pk, alice.pk);
    }

    #[test]
    fn handle_lan_discovery_for_ourselves() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let lan = Packet::LanDiscovery(LanDiscovery { pk: alice.pk });

        alice.handle_packet(lan, addr).wait().unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(alice);

        assert!(rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn handle_lan_discovery_when_disabled() {
        let (mut alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        alice.enable_lan_discovery(false);
        assert_eq!(alice.lan_discovery_enabled, false);

        let lan = Packet::LanDiscovery(LanDiscovery { pk: alice.pk });

        alice.handle_packet(lan, addr).wait().unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(alice);

        assert!(rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn refresh_onion_key() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, _addr) = create_node();

        let onion_symmetric_key_1 = alice.onion_symmetric_key.read().clone();

        alice.refresh_onion_key();

        let onion_symmetric_key_2 = alice.onion_symmetric_key.read().clone();

        assert_ne!(onion_symmetric_key_1, onion_symmetric_key_2)
    }

    #[test]
    fn handle_tcp_onion_request() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, addr) = create_node();

        let temporary_pk = gen_keypair().0;
        let payload = vec![42; 123];
        let ip_port = IpPort {
            protocol: ProtocolType::UDP,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let packet = OnionRequest {
            nonce: gen_nonce(),
            ip_port: ip_port.clone(),
            temporary_pk,
            payload: payload.clone()
        };

        alice.handle_tcp_onion_request(packet, addr).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, ip_port.to_saddr());

        let next_packet = unpack!(packet, Packet::OnionRequest1);

        assert_eq!(next_packet.temporary_pk, temporary_pk);
        assert_eq!(next_packet.payload, payload);

        let onion_symmetric_key = alice.onion_symmetric_key.read();
        let onion_return_payload = next_packet.onion_return.get_payload(&onion_symmetric_key).unwrap();

        assert_eq!(onion_return_payload.0, IpPort::from_tcp_saddr(addr));
    }

    #[test]
    fn ping_nodes_to_bootstrap() {
        let (alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let (node_pk, node_sk) = gen_keypair();

        let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), &node_pk);
        assert!(alice.nodes_to_bootstrap.write().try_add(&alice.pk, pn, /* evict */ true));

        let pn = PackedNode::new("127.0.0.1:33445".parse().unwrap(), &bob_pk);
        assert!(alice.nodes_to_bootstrap.write().try_add(&alice.pk, pn, /* evict */ true));

        alice.dht_main_loop().wait().unwrap();

        let mut request_queue = alice.request_queue.write();

        rx.take(2).map(|(packet, addr)| {
            let nodes_req = unpack!(packet, Packet::NodesRequest);
            if addr == "127.0.0.1:33445".parse().unwrap() {
                let precomputed_key = precompute(&nodes_req.pk, &bob_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(request_queue.check_ping_id(bob_pk, nodes_req_payload.id));
                assert_eq!(nodes_req_payload.pk, alice.pk);
            } else {
                let precomputed_key = precompute(&nodes_req.pk, &node_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(request_queue.check_ping_id(node_pk, nodes_req_payload.id));
                assert_eq!(nodes_req_payload.pk, alice.pk);
            }
        }).collect().wait().unwrap();
    }

    #[test]
    fn ping_nodes_from_nodes_to_ping_list() {
        let (alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let (node_pk, node_sk) = gen_keypair();

        let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), &node_pk);
        assert!(alice.nodes_to_ping.write().try_add(&alice.pk, pn, /* evict */ true));

        let pn = PackedNode::new("127.0.0.1:33445".parse().unwrap(), &bob_pk);
        assert!(alice.nodes_to_ping.write().try_add(&alice.pk, pn, /* evict */ true));

        alice.send_pings().wait().unwrap();

        let mut request_queue = alice.request_queue.write();

        rx.take(2).map(|(packet, addr)| {
            let nodes_req = unpack!(packet, Packet::PingRequest);
            if addr == "127.0.0.1:33445".parse().unwrap() {
                let precomputed_key = precompute(&nodes_req.pk, &bob_sk);
                let ping_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(request_queue.check_ping_id(bob_pk, ping_req_payload.id));
            } else {
                let precomputed_key = precompute(&nodes_req.pk, &node_sk);
                let ping_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(request_queue.check_ping_id(node_pk, ping_req_payload.id));
            }
        }).collect().wait().unwrap();
    }

    #[test]
    fn ping_nodes_when_nodes_to_ping_list_is_empty() {
        let (alice, _precomp, _bob_pk, _bob_sk, rx, _addr) = create_node();

        alice.send_pings().wait().unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(alice);

        assert!(rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn ping_close_nodes() {
        let (alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let (node_pk, node_sk) = gen_keypair();

        let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), &node_pk);
        assert!(alice.close_nodes.write().try_add(pn));

        let pn = PackedNode::new("127.0.0.1:33445".parse().unwrap(), &bob_pk);
        assert!(alice.close_nodes.write().try_add(pn));

        alice.dht_main_loop().wait().unwrap();

        let mut request_queue = alice.request_queue.write();

        // 3 = 2 packets sent by ping_close_nodes + 1 packet sent by send_nodes_req_random
        rx.take(3).map(|(packet, addr)| {
            let nodes_req = unpack!(packet, Packet::NodesRequest);
            if addr == "127.0.0.1:33445".parse().unwrap() {
                let precomputed_key = precompute(&nodes_req.pk, &bob_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(request_queue.check_ping_id(bob_pk, nodes_req_payload.id));
                assert_eq!(nodes_req_payload.pk, alice.pk);
            } else {
                let precomputed_key = precompute(&nodes_req.pk, &node_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(request_queue.check_ping_id(node_pk, nodes_req_payload.id));
                assert_eq!(nodes_req_payload.pk, alice.pk);
            }
        }).collect().wait().unwrap();
    }

    #[test]
    fn send_nodes_req_random_periodicity() {
        let (alice, _precomp, bob_pk, _bob_sk, mut rx, _addr) = create_node();

        {
            let mut close_nodes = alice.close_nodes.write();
            let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), &bob_pk);
            assert!(close_nodes.try_add(pn));
            let node = close_nodes.get_node_mut(&bob_pk).unwrap();
            // Set last_ping_req_time so that only random request will be sent
            node.assoc4.last_ping_req_time = Some(clock_now());
            node.assoc6.last_ping_req_time = Some(clock_now());
        }

        let now = Instant::now();
        let mut enter = tokio_executor::enter().unwrap();

        // Random request should be sent every second MAX_BOOTSTRAP_TIMES times
        // This loop will produce MAX_BOOTSTRAP_TIMES random packets
        for i in 0 .. MAX_BOOTSTRAP_TIMES {
            let clock = Clock::new_with_now(ConstNow(now + Duration::from_secs(u64::from(i))));

            with_default(&clock, &mut enter, |_| {
                alice.dht_main_loop().wait().unwrap();
            });

            let (received, rx1) = rx.into_future().wait().unwrap();
            let (packet, _) = received.unwrap();

            unpack!(packet, Packet::NodesRequest);

            rx = rx1;
        }

        // Random packet won't be sent anymore if NODES_REQ_INTERVAL is not passed
        let clock = Clock::new_with_now(ConstNow(
            now + Duration::from_secs(u64::from(MAX_BOOTSTRAP_TIMES))
        ));
        with_default(&clock, &mut enter, |_| {
            alice.dht_main_loop().wait().unwrap();
        });

        // Necessary to drop tx so that rx.collect() can be finished
        drop(alice);

        assert!(rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn ping_nodes_to_bootstrap_of_friend() {
        let (alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let (node_pk, node_sk) = gen_keypair();

        let friend_pk = gen_keypair().0;

        alice.add_friend(friend_pk);

        let mut friends = alice.friends.write();
        let friend = friends.get_mut(&friend_pk).unwrap();

        let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), &node_pk);
        assert!(friend.nodes_to_bootstrap.try_add(&alice.pk, pn, /* evict */ true));

        let pn = PackedNode::new("127.0.0.1:33445".parse().unwrap(), &bob_pk);
        assert!(friend.nodes_to_bootstrap.try_add(&alice.pk, pn, /* evict */ true));

        drop(friends);

        alice.dht_main_loop().wait().unwrap();

        let mut request_queue = alice.request_queue.write();

        rx.take(2).map(|(packet, addr)| {
            let nodes_req = unpack!(packet, Packet::NodesRequest);
            if addr == "127.0.0.1:33445".parse().unwrap() {
                let precomputed_key = precompute(&nodes_req.pk, &bob_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(request_queue.check_ping_id(bob_pk, nodes_req_payload.id));
                assert_eq!(nodes_req_payload.pk, friend_pk);
            } else {
                let precomputed_key = precompute(&nodes_req.pk, &node_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(request_queue.check_ping_id(node_pk, nodes_req_payload.id));
                assert_eq!(nodes_req_payload.pk, friend_pk);
            }
        }).collect().wait().unwrap();
    }

    #[test]
    fn ping_close_nodes_of_friend() {
        let (alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let (node_pk, node_sk) = gen_keypair();

        let friend_pk = gen_keypair().0;

        alice.add_friend(friend_pk);

        {
            let mut friends = alice.friends.write();
            let friend = friends.get_mut(&friend_pk).unwrap();

            let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), &node_pk);
            assert!(friend.try_add_to_close(pn));

            let pn = PackedNode::new("127.0.0.1:33445".parse().unwrap(), &bob_pk);
            assert!(friend.try_add_to_close(pn));
        }

        alice.dht_main_loop().wait().unwrap();

        let mut request_queue = alice.request_queue.write();

        // 3 = 2 packets sent by ping_close_nodes + 1 packet sent by send_nodes_req_random
        rx.take(3).map(|(packet, addr)| {
            let nodes_req = unpack!(packet, Packet::NodesRequest);
            if addr == "127.0.0.1:33445".parse().unwrap() {
                let precomputed_key = precompute(&nodes_req.pk, &bob_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(request_queue.check_ping_id(bob_pk, nodes_req_payload.id));
                assert_eq!(nodes_req_payload.pk, friend_pk);
            } else {
                let precomputed_key = precompute(&nodes_req.pk, &node_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(request_queue.check_ping_id(node_pk, nodes_req_payload.id));
                assert_eq!(nodes_req_payload.pk, friend_pk);
            }
        }).collect().wait().unwrap();
    }

    #[test]
    fn send_nodes_req_random_friend_periodicity() {
        let (alice, _precomp, bob_pk, _bob_sk, mut rx, _addr) = create_node();

        let friend_pk = gen_keypair().0;
        alice.add_friend(friend_pk);

        let mut friends = alice.friends.write();
        let friend = friends.get_mut(&friend_pk).unwrap();

        let pn = PackedNode::new("127.0.0.1:33445".parse().unwrap(), &bob_pk);
        assert!(friend.try_add_to_close(pn));

        // Set last_ping_req_time so that only random request will be sent
        friend.close_nodes.nodes[0].assoc4.last_ping_req_time = Some(clock_now());
        friend.close_nodes.nodes[0].assoc6.last_ping_req_time = Some(clock_now());

        drop(friends);

        let now = Instant::now();
        let mut enter = tokio_executor::enter().unwrap();

        // Random request should be sent every second MAX_BOOTSTRAP_TIMES times
        // This loop will produce MAX_BOOTSTRAP_TIMES random packets
        for i in 0 .. MAX_BOOTSTRAP_TIMES {
            let clock = Clock::new_with_now(ConstNow(now + Duration::from_secs(u64::from(i))));

            with_default(&clock, &mut enter, |_| {
                alice.friends.write().get_mut(&friend_pk).unwrap().hole_punch.last_send_ping_time = Some(clock_now());
                alice.dht_main_loop().wait().unwrap();
            });

            let (received, rx1) = rx.into_future().wait().unwrap();
            let (packet, _) = received.unwrap();

            unpack!(packet, Packet::NodesRequest);

            rx = rx1;
        }

        // Random packet won't be sent anymore if NODES_REQ_INTERVAL is not passed
        let clock = Clock::new_with_now(ConstNow(
            now + Duration::from_secs(u64::from(MAX_BOOTSTRAP_TIMES))
        ));
        with_default(&clock, &mut enter, |_| {
            alice.dht_main_loop().wait().unwrap();
        });

        // Necessary to drop tx so that rx.collect() can be finished
        drop(alice);

        assert!(rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn enable_ipv6_mode() {
        let (mut alice, _precomp, _bob_pk, _bob_sk, _rx, _addr) = create_node();

        alice.enable_ipv6_mode(true);
        assert_eq!(alice.is_ipv6_enabled, true);
    }

    #[test]
    fn send_to() {
        let (mut alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let (node_pk, node_sk) = gen_keypair();

        let pn = PackedNode::new("[FF::01]:33445".parse().unwrap(), &bob_pk);
        assert!(alice.close_nodes.write().try_add(pn));

        let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), &node_pk);
        assert!(alice.close_nodes.write().try_add(pn));

        // test with ipv6 mode
        alice.enable_ipv6_mode(true);
        alice.dht_main_loop().wait().unwrap();

        let mut request_queue = alice.request_queue.write();

        rx.take(2).map(|(packet, addr)| {
            let nodes_req = unpack!(packet, Packet::NodesRequest);
            if addr == "[FF::01]:33445".parse().unwrap() {
                let precomputed_key = precompute(&nodes_req.pk, &bob_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(request_queue.check_ping_id(bob_pk, nodes_req_payload.id));
            } else {
                let precomputed_key = precompute(&nodes_req.pk, &node_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(request_queue.check_ping_id(node_pk, nodes_req_payload.id));
            }
        }).collect().wait().unwrap();
    }

    #[test]
    fn send_bootstrap_requests() {
        let (mut alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let (node_pk, node_sk) = gen_keypair();

        let pn = PackedNode::new("[FF::01]:33445".parse().unwrap(), &bob_pk);
        alice.add_initial_bootstrap(pn);

        let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), &node_pk);
        alice.add_initial_bootstrap(pn);

        // test with ipv6 mode
        alice.enable_ipv6_mode(true);
        alice.send_bootstrap_requests().wait().unwrap();

        let mut request_queue = alice.request_queue.write();

        rx.take(2).map(|(packet, addr)| {
            let nodes_req = unpack!(packet, Packet::NodesRequest);
            if addr == "[FF::01]:33445".parse().unwrap() {
                let precomputed_key = precompute(&nodes_req.pk, &bob_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(request_queue.check_ping_id(bob_pk, nodes_req_payload.id));
            } else {
                let precomputed_key = precompute(&nodes_req.pk, &node_sk);
                let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                assert!(request_queue.check_ping_id(node_pk, nodes_req_payload.id));
            }
        }).collect().wait().unwrap();
    }

    #[test]
    fn send_bootstrap_requests_when_ktree_has_good_node() {
        let (mut alice, _precomp, bob_pk, _bob_sk, rx, _addr) = create_node();
        let (node_pk, _node_sk) = gen_keypair();

        let pn = PackedNode::new("[FF::01]:33445".parse().unwrap(), &bob_pk);
        alice.add_initial_bootstrap(pn);

        let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), &node_pk);
        assert!(alice.close_nodes.write().try_add(pn));

        // test with ipv6 mode
        alice.enable_ipv6_mode(true);
        alice.send_bootstrap_requests().wait().unwrap();

        // Necessary to drop tx so that rx.collect() can be finished
        drop(alice);

        assert!(rx.collect().wait().unwrap().is_empty());
    }

    #[test]
    fn send_bootstrap_requests_with_discarded() {
        let (mut alice, _precomp, bob_pk, bob_sk, rx, _addr) = create_node();
        let (node_pk, node_sk) = gen_keypair();

        let mut close_nodes = alice.close_nodes.write();

        let pn = PackedNode::new("[FF::01]:33445".parse().unwrap(), &bob_pk);
        assert!(close_nodes.try_add(pn));
        let pn = PackedNode::new("127.1.1.1:12345".parse().unwrap(), &node_pk);
        assert!(close_nodes.try_add(pn));

        drop(close_nodes);

        // test with ipv6 mode
        alice.enable_ipv6_mode(true);

        let time = Instant::now() + Duration::from_secs(KILL_NODE_TIMEOUT + 1);

        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(time));

        with_default(&clock, &mut enter, |_| {
            alice.send_bootstrap_requests().wait().unwrap();

            let mut request_queue = alice.request_queue.write();

            rx.take(2).map(|(packet, addr)| {
                let nodes_req = unpack!(packet, Packet::NodesRequest);
                if addr == "[FF::01]:33445".parse().unwrap() {
                    let precomputed_key = precompute(&nodes_req.pk, &bob_sk);
                    let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                    assert!(request_queue.check_ping_id(bob_pk, nodes_req_payload.id));
                } else {
                    let precomputed_key = precompute(&nodes_req.pk, &node_sk);
                    let nodes_req_payload = nodes_req.get_payload(&precomputed_key).unwrap();
                    assert!(request_queue.check_ping_id(node_pk, nodes_req_payload.id));
                }
            }).collect().wait().unwrap();
        });
    }

    #[test]
    fn handle_crypto_data() {
        let (alice, precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let data_payload = CryptoDataPayload {
            buffer_start: 1,
            packet_number: 0,
            data: vec![1, 2, 3, 4]
        };

        let data = Packet::CryptoData(CryptoData::new(&precomp, gen_nonce(), &data_payload));

        let res = alice.handle_packet(data, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::NotHandled);
    }

    #[test]
    fn handle_onion_data_response() {
        let (alice, _precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let data = Packet::OnionDataResponse(OnionDataResponse {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123]
        });

        let res = alice.handle_packet(data, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::NotHandled);
    }

    #[test]
    fn handle_onion_announce_response() {
        let (alice, precomp, _bob_pk, _bob_sk, _rx, addr) = create_node();

        let payload = OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Found,
            ping_id_or_pk: sha256::hash(&[1, 2, 3]),
            nodes: vec![
                PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &gen_keypair().0)
            ]
        };

        let data = Packet::OnionAnnounceResponse(OnionAnnounceResponse::new(&precomp, 12345, &payload));

        let res = alice.handle_packet(data, addr).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), HandlePacketErrorKind::NotHandled);
    }

    #[test]
    fn ping_node() {
        let (alice, precomp, bob_pk, _bob_sk, rx, addr) = create_node();

        let node = PackedNode::new(addr, &bob_pk);

        alice.ping_node(&node).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr);

        let nodes_req = unpack!(packet, Packet::NodesRequest);
        let nodes_req_payload = nodes_req.get_payload(&precomp).unwrap();

        assert_eq!(nodes_req_payload.pk, alice.pk);
    }
}
