/*! The implementation of Friend connection
*/

pub mod errors;
pub mod packet;

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use failure::Fail;
use futures::{Future, FutureExt, TryFutureExt, StreamExt, TryStreamExt, SinkExt, future};
use futures::future::Either;
use futures::channel::mpsc;
use parking_lot::RwLock;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::dht_node::BAD_NODE_TIMEOUT;
use crate::toxcore::dht::packed_node::PackedNode;
use crate::toxcore::dht::server::{Server as DhtServer};
use crate::toxcore::friend_connection::errors::*;
use crate::toxcore::friend_connection::packet::*;
use crate::toxcore::net_crypto::NetCrypto;
use crate::toxcore::net_crypto::errors::KillConnectionErrorKind;
use crate::toxcore::onion::client::OnionClient;
use crate::toxcore::tcp::client::{Connections as TcpConnections};
use crate::toxcore::time::*;

/// Shorthand for the transmit half of the message channel for sending a
/// connection status when it becomes connected or disconnected. The key is a
/// long term key of the connection.
type ConnectionStatusTx = mpsc::UnboundedSender<(PublicKey, bool)>;

/// How often we should send ping packets to a friend.
const FRIEND_PING_INTERVAL: Duration = Duration::from_secs(8);

/// Connection to a friend is considered timed out if we haven't been receiving
/// ping packets for this amount of time.
const FRIEND_CONNECTION_TIMEOUT: Duration = Duration::from_secs(FRIEND_PING_INTERVAL.as_secs() * 4);

/// How often we should send `ShareRelays` packet to a friend.
const SHARE_RELAYS_INTERVAL: Duration = Duration::from_secs(300);

/// How often the main loop should be called.
const MAIN_LOOP_INTERVAL: Duration = Duration::from_secs(1);

/// After this amount of time with no connection friend's DHT `PublicKey` and IP
/// address will be considered timed out.
const FRIEND_DHT_TIMEOUT: Duration = BAD_NODE_TIMEOUT;

/// Friend related data stored in the friend connections module.
#[derive(Clone, Debug)]
struct Friend {
    /// Friend's long term `PublicKey`.
    real_pk: PublicKey,
    /// Friend's DHT `PublicKey` when it's known.
    dht_pk: Option<PublicKey>,
    /// Friend's IP address when it's known.
    saddr: Option<SocketAddr>,
    /// Time when we received friend's DHT `PublicKey`.
    dht_pk_time: Option<Instant>,
    /// Time when we received friend's IP address.
    saddr_time: Option<Instant>,
    /// Whether we connected to this friend.
    connected: bool,
    /// Time when we sent the last ping packet.
    ping_sent_time: Option<Instant>,
    /// Time when we received the last ping packet.
    ping_received_time: Option<Instant>,
    /// Time when we sent the last `ShareRelays` packet.
    share_relays_time: Option<Instant>,
}

impl Friend {
    pub fn new(real_pk: PublicKey) -> Self {
        Friend {
            real_pk,
            dht_pk: None,
            saddr: None,
            dht_pk_time: None,
            saddr_time: None,
            connected: false,
            ping_sent_time: None,
            ping_received_time: None,
            share_relays_time: None,
        }
    }
}

/// Friend connections module that handles friends and their connections.
#[derive(Clone)]
pub struct FriendConnections {
    /// Our long term `SecretKey`.
    real_sk: SecretKey,
    /// Our long term `PublicKey`.
    real_pk: PublicKey,
    /// List of friends we want to be connected to.
    friends: Arc<RwLock<HashMap<PublicKey, Friend>>>,
    /// Sink to send a connection status when it becomes connected or
    /// disconnected. The key is a long term key of the connection.
    connection_status_tx: Arc<RwLock<Option<ConnectionStatusTx>>>,
    /// DHT server.
    dht: DhtServer,
    /// TCP connections.
    tcp_connections: TcpConnections,
    /// Onion client.
    onion_client: OnionClient,
    /// Net crypto.
    net_crypto: NetCrypto,
}

impl FriendConnections {
    /// Create new `FriendConnections`.
    pub fn new(
        real_sk: SecretKey,
        real_pk: PublicKey,
        dht: DhtServer,
        tcp_connections: TcpConnections,
        onion_client: OnionClient,
        net_crypto: NetCrypto,
    ) -> Self {
        FriendConnections {
            real_sk,
            real_pk,
            friends: Arc::new(RwLock::new(HashMap::new())),
            connection_status_tx: Arc::new(RwLock::new(None)),
            dht,
            tcp_connections,
            onion_client,
            net_crypto,
        }
    }

    /// Add a friend we want to be connected to.
    pub fn add_friend(&self, friend_pk: PublicKey) {
        let mut friends = self.friends.write();
        if let Entry::Vacant(entry) = friends.entry(friend_pk) {
            entry.insert(Friend::new(friend_pk));
            self.onion_client.add_friend(friend_pk);
            self.net_crypto.add_friend(friend_pk);
        }
    }

    /// Remove a friend and drop all connections with him.
    pub fn remove_friend(&self, friend_pk: PublicKey) -> impl Future<Output = Result<(), RemoveFriendError>> + Send {
        let mut friends = self.friends.write();
        if let Some(friend) = friends.remove(&friend_pk) {
            let tcp_remove_future = if let Some(dht_pk) = friend.dht_pk {
                self.dht.remove_friend(dht_pk);
                // TODO: handle error properly after migrating the TCP client to failure
                Either::Left(
                    self.tcp_connections.remove_connection(dht_pk)
                        .then(|_| future::ok(()))
                )
            } else {
                Either::Right(future::ok(()))
            };
            self.net_crypto.remove_friend(friend_pk);
            self.onion_client.remove_friend(friend_pk);
            let kill_connection_future = self.net_crypto.kill_connection(friend_pk)
                .then(|res| future::ready(match res {
                    Err(ref e)
                    if *e.kind() == KillConnectionErrorKind::NoConnection =>
                        Ok(()),
                    res => res,
                }))
                .map_err(|e| e.context(RemoveFriendErrorKind::KillConnection).into());
            Either::Left(
                future::try_join(kill_connection_future, tcp_remove_future)
                    .map_ok(drop)
            )
        } else {
            Either::Right(future::err(RemoveFriendErrorKind::NoFriend.into()))
        }
    }

    /// Handle received `ShareRelays` packet.
    pub fn handle_share_relays(&self, friend_pk: PublicKey, share_relays: ShareRelays) -> impl Future<Output = Result<(), HandleShareRelaysError>> + Send {
        if let Some(friend) = self.friends.read().get(&friend_pk) {
            if let Some(dht_pk) = friend.dht_pk {
                let futures = share_relays.relays
                    .iter()
                    .map(|node| self.tcp_connections.add_relay_connection(node.saddr, node.pk, dht_pk))
                    .collect::<Vec<_>>();
                Either::Left(
                    future::try_join_all(futures)
                        .map_ok(drop)
                        .map_err(|e|
                            e.context(HandleShareRelaysErrorKind::AddTcpConnection).into()
                        )
                )
            } else {
                Either::Right(future::ok(()))
            }
        } else {
            Either::Right(future::ok(()))
        }
    }

    /// Handle received ping packet.
    pub fn handle_ping(&self, friend_pk: PublicKey) {
        if let Some(friend) = self.friends.write().get_mut(&friend_pk) {
            friend.ping_received_time = Some(clock_now());
        }
    }

    /// Handle the stream of found DHT `PublicKey`s.
    fn handle_dht_pk(&self, dht_pk_rx: mpsc::UnboundedReceiver<(PublicKey, PublicKey)>) -> impl Future<Output = Result<(), RunError>> + Send {
        let dht = self.dht.clone();
        let net_crypto = self.net_crypto.clone();
        let onion_client = self.onion_client.clone();
        let friends = self.friends.clone();
        let tcp_connections = self.tcp_connections.clone();
        dht_pk_rx
            .map(Ok)
            .try_for_each(move |(real_pk, dht_pk)| {
                if let Some(friend) = friends.write().get_mut(&real_pk) {
                    friend.dht_pk_time = Some(clock_now());

                    if friend.dht_pk != Some(dht_pk) {
                        info!("Found a friend's DHT key");

                        let kill_future = if let Some(dht_pk) = friend.dht_pk {
                            dht.remove_friend(dht_pk);

                            let kill_connection_future = net_crypto.kill_connection(real_pk)
                                .then(|res| future::ready(
                                    match res {
                                        Err(ref e)
                                        if *e.kind() == KillConnectionErrorKind::NoConnection =>
                                            Ok(()),
                                        res => res,
                                    }
                                ))
                                .map_err(|e| e.context(RunErrorKind::KillConnection).into());
                            // TODO: handle error properly after migrating the TCP client to failure
                            let tcp_remove_future = tcp_connections.remove_connection(dht_pk)
                                .then(|_| future::ok(()));

                            Either::Left(
                                future::try_join(kill_connection_future, tcp_remove_future)
                                    .map_ok(drop)
                            )
                        } else {
                            Either::Right(future::ok(()))
                        };

                        friend.dht_pk = Some(dht_pk);

                        dht.add_friend(dht_pk);
                        net_crypto.add_connection(real_pk, dht_pk);
                        onion_client.set_friend_dht_pk(real_pk, dht_pk);

                        kill_future
                    } else {
                        Either::Right(future::ok(()))
                    }
                } else {
                    Either::Right(future::ok(()))
                }
            })
    }

    /// Handle the stream of found IP addresses.
    fn handle_friend_saddr(&self, friend_saddr_rx: mpsc::UnboundedReceiver<PackedNode>) -> impl Future<Output = Result<(), RunError>> + Send {
        let net_crypto = self.net_crypto.clone();
        let friends = self.friends.clone();
        friend_saddr_rx
            .map(Ok)
            .try_for_each(move |node| {
                let mut friends = friends.write();
                let friend = friends.values_mut()
                    .find(|friend| friend.dht_pk == Some(node.pk));
                if let Some(friend) = friend {
                    friend.saddr_time = Some(clock_now());

                    if friend.saddr != Some(node.saddr) {
                        info!("Found a friend's IP address");

                        friend.saddr = Some(node.saddr);

                        net_crypto.add_connection(friend.real_pk, node.pk);
                        net_crypto.set_friend_udp_addr(friend.real_pk, node.saddr);
                    }
                }

                future::ok(())
            })
    }

    /// Handle the stream of connection statuses.
    fn handle_connection_status(&self, connnection_status_rx: mpsc::UnboundedReceiver<(PublicKey, bool)>) -> impl Future<Output = Result<(), RunError>> + Send {
        let onion_client = self.onion_client.clone();
        let friends = self.friends.clone();
        let connection_status_tx = self.connection_status_tx.clone();
        connnection_status_rx
            .map(Ok)
            .try_for_each(move |(real_pk, status)| {
                if let Some(friend) = friends.write().get_mut(&real_pk) {
                    if status && !friend.connected {
                        info!("Connection with a friend is established");

                        friend.ping_received_time = Some(clock_now());
                        friend.ping_sent_time = None;
                        friend.share_relays_time = None;
                    } else if !status && friend.connected {
                        info!("Connection with a friend is lost");

                        // update dht_pk_time right after it went offline to enforce attemts to reconnect
                        friend.dht_pk_time = Some(clock_now());
                    }

                    if status != friend.connected {
                        friend.connected = status;
                        onion_client.set_friend_connected(real_pk, status);
                        if let Some(mut connection_status_tx) = connection_status_tx.read().clone() {
                            let res = async move {
                                connection_status_tx.send((real_pk, status)).await
                                    .map_err(|e| e.context(RunErrorKind::SendToConnectionStatus).into())
                            };

                            return Either::Left(res);
                        }
                    }
                }

                Either::Right(future::ok(()))
            })
    }

    /// Send some of our relays to a friend and start using these relays to
    /// connect to this friend.
    fn share_relays(&self, friend_pk: PublicKey) -> impl Future<Output = Result<(), RunError>> + Send {
        let relays = self.tcp_connections.get_random_relays(MAX_SHARED_RELAYS as u8);
        if !relays.is_empty() {
            let relay_futures = relays.iter().map(|relay|
                self.tcp_connections.add_connection(relay.pk, friend_pk)
                    .map_err(|e| e.context(RunErrorKind::AddTcpConnection).into())
            ).collect::<Vec<_>>();

            let share_relays = ShareRelays {
                relays,
            };
            let mut buf = vec![0; 154];
            let (_, size) = share_relays.to_bytes((&mut buf, 0)).unwrap();
            buf.truncate(size);
            let send_future = self.net_crypto.send_lossless(friend_pk, buf)
                .map_err(|e| e.context(RunErrorKind::SendTo).into());

            Either::Left(
                future::try_join(
                    future::try_join_all(relay_futures),
                    send_future
                )
                .map_ok(drop)
            )
        } else {
            Either::Right(future::ok(()))
        }
    }

    /// Main loop that should be called periodically.
    fn main_loop(&self) -> impl Future<Output = Result<(), RunError>> + Send {
        use std::pin::Pin;
        let mut futures: Vec<Pin<Box<dyn Future<Output = Result<_, _>> + Send>>> = Vec::new();

        for friend in self.friends.write().values_mut() {
            if friend.connected {
                if friend.ping_received_time.map_or(true, |time| clock_elapsed(time) >= FRIEND_CONNECTION_TIMEOUT) {
                    let future = self.net_crypto.kill_connection(friend.real_pk)
                        .then(|res| future::ready(match res {
                            Err(ref e)
                            if *e.kind() == KillConnectionErrorKind::NoConnection =>
                                Ok(()),
                            res => res,
                        }))
                        .map_err(|e| e.context(RunErrorKind::KillConnection).into());
                    futures.push(Box::pin(future));
                    continue;
                }

                if friend.ping_sent_time.map_or(true, |time| clock_elapsed(time) >= FRIEND_PING_INTERVAL) {
                    let future = self.net_crypto.send_lossless(friend.real_pk, vec![PACKET_ID_ALIVE])
                        .map_err(|e| e.context(RunErrorKind::SendTo).into());
                    futures.push(Box::pin(future));
                    friend.ping_sent_time = Some(clock_now());
                }

                if friend.share_relays_time.map_or(true, |time| clock_elapsed(time) >= SHARE_RELAYS_INTERVAL) {
                    futures.push(Box::pin(self.share_relays(friend.real_pk)));
                    friend.share_relays_time = Some(clock_now());
                }
            } else {
                if friend.dht_pk_time.map_or(false, |time| clock_elapsed(time) >= FRIEND_DHT_TIMEOUT) {
                    if let Some(dht_pk) = friend.dht_pk {
                        self.dht.remove_friend(dht_pk);
                    }
                    friend.dht_pk = None;
                    friend.dht_pk_time = None;
                }

                if friend.saddr_time.map_or(false, |time| clock_elapsed(time) >= FRIEND_DHT_TIMEOUT) {
                    friend.saddr = None;
                    friend.saddr_time = None;
                }

                if let Some(dht_pk) = friend.dht_pk {
                    self.net_crypto.add_connection(friend.real_pk, dht_pk);
                    if let Some(saddr) = friend.saddr {
                        self.net_crypto.set_friend_udp_addr(friend.real_pk, saddr);
                    }
                }
            }
        }

        future::try_join_all(futures)
            .map_ok(drop)
    }

    /// Call the main loop periodically.
    async fn run_main_loop(self) -> Result<(), RunError> {
        let mut wakeups = tokio::time::interval(MAIN_LOOP_INTERVAL);

        while let Some(_) = wakeups.next().await {
            let fut = tokio::time::timeout(MAIN_LOOP_INTERVAL, self.main_loop());
            let res = match fut.await {
                Err(e) => Err(e.context(RunErrorKind::Timeout).into()),
                Ok(Err(e)) => Err(e),
                Ok(Ok(_)) => Ok(()),
            };

            if let Err(ref e) = res {
                warn!("Failed to send friend's periodical packets: {}", e);
                return res
            }
        }

        Ok(())
    }

    /// Run friends connection module. This will add handlers for DHT
    /// `PublicKey`, IP address and connection status updates to appropriate
    /// modules.
    pub fn run(self) -> impl Future<Output = Result<(), RunError>> + Send {
        let (dht_pk_tx, dht_pk_rx) = mpsc::unbounded();
        self.onion_client.set_dht_pk_sink(dht_pk_tx.clone());
        self.net_crypto.set_dht_pk_sink(dht_pk_tx);

        let (friend_saddr_tx, friend_saddr_rx) = mpsc::unbounded();
        self.dht.set_friend_saddr_sink(friend_saddr_tx);

        let (connection_status_tx, connection_status_rx) = mpsc::unbounded();
        self.net_crypto.set_connection_status_sink(connection_status_tx);

        let dht_pk_future = self.handle_dht_pk(dht_pk_rx);
        let friend_saddr_future = self.handle_friend_saddr(friend_saddr_rx);
        let connection_status_future = self.handle_connection_status(connection_status_rx);
        let main_loop_future = self.run_main_loop();

        async {
            let res = futures::select! {
                res = dht_pk_future.fuse() => res,
                res = friend_saddr_future.fuse() => res,
                res = connection_status_future.fuse() => res,
                res = main_loop_future.fuse() => res,
            };

            res
        }
    }

    /// Set sink to send a connection status when it becomes connected or
    /// disconnected.
    pub fn set_connection_status_sink(&self, connection_status_tx: mpsc::UnboundedSender<(PublicKey, bool)>) {
        *self.connection_status_tx.write() = Some(connection_status_tx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::toxcore::dht::packet::{Packet as DhtPacket, *};
    use crate::toxcore::dht::precomputed_cache::*;
    use crate::toxcore::net_crypto::*;

    type DhtRx = mpsc::Receiver<(DhtPacket, SocketAddr)>;
    type LosslessRx = mpsc::UnboundedReceiver<(PublicKey, Vec<u8>)>;

    fn create_friend_connections() -> (FriendConnections, DhtRx, LosslessRx) {
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let (lossless_tx, lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let mut dht = DhtServer::new(udp_tx.clone(), dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk.clone(), tcp_incoming_tx);
        let onion_client = OnionClient::new(dht.clone(), tcp_connections.clone(), real_sk.clone(), real_pk);
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk: real_sk.clone(),
            precomputed_keys,
        });
        dht.set_onion_client(onion_client.clone());
        dht.set_net_crypto(net_crypto.clone());
        let friend_connections = FriendConnections::new(
            real_sk,
            real_pk,
            dht,
            tcp_connections,
            onion_client,
            net_crypto
        );
        (friend_connections, udp_rx, lossless_rx)
    }

    #[tokio::test]
    async fn add_remove_friend() {
        let (friend_connections, udp_rx, _lossless_rx) = create_friend_connections();
        let (friend_pk, _friend_sk) = gen_keypair();
        friend_connections.add_friend(friend_pk);

        let now = Instant::now();
        let saddr = "127.0.0.1:12345".parse().unwrap();
        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        let mut friends = friend_connections.friends.write();
        let friend = friends.get_mut(&friend_pk).unwrap();
        friend.dht_pk = Some(friend_dht_pk);
        friend.dht_pk_time = Some(now);
        friend.saddr = Some(saddr);
        friend.saddr_time = Some(now);
        drop(friends);

        // add friend to all modules to check later that it will be deleted
        // from everywhere
        friend_connections.dht.add_friend(friend_dht_pk);
        friend_connections.onion_client.add_friend(friend_pk);
        friend_connections.net_crypto.add_friend(friend_pk);
        let (_relay_incoming_rx, _relay_outgoing_rx, relay_pk) = friend_connections.tcp_connections.add_client();
        // ignore result future since it spawns the connection which should be
        // executed inside tokio context
        let _ = friend_connections.tcp_connections.add_connection(relay_pk, friend_dht_pk);

        let session_precomputed_key = precompute(&gen_keypair().0, &gen_keypair().1);
        let sent_nonce = gen_nonce();
        friend_connections.net_crypto.add_established_connection(
            gen_keypair().0,
            friend_pk,
            sent_nonce,
            gen_nonce(),
            session_precomputed_key.clone()
        );
        friend_connections.net_crypto.set_friend_udp_addr(friend_pk, saddr);

        friend_connections.remove_friend(friend_pk).await.unwrap();

        assert!(!friend_connections.dht.has_friend(&friend_dht_pk));
        assert!(!friend_connections.onion_client.has_friend(&friend_pk));
        assert!(!friend_connections.net_crypto.has_friend(&friend_pk));
        assert!(!friend_connections.tcp_connections.has_connection(&friend_dht_pk));

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, saddr);

        let packet = unpack!(received, DhtPacket::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.data, vec![2]); // PACKET_ID_KILL
    }

    #[tokio::test]
    async fn handle_dht_pk() {
        tokio::time::pause();
        let now = clock_now();

        let (friend_connections, udp_rx, _lossless_rx) = create_friend_connections();

        let saddr = "127.0.0.1:12345".parse().unwrap();
        let (friend_pk, _friend_sk) = gen_keypair();
        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        let mut friend = Friend::new(friend_pk);
        friend.dht_pk = Some(friend_dht_pk);
        friend.dht_pk_time = Some(now);
        friend.saddr = Some(saddr);
        friend.saddr_time = Some(now);
        friend_connections.friends.write().insert(friend_pk, friend);
        friend_connections.dht.add_friend(friend_dht_pk);
        friend_connections.net_crypto.add_friend(friend_pk);
        friend_connections.onion_client.add_friend(friend_pk);
        let (_relay_incoming_rx, _relay_outgoing_rx, relay_pk) = friend_connections.tcp_connections.add_client();
        // ignore result future since it spawns the connection which should be
        // executed inside tokio context
        let _ = friend_connections.tcp_connections.add_connection(relay_pk, friend_dht_pk);

        let session_precomputed_key = precompute(&gen_keypair().0, &gen_keypair().1);
        let sent_nonce = gen_nonce();
        friend_connections.net_crypto.add_established_connection(
            gen_keypair().0,
            friend_pk,
            sent_nonce,
            gen_nonce(),
            session_precomputed_key.clone()
        );
        friend_connections.net_crypto.set_friend_udp_addr(friend_pk, saddr);

        let (new_friend_dht_pk, _new_friend_dht_sk) = gen_keypair();
        let (mut dht_pk_tx, dht_pk_rx) = mpsc::unbounded();
        dht_pk_tx.send((friend_pk, new_friend_dht_pk)).await.unwrap();
        drop(dht_pk_tx);

        let delay = Duration::from_secs(1);
        tokio::time::advance(delay).await;

        friend_connections.handle_dht_pk(dht_pk_rx).await.unwrap();

        assert!(!friend_connections.dht.has_friend(&friend_dht_pk));
        assert!(friend_connections.dht.has_friend(&new_friend_dht_pk));
        assert_eq!(friend_connections.net_crypto.connection_dht_pk(&friend_pk), Some(new_friend_dht_pk));
        assert_eq!(friend_connections.onion_client.friend_dht_pk(&friend_pk), Some(new_friend_dht_pk));
        assert!(!friend_connections.tcp_connections.has_connection(&friend_dht_pk));

        let friend = &friend_connections.friends.read()[&friend_pk];
        assert_eq!(friend.dht_pk, Some(new_friend_dht_pk));
        assert_eq!(friend.dht_pk_time, Some(now + delay));

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, saddr);

        let packet = unpack!(received, DhtPacket::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.data, vec![2]); // PACKET_ID_KILL
    }

    #[tokio::test]
    async fn handle_friend_saddr() {
        tokio::time::pause();
        let now = clock_now();

        let (friend_connections, _udp_rx, _lossless_rx) = create_friend_connections();

        let (friend_pk, _friend_sk) = gen_keypair();
        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        let mut friend = Friend::new(friend_pk);
        friend.dht_pk = Some(friend_dht_pk);
        friend.dht_pk_time = Some(now);
        friend_connections.friends.write().insert(friend_pk, friend);

        let saddr = "127.0.0.1:12345".parse().unwrap();
        let (mut friend_saddr_tx, friend_saddr_rx) = mpsc::unbounded();
        friend_saddr_tx.send(PackedNode::new(saddr, &friend_dht_pk)).await.unwrap();
        drop(friend_saddr_tx);

        let delay = Duration::from_secs(1);
        tokio::time::advance(delay).await;

        friend_connections.handle_friend_saddr(friend_saddr_rx).await.unwrap();
        assert_eq!(friend_connections.net_crypto.connection_saddr(&friend_pk), Some(saddr));

        let friend = &friend_connections.friends.read()[&friend_pk];
        assert_eq!(friend.dht_pk, Some(friend_dht_pk));
        assert_eq!(friend.dht_pk_time, Some(now));
        assert_eq!(friend.saddr, Some(saddr));
        assert_eq!(friend.saddr_time, Some(now + delay));
    }

    #[tokio::test]
    async fn handle_connection_status_connected() {
        tokio::time::pause();
        let now = clock_now();

        let (friend_connections, _udp_rx, _lossless_rx) = create_friend_connections();
        let (friend_pk, _friend_sk) = gen_keypair();
        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        let mut friend = Friend::new(friend_pk);
        friend.dht_pk = Some(friend_dht_pk);
        friend.dht_pk_time = Some(now);
        friend.ping_sent_time = Some(now);
        friend.share_relays_time = Some(now);
        friend_connections.friends.write().insert(friend_pk, friend);
        friend_connections.onion_client.add_friend(friend_pk);

        let (mut connnection_status_tx, connnection_status_rx) = mpsc::unbounded();
        connnection_status_tx.send((friend_pk, true)).await.unwrap();
        drop(connnection_status_tx);

        friend_connections.handle_connection_status(connnection_status_rx).await.unwrap();

        let friend = &friend_connections.friends.read()[&friend_pk];
        assert!(friend.connected);
        assert_eq!(friend.ping_received_time, Some(now));
        assert!(friend.ping_sent_time.is_none());
        assert!(friend.share_relays_time.is_none());

        assert!(friend_connections.onion_client.is_friend_connected(&friend_pk));
    }

    #[tokio::test]
    async fn handle_connection_status_disconnected() {
        tokio::time::pause();
        let now = clock_now();

        let (friend_connections, _udp_rx, _lossless_rx) = create_friend_connections();
        let (friend_pk, _friend_sk) = gen_keypair();
        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        let mut friend = Friend::new(friend_pk);
        friend.dht_pk = Some(friend_dht_pk);
        friend.dht_pk_time = Some(now);
        friend.connected = true;
        friend_connections.friends.write().insert(friend_pk, friend);
        friend_connections.onion_client.add_friend(friend_pk);
        friend_connections.onion_client.set_friend_connected(friend_pk, true);

        let (mut connnection_status_tx, connnection_status_rx) = mpsc::unbounded();
        connnection_status_tx.send((friend_pk, false)).await.unwrap();
        drop(connnection_status_tx);

        friend_connections.handle_connection_status(connnection_status_rx).await.unwrap();

        let friend = &friend_connections.friends.read()[&friend_pk];
        assert!(!friend.connected);
        assert_eq!(friend.dht_pk_time, Some(now));

        assert!(!friend_connections.onion_client.is_friend_connected(&friend_pk));
    }

    #[tokio::test]
    async fn main_loop_remove_timed_out() {
        let (friend_connections, udp_rx, _lossless_rx) = create_friend_connections();

        let now = Instant::now();
        let saddr = "127.0.0.1:12345".parse().unwrap();
        let (friend_pk, _friend_sk) = gen_keypair();
        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        let mut friend = Friend::new(friend_pk);
        friend.dht_pk = Some(friend_dht_pk);
        friend.dht_pk_time = Some(now);
        friend.saddr = Some(saddr);
        friend.saddr_time = Some(now);
        friend.ping_received_time = Some(now);
        friend.ping_sent_time = Some(now);
        friend.share_relays_time = Some(now);
        friend.connected = true;
        friend_connections.friends.write().insert(friend_pk, friend);

        let session_precomputed_key = precompute(&gen_keypair().0, &gen_keypair().1);
        let sent_nonce = gen_nonce();
        friend_connections.net_crypto.add_established_connection(
            gen_keypair().0,
            friend_pk,
            sent_nonce,
            gen_nonce(),
            session_precomputed_key.clone()
        );
        friend_connections.net_crypto.set_friend_udp_addr(friend_pk, saddr);

        tokio::time::pause();
        tokio::time::advance(FRIEND_CONNECTION_TIMEOUT + Duration::from_secs(1)).await;

        friend_connections.main_loop().await.unwrap();

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, saddr);

        let packet = unpack!(received, DhtPacket::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.data, vec![2]); // PACKET_ID_KILL
    }

    #[tokio::test]
    async fn main_loop_send_ping() {
        tokio::time::pause();
        let now = clock_now();

        let (friend_connections, udp_rx, _lossless_rx) = create_friend_connections();

        let saddr = "127.0.0.1:12345".parse().unwrap();
        let (friend_pk, _friend_sk) = gen_keypair();
        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        let mut friend = Friend::new(friend_pk);
        friend.dht_pk = Some(friend_dht_pk);
        friend.dht_pk_time = Some(now);
        friend.saddr = Some(saddr);
        friend.saddr_time = Some(now);
        friend.ping_received_time = Some(now);
        friend.share_relays_time = Some(now);
        friend.connected = true;
        friend_connections.friends.write().insert(friend_pk, friend);

        let session_precomputed_key = precompute(&gen_keypair().0, &gen_keypair().1);
        let sent_nonce = gen_nonce();
        friend_connections.net_crypto.add_established_connection(
            gen_keypair().0,
            friend_pk,
            sent_nonce,
            gen_nonce(),
            session_precomputed_key.clone()
        );
        friend_connections.net_crypto.set_friend_udp_addr(friend_pk, saddr);

        let delay = Duration::from_secs(1);
        tokio::time::advance(delay).await;

        friend_connections.main_loop().await.unwrap();

        let friend = &friend_connections.friends.read()[&friend_pk];
        assert_eq!(friend.ping_sent_time, Some(now + delay));

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, saddr);

        let packet = unpack!(received, DhtPacket::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.data, vec![PACKET_ID_ALIVE]);
    }

    #[tokio::test]
    async fn main_loop_share_relays() {
        tokio::time::pause();
        let now = clock_now();

        let (friend_connections, udp_rx, _lossless_rx) = create_friend_connections();

        let saddr = "127.0.0.1:12345".parse().unwrap();
        let (friend_pk, _friend_sk) = gen_keypair();
        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        let mut friend = Friend::new(friend_pk);
        friend.dht_pk = Some(friend_dht_pk);
        friend.dht_pk_time = Some(now);
        friend.saddr = Some(saddr);
        friend.saddr_time = Some(now);
        friend.ping_received_time = Some(now);
        friend.ping_sent_time = Some(now);
        friend.connected = true;
        friend_connections.friends.write().insert(friend_pk, friend);

        let session_precomputed_key = precompute(&gen_keypair().0, &gen_keypair().1);
        let sent_nonce = gen_nonce();
        friend_connections.net_crypto.add_established_connection(
            gen_keypair().0,
            friend_pk,
            sent_nonce,
            gen_nonce(),
            session_precomputed_key.clone()
        );
        friend_connections.net_crypto.set_friend_udp_addr(friend_pk, saddr);

        let (_relay_incoming_rx, _relay_outgoing_rx, relay_pk) = friend_connections.tcp_connections.add_client();

        let delay = Duration::from_secs(1);
        tokio::time::advance(delay).await;

        friend_connections.main_loop().await.unwrap();

        let friend = &friend_connections.friends.read()[&friend_pk];
        assert_eq!(friend.share_relays_time, Some(now + delay));

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, saddr);

        let packet = unpack!(received, DhtPacket::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        let (_rest, packet) = ShareRelays::from_bytes(&payload.data).unwrap();
        assert_eq!(packet.relays.len(), 1);
        assert_eq!(packet.relays[0].pk, relay_pk);
    }

    #[tokio::test]
    async fn main_loop_clear_dht_pk() {
        tokio::time::pause();

        let now = clock_now();
        let delay = FRIEND_DHT_TIMEOUT + Duration::from_secs(1);

        let (friend_connections, _udp_rx, _lossless_rx) = create_friend_connections();
        let saddr = "127.0.0.1:12345".parse().unwrap();
        let (friend_pk, _friend_sk) = gen_keypair();
        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        let mut friend = Friend::new(friend_pk);
        friend.dht_pk = Some(friend_dht_pk);
        friend.dht_pk_time = Some(now);
        friend.saddr = Some(saddr);
        friend.saddr_time = Some(now + delay);
        friend.ping_received_time = Some(now);
        friend.ping_sent_time = Some(now);
        friend_connections.friends.write().insert(friend_pk, friend);

        tokio::time::advance(delay).await;

        friend_connections.main_loop().await.unwrap();

        let friend = &friend_connections.friends.read()[&friend_pk];
        assert!(friend.dht_pk.is_none());
        assert!(friend.dht_pk_time.is_none());
        assert_eq!(friend.saddr, Some(saddr));
        assert_eq!(friend.saddr_time, Some(now + delay));
    }

    #[tokio::test]
    async fn main_loop_clear_saddr() {
        tokio::time::pause();
        let now = clock_now();
        let delay = FRIEND_DHT_TIMEOUT + Duration::from_secs(1);

        let (friend_connections, _udp_rx, _lossless_rx) = create_friend_connections();
        let saddr = "127.0.0.1:12345".parse().unwrap();
        let (friend_pk, _friend_sk) = gen_keypair();
        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        let mut friend = Friend::new(friend_pk);
        friend.dht_pk = Some(friend_dht_pk);
        friend.dht_pk_time = Some(now + delay);
        friend.saddr = Some(saddr);
        friend.saddr_time = Some(now);
        friend.ping_received_time = Some(now);
        friend.ping_sent_time = Some(now);
        friend_connections.friends.write().insert(friend_pk, friend);

        tokio::time::advance(delay).await;
        friend_connections.main_loop().await.unwrap();

        let friend = &friend_connections.friends.read()[&friend_pk];
        assert_eq!(friend.dht_pk, Some(friend_dht_pk));
        assert_eq!(friend.dht_pk_time, Some(now + delay));
        assert!(friend.saddr.is_none());
        assert!(friend.saddr_time.is_none());
    }

    #[tokio::test]
    async fn handle_share_relays() {
        let (friend_connections, _udp_rx, _lossless_rx) = create_friend_connections();

        let (friend_pk, _friend_sk) = gen_keypair();
        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        let mut friend = Friend::new(friend_pk);
        friend.dht_pk = Some(friend_dht_pk);
        friend.connected = true;
        friend_connections.friends.write().insert(friend_pk, friend);

        let (relay_pk, _relay_sk) = gen_keypair();
        let relay_saddr = "127.0.0.1:12345".parse().unwrap();
        let share_relays = ShareRelays {
            relays: vec![PackedNode::new(relay_saddr, &relay_pk)],
        };

        // ignore result future since it spawns the connection which should be
        // executed inside tokio context
        let _ = friend_connections.handle_share_relays(friend_pk, share_relays);

        assert!(friend_connections.tcp_connections.has_relay(&relay_pk));
        assert!(friend_connections.tcp_connections.has_connection(&friend_dht_pk));
    }

    #[tokio::test]
    async fn handle_ping() {
        tokio::time::pause();
        let now = clock_now();

        let (friend_connections, _udp_rx, _lossless_rx) = create_friend_connections();

        let (friend_pk, _friend_sk) = gen_keypair();
        let mut friend = Friend::new(friend_pk);
        friend.ping_received_time = Some(now);
        friend.ping_sent_time = Some(now);
        friend.connected = true;
        friend_connections.friends.write().insert(friend_pk, friend);

        let duration = Duration::from_secs(1);
        tokio::time::advance(duration).await;

        friend_connections.handle_ping(friend_pk);

        let friend = &friend_connections.friends.read()[&friend_pk];
        assert_eq!(friend.ping_sent_time, Some(now));
        assert_eq!(friend.ping_received_time, Some(now + duration));
    }

    #[tokio::test]
    async fn run() {
        let (friend_connections, _udp_rx, lossless_rx) = create_friend_connections();
        let (friend_pk, friend_sk) = gen_keypair();
        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        let friend_saddr = "127.0.0.1:12345".parse().unwrap();
        friend_connections.add_friend(friend_pk);

        let (connection_status_tx, mut connection_status_rx) = mpsc::unbounded();
        friend_connections.set_connection_status_sink(connection_status_tx);

        // the ordering is essential since `run` adds its handlers that should
        // be done before packets handling
        let run_future = friend_connections.clone().run()
            .map(Result::unwrap);

        let precomputed_key = precompute(&friend_connections.real_pk, &friend_sk);
        let cookie = friend_connections.net_crypto.get_cookie(friend_pk, friend_dht_pk);
        let sent_nonce = gen_nonce();
        let (friend_session_pk, friend_session_sk) = gen_keypair();
        let our_cookie = EncryptedCookie {
            nonce: secretbox::gen_nonce(),
            payload: vec![42; 88]
        };
        let handshake_payload = CryptoHandshakePayload {
            base_nonce: sent_nonce,
            session_pk: friend_session_pk,
            cookie_hash: cookie.hash(),
            cookie: our_cookie,
        };
        let handshake = CryptoHandshake::new(&precomputed_key, &handshake_payload, cookie);

        let net_crypto = friend_connections.net_crypto.clone();
        let dht = friend_connections.dht.clone();
        let packets_future = async move {
            friend_connections.dht.handle_packet(DhtPacket::CryptoHandshake(handshake), friend_saddr).await.unwrap();

            let session_pk = net_crypto.get_session_pk(&friend_pk).unwrap();
            let session_precomputed_key = precompute(&session_pk, &friend_session_sk);

            let crypto_data_payload = CryptoDataPayload {
                buffer_start: 0,
                packet_number: 0,
                data: vec![PACKET_ID_ALIVE],
            };
            let crypto_data = CryptoData::new(&session_precomputed_key, sent_nonce, &crypto_data_payload);

            dht.handle_packet(DhtPacket::CryptoData(crypto_data), friend_saddr).await.unwrap();

            let (received, _lossless_rx) = lossless_rx.into_future().await;
            let (received_pk, received_data) = received.unwrap();
            assert_eq!(received_pk, friend_pk);
            assert_eq!(received_data, vec![PACKET_ID_ALIVE]);
        };

        let connection_status_future = async move {
            let packet = connection_status_rx.next().await;
            let (pk, status) = packet.unwrap();
            assert_eq!(pk, friend_pk);
            assert!(status);
        };

        let future = async move {
            let join = future::join(packets_future, run_future);

            futures::select! {
                _ = join.fuse() => (),
                _ = connection_status_future.fuse() => (),
            }
        };

        future.await;
    }
}
