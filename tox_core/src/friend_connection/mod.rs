/*! The implementation of Friend connection
*/

pub mod errors;

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::channel::mpsc;
use futures::{future, FutureExt, SinkExt, StreamExt};
use tokio::sync::RwLock;

use crate::dht::dht_node::BAD_NODE_TIMEOUT;
use crate::dht::server::Server as DhtServer;
use crate::friend_connection::errors::*;
use crate::net_crypto::errors::KillConnectionError;
use crate::net_crypto::NetCrypto;
use crate::onion::client::OnionClient;
use crate::relay::client::Connections as TcpConnections;
use crate::time::*;
use tox_binary_io::*;
use tox_crypto::*;
use tox_packet::dht::packed_node::PackedNode;
use tox_packet::friend_connection::*;

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
        dht: DhtServer,
        tcp_connections: TcpConnections,
        onion_client: OnionClient,
        net_crypto: NetCrypto,
    ) -> Self {
        FriendConnections {
            friends: Arc::new(RwLock::new(HashMap::new())),
            connection_status_tx: Arc::new(RwLock::new(None)),
            dht,
            tcp_connections,
            onion_client,
            net_crypto,
        }
    }

    /// Add a friend we want to be connected to.
    pub async fn add_friend(&self, friend_pk: PublicKey) {
        let mut friends = self.friends.write().await;
        if let Entry::Vacant(entry) = friends.entry(friend_pk.clone()) {
            entry.insert(Friend::new(friend_pk.clone()));
            self.onion_client.add_friend(friend_pk.clone()).await;
            self.net_crypto.add_friend(friend_pk).await;
        }
    }

    /// Remove a friend and drop all connections with him.
    pub async fn remove_friend(&self, friend_pk: PublicKey) -> Result<(), RemoveFriendError> {
        if let Some(friend) = self.friends.write().await.remove(&friend_pk) {
            if let Some(ref dht_pk) = friend.dht_pk {
                self.dht.remove_friend(dht_pk.clone()).await;
                // TODO: handle error properly after migrating the TCP client to failure
                self.tcp_connections.remove_connection(dht_pk.clone()).await.ok();
            };
            self.net_crypto.remove_friend(friend_pk.clone()).await;
            self.onion_client.remove_friend(friend_pk.clone()).await;
            self.net_crypto
                .kill_connection(friend_pk.clone())
                .then(|res| {
                    future::ready(match res {
                        Err(ref e) if e == &KillConnectionError::NoConnection => Ok(()),
                        res => res,
                    })
                })
                .await
                .map_err(RemoveFriendError::KillConnection)
        } else {
            Err(RemoveFriendError::NoFriend)
        }
    }

    /// Handle received `ShareRelays` packet.
    pub async fn handle_share_relays(
        &self,
        friend_pk: PublicKey,
        share_relays: ShareRelays,
    ) -> Result<(), HandleShareRelaysError> {
        if let Some(friend) = self.friends.read().await.get(&friend_pk) {
            if let Some(ref dht_pk) = friend.dht_pk {
                for node in share_relays.relays {
                    self.tcp_connections
                        .add_relay_connection(node.saddr, node.pk, dht_pk.clone())
                        .await
                        .map_err(HandleShareRelaysError::AddTcpConnection)?;
                }
            }
        }

        Ok(())
    }

    /// Handle received ping packet.
    pub async fn handle_ping(&self, friend_pk: PublicKey) {
        if let Some(friend) = self.friends.write().await.get_mut(&friend_pk) {
            friend.ping_received_time = Some(clock_now());
        }
    }

    /// Handle the stream of found DHT `PublicKey`s.
    async fn handle_dht_pk(
        &self,
        dht_pk_rx: &mut mpsc::UnboundedReceiver<(PublicKey, PublicKey)>,
    ) -> Result<(), RunError> {
        let dht = self.dht.clone();
        let net_crypto = self.net_crypto.clone();
        let onion_client = self.onion_client.clone();
        let friends = self.friends.clone();
        let tcp_connections = self.tcp_connections.clone();
        while let Some((real_pk, dht_pk)) = dht_pk_rx.next().await {
            if let Some(friend) = friends.write().await.get_mut(&real_pk) {
                friend.dht_pk_time = Some(clock_now());

                if friend.dht_pk.as_ref() != Some(&dht_pk) {
                    info!("Found a friend's DHT key");

                    if let Some(ref dht_pk) = friend.dht_pk {
                        dht.remove_friend(dht_pk.clone()).await;

                        net_crypto
                            .kill_connection(real_pk.clone())
                            .then(|res| {
                                future::ready(match res {
                                    Err(ref e) if e == &KillConnectionError::NoConnection => Ok(()),
                                    res => res,
                                })
                            })
                            .await
                            .map_err(RunError::KillConnection)?;
                        // TODO: handle error properly after migrating the TCP client to failure
                        tcp_connections.remove_connection(dht_pk.clone()).await.ok();
                    };

                    friend.dht_pk = Some(dht_pk.clone());

                    dht.add_friend(dht_pk.clone()).await;
                    net_crypto.add_connection(real_pk.clone(), dht_pk.clone()).await;
                    onion_client.set_friend_dht_pk(real_pk, dht_pk).await;
                }
            }
        }

        Ok(())
    }

    /// Handle the stream of found IP addresses.
    async fn handle_friend_saddr(
        &self,
        friend_saddr_rx: &mut mpsc::UnboundedReceiver<PackedNode>,
    ) -> Result<(), RunError> {
        let net_crypto = self.net_crypto.clone();
        let friends = self.friends.clone();
        while let Some(ref node) = friend_saddr_rx.next().await {
            let mut friends = friends.write().await;
            let friend = friends
                .values_mut()
                .find(|friend| friend.dht_pk.as_ref() == Some(&node.pk));
            if let Some(friend) = friend {
                friend.saddr_time = Some(clock_now());

                if friend.saddr != Some(node.saddr) {
                    info!("Found a friend's IP address");

                    friend.saddr = Some(node.saddr);

                    net_crypto.add_connection(friend.real_pk.clone(), node.pk.clone()).await;
                    net_crypto.set_friend_udp_addr(friend.real_pk.clone(), node.saddr).await;
                }
            }
        }

        Ok(())
    }

    /// Handle the stream of connection statuses.
    async fn handle_connection_status(
        &self,
        connnection_status_rx: &mut mpsc::UnboundedReceiver<(PublicKey, bool)>,
    ) -> Result<(), RunError> {
        let onion_client = self.onion_client.clone();
        let friends = self.friends.clone();
        let connection_status_tx = self.connection_status_tx.clone();
        while let Some((real_pk, status)) = connnection_status_rx.next().await {
            if let Some(friend) = friends.write().await.get_mut(&real_pk) {
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
                    onion_client.set_friend_connected(real_pk.clone(), status).await;
                    if let Some(mut connection_status_tx) = connection_status_tx.read().await.clone() {
                        connection_status_tx
                            .send((real_pk, status))
                            .await
                            .map_err(RunError::SendToConnectionStatus)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Send some of our relays to a friend and start using these relays to
    /// connect to this friend.
    async fn share_relays(&self, friend_pk: PublicKey) -> Result<(), RunError> {
        let relays = self.tcp_connections.get_random_relays(MAX_SHARED_RELAYS as u8).await;
        if !relays.is_empty() {
            for relay in &relays {
                self.tcp_connections
                    .add_connection(relay.pk.clone(), friend_pk.clone())
                    .await
                    .map_err(RunError::AddTcpConnection)?;
            }

            let share_relays = ShareRelays { relays };
            let mut buf = vec![0; 154];
            let (_, size) = share_relays.to_bytes((&mut buf, 0)).unwrap();
            buf.truncate(size);
            self.net_crypto
                .send_lossless(friend_pk, buf)
                .await
                .map_err(RunError::SendTo)
        } else {
            Ok(())
        }
    }

    /// Main loop that should be called periodically.
    async fn main_loop(&self) -> Result<(), RunError> {
        for friend in self.friends.write().await.values_mut() {
            if friend.connected {
                if friend
                    .ping_received_time
                    .map_or(true, |time| clock_elapsed(time) >= FRIEND_CONNECTION_TIMEOUT)
                {
                    self.net_crypto
                        .kill_connection(friend.real_pk.clone())
                        .then(|res| {
                            future::ready(match res {
                                Err(ref e) if e == &KillConnectionError::NoConnection => Ok(()),
                                res => res,
                            })
                        })
                        .await
                        .map_err(RunError::KillConnection)?;
                    continue;
                }

                if friend
                    .ping_sent_time
                    .map_or(true, |time| clock_elapsed(time) >= FRIEND_PING_INTERVAL)
                {
                    self.net_crypto
                        .send_lossless(friend.real_pk.clone(), vec![PACKET_ID_ALIVE])
                        .await
                        .map_err(RunError::SendTo)?;
                    friend.ping_sent_time = Some(clock_now());
                }

                if friend
                    .share_relays_time
                    .map_or(true, |time| clock_elapsed(time) >= SHARE_RELAYS_INTERVAL)
                {
                    self.share_relays(friend.real_pk.clone()).await?;
                    friend.share_relays_time = Some(clock_now());
                }
            } else {
                if friend
                    .dht_pk_time
                    .map_or(false, |time| clock_elapsed(time) >= FRIEND_DHT_TIMEOUT)
                {
                    if let Some(ref dht_pk) = friend.dht_pk {
                        self.dht.remove_friend(dht_pk.clone()).await;
                    }
                    friend.dht_pk = None;
                    friend.dht_pk_time = None;
                }

                if friend
                    .saddr_time
                    .map_or(false, |time| clock_elapsed(time) >= FRIEND_DHT_TIMEOUT)
                {
                    friend.saddr = None;
                    friend.saddr_time = None;
                }

                if let Some(ref dht_pk) = friend.dht_pk {
                    self.net_crypto
                        .add_connection(friend.real_pk.clone(), dht_pk.clone())
                        .await;
                    if let Some(saddr) = friend.saddr {
                        self.net_crypto.set_friend_udp_addr(friend.real_pk.clone(), saddr).await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Call the main loop periodically.
    async fn run_main_loop(&self) -> Result<(), RunError> {
        let mut wakeups = tokio::time::interval(MAIN_LOOP_INTERVAL);

        loop {
            wakeups.tick().await;

            let fut = tokio::time::timeout(MAIN_LOOP_INTERVAL, self.main_loop());
            let res = match fut.await {
                Err(e) => Err(RunError::Timeout(e)),
                Ok(Err(e)) => Err(e),
                Ok(Ok(_)) => Ok(()),
            };

            if let Err(ref e) = res {
                warn!("Failed to send friend's periodical packets: {}", e);
                return res;
            }
        }
    }

    /// Run friends connection module. This will add handlers for DHT
    /// `PublicKey`, IP address and connection status updates to appropriate
    /// modules.
    pub async fn run(&self) -> Result<(), RunError> {
        let (dht_pk_tx, mut dht_pk_rx) = mpsc::unbounded();
        self.onion_client.set_dht_pk_sink(dht_pk_tx.clone()).await;
        self.net_crypto.set_dht_pk_sink(dht_pk_tx).await;

        // Announce bridge between DhtServer and OnionClient: a single-consumer
        // mpsc channel, consistent with the other inter-module sinks.
        let (dht_pk_announce_tx, dht_pk_announce_rx) = tokio::sync::mpsc::unbounded_channel();
        self.dht.set_dht_pk_announce_sink(dht_pk_announce_tx).await;
        self.onion_client.set_dht_pk_announce_sink(dht_pk_announce_rx).await;

        let (friend_saddr_tx, mut friend_saddr_rx) = mpsc::unbounded();
        self.dht.set_friend_saddr_sink(friend_saddr_tx).await;

        let (connection_status_tx, mut connection_status_rx) = mpsc::unbounded();
        self.net_crypto.set_connection_status_sink(connection_status_tx).await;

        let dht_pk_future = self.handle_dht_pk(&mut dht_pk_rx);
        let friend_saddr_future = self.handle_friend_saddr(&mut friend_saddr_rx);
        let connection_status_future = self.handle_connection_status(&mut connection_status_rx);
        let main_loop_future = self.run_main_loop();

        futures::select! {
            res = dht_pk_future.fuse() => res,
            res = friend_saddr_future.fuse() => res,
            res = connection_status_future.fuse() => res,
            res = main_loop_future.fuse() => res,
        }
    }

    /// Set sink to send a connection status when it becomes connected or
    /// disconnected.
    pub async fn set_connection_status_sink(&self, connection_status_tx: mpsc::UnboundedSender<(PublicKey, bool)>) {
        *self.connection_status_tx.write().await = Some(connection_status_tx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream::FuturesUnordered;
    use rand::thread_rng;
    use std::future::Future;
    use std::pin::Pin;

    use crate::dht::precomputed_cache::*;
    use crate::net_crypto::*;
    use crypto_box::{
        aead::{generic_array::typenum::marker_traits::Unsigned, AeadCore},
        SalsaBox,
    };
    use tox_packet::dht::packed_node::PackedNode;
    use tox_packet::dht::{Packet as DhtPacket, *};
    use tox_packet::friend_connection::PACKET_ID_ALIVE;

    type DhtRx = mpsc::Receiver<(DhtPacket, SocketAddr)>;
    type LosslessRx = mpsc::UnboundedReceiver<(PublicKey, Vec<u8>)>;

    impl FriendConnections {
        /// Test helper: whether the orchestrator knows this friend is connected.
        async fn friend_is_connected(&self, pk: &PublicKey) -> bool {
            self.friends.read().await.get(pk).map_or(false, |f| f.connected)
        }
    }

    fn create_friend_connections() -> (FriendConnections, DhtRx, LosslessRx) {
        let mut rng = thread_rng();
        let dht_sk = SecretKey::generate(&mut rng);
        let dht_pk = dht_sk.public_key();
        let real_sk = SecretKey::generate(&mut rng);
        let real_pk = real_sk.public_key();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let (lossless_tx, lossless_rx) = mpsc::unbounded();
        let (lossy_tx, _lossy_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx.clone(), dht_pk.clone(), dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk.clone(), dht_sk.clone(), tcp_incoming_tx);
        let onion_client = OnionClient::new(dht.clone(), tcp_connections.clone(), real_sk.clone(), real_pk.clone());
        let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 1);
        let net_crypto = NetCrypto::new(NetCryptoNewArgs {
            udp_tx,
            lossless_tx,
            lossy_tx,
            dht_pk,
            dht_sk,
            real_pk,
            real_sk,
            precomputed_keys,
        });
        let friend_connections = FriendConnections::new(dht, tcp_connections, onion_client, net_crypto);
        (friend_connections, udp_rx, lossless_rx)
    }

    #[tokio::test]
    async fn add_remove_friend() {
        let mut rng = thread_rng();
        let (friend_connections, udp_rx, _lossless_rx) = create_friend_connections();
        let friend_pk = SecretKey::generate(&mut rng).public_key();
        friend_connections.add_friend(friend_pk.clone()).await;

        let now = Instant::now();
        let saddr = "127.0.0.1:12345".parse().unwrap();
        let friend_dht_pk = SecretKey::generate(&mut rng).public_key();
        let mut friends = friend_connections.friends.write().await;
        let friend = friends.get_mut(&friend_pk).unwrap();
        friend.dht_pk = Some(friend_dht_pk.clone());
        friend.dht_pk_time = Some(now);
        friend.saddr = Some(saddr);
        friend.saddr_time = Some(now);
        drop(friends);

        // add friend to all modules to check later that it will be deleted
        // from everywhere
        friend_connections.dht.add_friend(friend_dht_pk.clone()).await;
        friend_connections.onion_client.add_friend(friend_pk.clone()).await;
        friend_connections.net_crypto.add_friend(friend_pk.clone()).await;
        let (_relay_incoming_rx, _relay_outgoing_rx, relay_pk) = friend_connections.tcp_connections.add_client().await;
        // ignore result future since it spawns the connection which should be
        // executed inside tokio context
        let _ = friend_connections
            .tcp_connections
            .add_connection(relay_pk, friend_dht_pk.clone());

        let session_precomputed_key = SalsaBox::new(
            &SecretKey::generate(&mut rng).public_key(),
            &SecretKey::generate(&mut rng),
        );
        let sent_nonce = SalsaBox::generate_nonce(&mut rng).into();
        friend_connections
            .net_crypto
            .add_established_connection(
                SecretKey::generate(&mut rng).public_key(),
                friend_pk.clone(),
                sent_nonce,
                [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                session_precomputed_key.clone(),
            )
            .await;
        friend_connections
            .net_crypto
            .set_friend_udp_addr(friend_pk.clone(), saddr)
            .await;

        friend_connections.remove_friend(friend_pk.clone()).await.unwrap();

        assert!(!friend_connections.dht.has_friend(&friend_dht_pk).await);
        assert!(!friend_connections.onion_client.has_friend(&friend_pk).await);
        assert!(!friend_connections.net_crypto.has_friend(&friend_pk).await);
        assert!(!friend_connections.tcp_connections.has_connection(&friend_dht_pk).await);

        let (received, _udp_rx) = udp_rx.into_future().await;
        let (received, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, saddr);

        let packet = unpack!(received, DhtPacket::CryptoData);
        let payload = packet.get_payload(&session_precomputed_key, &sent_nonce).unwrap();
        assert_eq!(payload.data, vec![2]); // PACKET_ID_KILL
    }

    #[tokio::test]
    async fn handle_dht_pk() {
        let mut rng = thread_rng();
        tokio::time::pause();
        let now = clock_now();

        let (friend_connections, udp_rx, _lossless_rx) = create_friend_connections();

        let saddr = "127.0.0.1:12345".parse().unwrap();
        let friend_pk = SecretKey::generate(&mut rng).public_key();
        let friend_dht_pk = SecretKey::generate(&mut rng).public_key();
        let mut friend = Friend::new(friend_pk.clone());
        friend.dht_pk = Some(friend_dht_pk.clone());
        friend.dht_pk_time = Some(now);
        friend.saddr = Some(saddr);
        friend.saddr_time = Some(now);
        friend_connections
            .friends
            .write()
            .await
            .insert(friend_pk.clone(), friend);
        friend_connections.dht.add_friend(friend_dht_pk.clone()).await;
        friend_connections.net_crypto.add_friend(friend_pk.clone()).await;
        friend_connections.onion_client.add_friend(friend_pk.clone()).await;
        let (_relay_incoming_rx, _relay_outgoing_rx, relay_pk) = friend_connections.tcp_connections.add_client().await;
        // ignore result future since it spawns the connection which should be
        // executed inside tokio context
        let _ = friend_connections
            .tcp_connections
            .add_connection(relay_pk, friend_dht_pk.clone());

        let session_precomputed_key = SalsaBox::new(
            &SecretKey::generate(&mut rng).public_key(),
            &SecretKey::generate(&mut rng),
        );
        let sent_nonce = SalsaBox::generate_nonce(&mut rng).into();
        friend_connections
            .net_crypto
            .add_established_connection(
                SecretKey::generate(&mut rng).public_key(),
                friend_pk.clone(),
                sent_nonce,
                [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                session_precomputed_key.clone(),
            )
            .await;
        friend_connections
            .net_crypto
            .set_friend_udp_addr(friend_pk.clone(), saddr)
            .await;

        let new_friend_dht_pk = SecretKey::generate(&mut rng).public_key();
        let (mut dht_pk_tx, mut dht_pk_rx) = mpsc::unbounded();
        dht_pk_tx
            .send((friend_pk.clone(), new_friend_dht_pk.clone()))
            .await
            .unwrap();
        drop(dht_pk_tx);

        let delay = Duration::from_secs(1);
        tokio::time::advance(delay).await;

        friend_connections.handle_dht_pk(&mut dht_pk_rx).await.unwrap();

        assert!(!friend_connections.dht.has_friend(&friend_dht_pk).await);
        assert!(friend_connections.dht.has_friend(&new_friend_dht_pk).await);
        assert_eq!(
            friend_connections.net_crypto.connection_dht_pk(&friend_pk).await,
            Some(new_friend_dht_pk.clone())
        );
        assert_eq!(
            friend_connections.onion_client.friend_dht_pk(&friend_pk).await,
            Some(new_friend_dht_pk.clone())
        );
        assert!(!friend_connections.tcp_connections.has_connection(&friend_dht_pk).await);

        let friend = &friend_connections.friends.read().await[&friend_pk];
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
        let mut rng = thread_rng();
        tokio::time::pause();
        let now = clock_now();

        let (friend_connections, _udp_rx, _lossless_rx) = create_friend_connections();

        let friend_pk = SecretKey::generate(&mut rng).public_key();
        let friend_dht_pk = SecretKey::generate(&mut rng).public_key();
        let mut friend = Friend::new(friend_pk.clone());
        friend.dht_pk = Some(friend_dht_pk.clone());
        friend.dht_pk_time = Some(now);
        friend_connections
            .friends
            .write()
            .await
            .insert(friend_pk.clone(), friend);

        let saddr = "127.0.0.1:12345".parse().unwrap();
        let (mut friend_saddr_tx, mut friend_saddr_rx) = mpsc::unbounded();
        friend_saddr_tx
            .send(PackedNode::new(saddr, friend_dht_pk.clone()))
            .await
            .unwrap();
        drop(friend_saddr_tx);

        let delay = Duration::from_secs(1);
        tokio::time::advance(delay).await;

        friend_connections
            .handle_friend_saddr(&mut friend_saddr_rx)
            .await
            .unwrap();
        assert_eq!(
            friend_connections.net_crypto.connection_saddr(&friend_pk).await,
            Some(saddr)
        );

        let friend = &friend_connections.friends.read().await[&friend_pk];
        assert_eq!(friend.dht_pk, Some(friend_dht_pk));
        assert_eq!(friend.dht_pk_time, Some(now));
        assert_eq!(friend.saddr, Some(saddr));
        assert_eq!(friend.saddr_time, Some(now + delay));
    }

    #[tokio::test]
    async fn handle_connection_status_connected() {
        let mut rng = thread_rng();
        tokio::time::pause();
        let now = clock_now();

        let (friend_connections, _udp_rx, _lossless_rx) = create_friend_connections();
        let friend_pk = SecretKey::generate(&mut rng).public_key();
        let friend_dht_pk = SecretKey::generate(&mut rng).public_key();
        let mut friend = Friend::new(friend_pk.clone());
        friend.dht_pk = Some(friend_dht_pk);
        friend.dht_pk_time = Some(now);
        friend.ping_sent_time = Some(now);
        friend.share_relays_time = Some(now);
        friend_connections
            .friends
            .write()
            .await
            .insert(friend_pk.clone(), friend);
        friend_connections.onion_client.add_friend(friend_pk.clone()).await;

        let (mut connnection_status_tx, mut connnection_status_rx) = mpsc::unbounded();
        connnection_status_tx.send((friend_pk.clone(), true)).await.unwrap();
        drop(connnection_status_tx);

        friend_connections
            .handle_connection_status(&mut connnection_status_rx)
            .await
            .unwrap();

        let friend = &friend_connections.friends.read().await[&friend_pk];
        assert!(friend.connected);
        assert_eq!(friend.ping_received_time, Some(now));
        assert!(friend.ping_sent_time.is_none());
        assert!(friend.share_relays_time.is_none());

        assert!(friend_connections.onion_client.is_friend_connected(&friend_pk).await);
    }

    #[tokio::test]
    async fn handle_connection_status_disconnected() {
        let mut rng = thread_rng();
        tokio::time::pause();
        let now = clock_now();

        let (friend_connections, _udp_rx, _lossless_rx) = create_friend_connections();
        let friend_pk = SecretKey::generate(&mut rng).public_key();
        let friend_dht_pk = SecretKey::generate(&mut rng).public_key();
        let mut friend = Friend::new(friend_pk.clone());
        friend.dht_pk = Some(friend_dht_pk);
        friend.dht_pk_time = Some(now);
        friend.connected = true;
        friend_connections
            .friends
            .write()
            .await
            .insert(friend_pk.clone(), friend);
        friend_connections.onion_client.add_friend(friend_pk.clone()).await;
        friend_connections
            .onion_client
            .set_friend_connected(friend_pk.clone(), true)
            .await;

        let (mut connnection_status_tx, mut connnection_status_rx) = mpsc::unbounded();
        connnection_status_tx.send((friend_pk.clone(), false)).await.unwrap();
        drop(connnection_status_tx);

        friend_connections
            .handle_connection_status(&mut connnection_status_rx)
            .await
            .unwrap();

        let friend = &friend_connections.friends.read().await[&friend_pk];
        assert!(!friend.connected);
        assert_eq!(friend.dht_pk_time, Some(now));

        assert!(!friend_connections.onion_client.is_friend_connected(&friend_pk).await);
    }

    #[tokio::test]
    async fn main_loop_remove_timed_out() {
        let mut rng = thread_rng();
        let (friend_connections, udp_rx, _lossless_rx) = create_friend_connections();

        let now = Instant::now();
        let saddr = "127.0.0.1:12345".parse().unwrap();
        let friend_pk = SecretKey::generate(&mut rng).public_key();
        let friend_dht_pk = SecretKey::generate(&mut rng).public_key();
        let mut friend = Friend::new(friend_pk.clone());
        friend.dht_pk = Some(friend_dht_pk);
        friend.dht_pk_time = Some(now);
        friend.saddr = Some(saddr);
        friend.saddr_time = Some(now);
        friend.ping_received_time = Some(now);
        friend.ping_sent_time = Some(now);
        friend.share_relays_time = Some(now);
        friend.connected = true;
        friend_connections
            .friends
            .write()
            .await
            .insert(friend_pk.clone(), friend);

        let session_precomputed_key = SalsaBox::new(
            &SecretKey::generate(&mut rng).public_key(),
            &SecretKey::generate(&mut rng),
        );
        let sent_nonce = SalsaBox::generate_nonce(&mut rng).into();
        friend_connections
            .net_crypto
            .add_established_connection(
                SecretKey::generate(&mut rng).public_key(),
                friend_pk.clone(),
                sent_nonce,
                [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                session_precomputed_key.clone(),
            )
            .await;
        friend_connections
            .net_crypto
            .set_friend_udp_addr(friend_pk, saddr)
            .await;

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
        let mut rng = thread_rng();
        tokio::time::pause();
        let now = clock_now();

        let (friend_connections, udp_rx, _lossless_rx) = create_friend_connections();

        let saddr = "127.0.0.1:12345".parse().unwrap();
        let friend_pk = SecretKey::generate(&mut rng).public_key();
        let friend_dht_pk = SecretKey::generate(&mut rng).public_key();
        let mut friend = Friend::new(friend_pk.clone());
        friend.dht_pk = Some(friend_dht_pk);
        friend.dht_pk_time = Some(now);
        friend.saddr = Some(saddr);
        friend.saddr_time = Some(now);
        friend.ping_received_time = Some(now);
        friend.share_relays_time = Some(now);
        friend.connected = true;
        friend_connections
            .friends
            .write()
            .await
            .insert(friend_pk.clone(), friend);

        let session_precomputed_key = SalsaBox::new(
            &SecretKey::generate(&mut rng).public_key(),
            &SecretKey::generate(&mut rng),
        );
        let sent_nonce = SalsaBox::generate_nonce(&mut rng).into();
        friend_connections
            .net_crypto
            .add_established_connection(
                SecretKey::generate(&mut rng).public_key(),
                friend_pk.clone(),
                sent_nonce,
                [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                session_precomputed_key.clone(),
            )
            .await;
        friend_connections
            .net_crypto
            .set_friend_udp_addr(friend_pk.clone(), saddr)
            .await;

        let delay = Duration::from_secs(1);
        tokio::time::advance(delay).await;

        friend_connections.main_loop().await.unwrap();

        let friend = &friend_connections.friends.read().await[&friend_pk];
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
        let mut rng = thread_rng();
        tokio::time::pause();
        let now = clock_now();

        let (friend_connections, udp_rx, _lossless_rx) = create_friend_connections();

        let saddr = "127.0.0.1:12345".parse().unwrap();
        let friend_pk = SecretKey::generate(&mut rng).public_key();
        let friend_dht_pk = SecretKey::generate(&mut rng).public_key();
        let mut friend = Friend::new(friend_pk.clone());
        friend.dht_pk = Some(friend_dht_pk);
        friend.dht_pk_time = Some(now);
        friend.saddr = Some(saddr);
        friend.saddr_time = Some(now);
        friend.ping_received_time = Some(now);
        friend.ping_sent_time = Some(now);
        friend.connected = true;
        friend_connections
            .friends
            .write()
            .await
            .insert(friend_pk.clone(), friend);

        let session_precomputed_key = SalsaBox::new(
            &SecretKey::generate(&mut rng).public_key(),
            &SecretKey::generate(&mut rng),
        );
        let sent_nonce = SalsaBox::generate_nonce(&mut rng).into();
        friend_connections
            .net_crypto
            .add_established_connection(
                SecretKey::generate(&mut rng).public_key(),
                friend_pk.clone(),
                sent_nonce,
                [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                session_precomputed_key.clone(),
            )
            .await;
        friend_connections
            .net_crypto
            .set_friend_udp_addr(friend_pk.clone(), saddr)
            .await;

        let (_relay_incoming_rx, _relay_outgoing_rx, relay_pk) = friend_connections.tcp_connections.add_client().await;

        let delay = Duration::from_secs(1);
        tokio::time::advance(delay).await;

        friend_connections.main_loop().await.unwrap();

        let friend = &friend_connections.friends.read().await[&friend_pk];
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
        let mut rng = thread_rng();
        tokio::time::pause();

        let now = clock_now();
        let delay = FRIEND_DHT_TIMEOUT + Duration::from_secs(1);

        let (friend_connections, _udp_rx, _lossless_rx) = create_friend_connections();
        let saddr = "127.0.0.1:12345".parse().unwrap();
        let friend_pk = SecretKey::generate(&mut rng).public_key();
        let friend_dht_pk = SecretKey::generate(&mut rng).public_key();
        let mut friend = Friend::new(friend_pk.clone());
        friend.dht_pk = Some(friend_dht_pk);
        friend.dht_pk_time = Some(now);
        friend.saddr = Some(saddr);
        friend.saddr_time = Some(now + delay);
        friend.ping_received_time = Some(now);
        friend.ping_sent_time = Some(now);
        friend_connections
            .friends
            .write()
            .await
            .insert(friend_pk.clone(), friend);

        tokio::time::advance(delay).await;

        friend_connections.main_loop().await.unwrap();

        let friend = &friend_connections.friends.read().await[&friend_pk];
        assert!(friend.dht_pk.is_none());
        assert!(friend.dht_pk_time.is_none());
        assert_eq!(friend.saddr, Some(saddr));
        assert_eq!(friend.saddr_time, Some(now + delay));
    }

    #[tokio::test]
    async fn main_loop_clear_saddr() {
        let mut rng = thread_rng();
        tokio::time::pause();
        let now = clock_now();
        let delay = FRIEND_DHT_TIMEOUT + Duration::from_secs(1);

        let (friend_connections, _udp_rx, _lossless_rx) = create_friend_connections();
        let saddr = "127.0.0.1:12345".parse().unwrap();
        let friend_pk = SecretKey::generate(&mut rng).public_key();
        let friend_dht_pk = SecretKey::generate(&mut rng).public_key();
        let mut friend = Friend::new(friend_pk.clone());
        friend.dht_pk = Some(friend_dht_pk.clone());
        friend.dht_pk_time = Some(now + delay);
        friend.saddr = Some(saddr);
        friend.saddr_time = Some(now);
        friend.ping_received_time = Some(now);
        friend.ping_sent_time = Some(now);
        friend_connections
            .friends
            .write()
            .await
            .insert(friend_pk.clone(), friend);

        tokio::time::advance(delay).await;
        friend_connections.main_loop().await.unwrap();

        let friend = &friend_connections.friends.read().await[&friend_pk];
        assert_eq!(friend.dht_pk, Some(friend_dht_pk));
        assert_eq!(friend.dht_pk_time, Some(now + delay));
        assert!(friend.saddr.is_none());
        assert!(friend.saddr_time.is_none());
    }

    #[tokio::test]
    async fn handle_share_relays() {
        let mut rng = thread_rng();
        let (friend_connections, _udp_rx, _lossless_rx) = create_friend_connections();

        let friend_pk = SecretKey::generate(&mut rng).public_key();
        let friend_dht_pk = SecretKey::generate(&mut rng).public_key();
        let mut friend = Friend::new(friend_pk.clone());
        friend.dht_pk = Some(friend_dht_pk.clone());
        friend.connected = true;
        friend_connections
            .friends
            .write()
            .await
            .insert(friend_pk.clone(), friend);

        let relay_pk = SecretKey::generate(&mut rng).public_key();
        let relay_saddr = "127.0.0.1:12345".parse().unwrap();
        let share_relays = ShareRelays {
            relays: vec![PackedNode::new(relay_saddr, relay_pk.clone())],
        };

        friend_connections
            .handle_share_relays(friend_pk, share_relays)
            .await
            .unwrap();

        assert!(friend_connections.tcp_connections.has_relay(&relay_pk).await);
        assert!(friend_connections.tcp_connections.has_connection(&friend_dht_pk).await);
    }

    #[tokio::test]
    async fn handle_ping() {
        let mut rng = thread_rng();
        tokio::time::pause();
        let now = clock_now();

        let (friend_connections, _udp_rx, _lossless_rx) = create_friend_connections();

        let friend_pk = SecretKey::generate(&mut rng).public_key();
        let mut friend = Friend::new(friend_pk.clone());
        friend.ping_received_time = Some(now);
        friend.ping_sent_time = Some(now);
        friend.connected = true;
        friend_connections
            .friends
            .write()
            .await
            .insert(friend_pk.clone(), friend);

        let duration = Duration::from_secs(1);
        tokio::time::advance(duration).await;

        friend_connections.handle_ping(friend_pk.clone()).await;

        let friend = &friend_connections.friends.read().await[&friend_pk];
        assert_eq!(friend.ping_sent_time, Some(now));
        assert_eq!(friend.ping_received_time, Some(now + duration));
    }

    #[tokio::test]
    async fn run() {
        let mut rng = thread_rng();
        let (friend_connections, _udp_rx, lossless_rx) = create_friend_connections();
        let friend_sk = SecretKey::generate(&mut rng);
        let friend_pk = friend_sk.public_key();
        let friend_dht_pk = SecretKey::generate(&mut rng).public_key();
        let friend_saddr = "127.0.0.1:12345".parse().unwrap();
        friend_connections.add_friend(friend_pk.clone()).await;

        let (connection_status_tx, mut connection_status_rx) = mpsc::unbounded();
        friend_connections
            .set_connection_status_sink(connection_status_tx)
            .await;

        // the ordering is essential since `run` adds its handlers that should
        // be done before packets handling
        let run_future = friend_connections.run().map(Result::unwrap);

        let precomputed_key = SalsaBox::new(friend_connections.net_crypto.real_pk(), &friend_sk);
        let cookie = friend_connections
            .net_crypto
            .get_cookie(&mut rng, friend_pk.clone(), friend_dht_pk);
        let sent_nonce = SalsaBox::generate_nonce(&mut rng).into();
        let friend_session_sk = SecretKey::generate(&mut rng);
        let friend_session_pk = friend_session_sk.public_key();
        let our_cookie = EncryptedCookie {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; 88],
        };
        let handshake_payload = CryptoHandshakePayload {
            base_nonce: sent_nonce,
            session_pk: friend_session_pk,
            cookie_hash: cookie.hash(),
            cookie: our_cookie,
        };
        let handshake = CryptoHandshake::new(&precomputed_key, &handshake_payload, cookie);

        let net_crypto = friend_connections.net_crypto.clone();
        let packets_future = async {
            net_crypto
                .handle_udp_crypto_handshake(&handshake, friend_saddr)
                .await
                .unwrap();

            let session_pk = net_crypto.get_session_pk(&friend_pk).await.unwrap();
            let session_precomputed_key = SalsaBox::new(&session_pk, &friend_session_sk);

            let crypto_data_payload = CryptoDataPayload {
                buffer_start: 0,
                packet_number: 0,
                data: vec![PACKET_ID_ALIVE],
            };
            let crypto_data = CryptoData::new(&session_precomputed_key, sent_nonce, &crypto_data_payload);

            net_crypto
                .handle_udp_crypto_data(&crypto_data, friend_saddr)
                .await
                .unwrap();

            let (received, _lossless_rx) = lossless_rx.into_future().await;
            let (received_pk, received_data) = received.unwrap();
            assert_eq!(received_pk, friend_pk);
            assert_eq!(received_data, vec![PACKET_ID_ALIVE]);
        };

        let connection_status_future = async {
            let packet = connection_status_rx.next().await;
            let (pk, status) = packet.unwrap();
            assert_eq!(pk, friend_pk);
            assert!(status);
        };

        let join = future::join(run_future, packets_future);

        futures::select! {
            _ = join.fuse() => {},
            _ = connection_status_future.fuse() => {},
        }
    }

    #[tokio::test]
    async fn dht_pk_announce_middleware_chain() {
        // Regression test for the friend-handshake stall at the onion-announce step.
        let mut rng = thread_rng();
        let dht_sk = SecretKey::generate(&mut rng);
        let dht_pk = dht_sk.public_key();
        let real_sk = SecretKey::generate(&mut rng);
        let real_pk = real_sk.public_key();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk.clone(), dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk.clone(), dht_sk.clone(), tcp_incoming_tx);
        let onion_client = OnionClient::new(dht.clone(), tcp_connections.clone(), real_sk.clone(), real_pk.clone());

        let friend_sk = SecretKey::generate(&mut rng);
        let friend_pk = friend_sk.public_key();
        let friend_dht_pk = SecretKey::generate(&mut rng).public_key();

        onion_client.add_friend(friend_pk.clone()).await;

        let dht_shared_secret = SalsaBox::new(&friend_dht_pk, &dht_sk);
        let announce_shared_secret = SalsaBox::new(&friend_pk, &real_sk);
        let dht_pk_announce = DhtPkAnnounce::new(
            &announce_shared_secret,
            friend_pk.clone(),
            &DhtPkAnnouncePayload::new(friend_dht_pk.clone(), vec![]),
        );
        let packet = DhtPacket::DhtRequest(DhtRequest::new(
            &dht_shared_secret,
            dht_pk.clone(),        // rpk: recipient = this server's DHT public key
            friend_dht_pk.clone(), // spk: sender = peer's DHT public key
            &DhtRequestPayload::DhtPkAnnounce(dht_pk_announce),
        ));
        let packet_inner = match packet {
            DhtPacket::DhtRequest(inner) => inner,
            _ => unreachable!(),
        };
        let saddr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let (announce_tx, announce_rx) = tokio::sync::mpsc::unbounded_channel();
        dht.set_dht_pk_announce_sink(announce_tx).await;
        onion_client.set_dht_pk_announce_sink(announce_rx).await;

        dht.handle_dht_req(packet_inner, saddr).await.unwrap();

        onion_client.drain_dht_pk_announce().await.unwrap();

        // The friend's DHT key must have been registered by handle_dht_pk_announce.
        assert_eq!(
            onion_client.friend_dht_pk(&friend_pk).await,
            Some(friend_dht_pk.clone())
        );
    }

    /// Full peer stack for end-to-end tests
    struct TestPeer {
        udp_addr: SocketAddr,
        real_pk: PublicKey,
        real_sk: SecretKey,
        dht_pk: PublicKey,
        dht: DhtServer,
        #[allow(dead_code)]
        tcp_connections: TcpConnections,
        onion_client: OnionClient,
        net_crypto: NetCrypto,
        friend_connections: FriendConnections,
        udp_rx: mpsc::Receiver<(DhtPacket, SocketAddr)>,
        lossless_rx: LosslessRx,
    }

    impl TestPeer {
        fn new(udp_addr: SocketAddr) -> Self {
            let mut rng = thread_rng();
            let dht_sk = SecretKey::generate(&mut rng);
            let dht_pk = dht_sk.public_key();
            let real_sk = SecretKey::generate(&mut rng);
            let real_pk = real_sk.public_key();

            let (udp_tx, udp_rx) = mpsc::channel(32);
            let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
            let (lossless_tx, lossless_rx) = mpsc::unbounded();
            let (lossy_tx, _lossy_rx) = mpsc::unbounded();

            let dht = DhtServer::new(udp_tx.clone(), dht_pk.clone(), dht_sk.clone());
            let tcp_connections = TcpConnections::new(dht_pk.clone(), dht_sk.clone(), tcp_incoming_tx);
            let onion_client = OnionClient::new(dht.clone(), tcp_connections.clone(), real_sk.clone(), real_pk.clone());
            let precomputed_keys = PrecomputedCache::new(dht_sk.clone(), 8);
            let net_crypto = NetCrypto::new(NetCryptoNewArgs {
                udp_tx,
                lossless_tx,
                lossy_tx,
                dht_pk: dht_pk.clone(),
                dht_sk: dht_sk.clone(),
                real_pk: real_pk.clone(),
                real_sk: real_sk.clone(),
                precomputed_keys,
            });
            let friend_connections = FriendConnections::new(
                dht.clone(),
                tcp_connections.clone(),
                onion_client.clone(),
                net_crypto.clone(),
            );

            TestPeer {
                udp_addr,
                real_pk,
                real_sk,
                dht_pk,
                dht,
                tcp_connections,
                onion_client,
                net_crypto,
                friend_connections,
                udp_rx,
                lossless_rx,
            }
        }
    }

    #[derive(Clone)]
    struct PeerHandle {
        udp_addr: SocketAddr,
        real_pk: PublicKey,
        dht_pk: PublicKey,
        dht: DhtServer,
        onion_client: OnionClient,
        net_crypto: NetCrypto,
        friend_connections: FriendConnections,
    }

    impl PeerHandle {
        /// Dispatch a packet that arrived from `from` into this peer's modules.
        async fn dispatch_from(&self, packet: DhtPacket, from: SocketAddr) {
            match packet {
                DhtPacket::PingRequest(p) => {
                    let _ = self.dht.handle_ping_req(p, from).await;
                }
                DhtPacket::PingResponse(p) => {
                    let _ = self.dht.handle_ping_resp(p, from).await;
                }
                DhtPacket::NodesRequest(p) => {
                    let _ = self.dht.handle_nodes_req(p, from).await;
                }
                DhtPacket::NodesResponse(p) => {
                    let _ = self.dht.handle_nodes_resp(p, from).await;
                }
                DhtPacket::CookieRequest(p) => {
                    let _ = self.net_crypto.handle_udp_cookie_request(&p, from).await;
                }
                DhtPacket::CookieResponse(p) => {
                    let _ = self.net_crypto.handle_udp_cookie_response(&p, from).await;
                }
                DhtPacket::CryptoHandshake(p) => {
                    let _ = self.net_crypto.handle_udp_crypto_handshake(&p, from).await;
                }
                DhtPacket::CryptoData(p) => {
                    let _ = self.net_crypto.handle_udp_crypto_data(&p, from).await;
                }
                DhtPacket::DhtRequest(p) => {
                    let _ = self.dht.handle_dht_req(p, from).await;
                }
                // Onion packets are not part of the tested handshake path.
                _ => {}
            }
        }
    }

    /// The subset of a peer needed to emit or receive a `DhtPkAnnounce`.
    #[derive(Clone)]
    struct AnnouncePeer {
        dht: DhtServer,
        real_pk: PublicKey,
        real_sk: SecretKey,
        dht_pk: PublicKey,
        udp_addr: SocketAddr,
    }

    impl AnnouncePeer {
        fn new(peer: &TestPeer) -> Self {
            AnnouncePeer {
                dht: peer.dht.clone(),
                real_pk: peer.real_pk.clone(),
                real_sk: peer.real_sk.clone(),
                dht_pk: peer.dht_pk.clone(),
                udp_addr: peer.udp_addr,
            }
        }
    }

    /// Inject a `DhtPkAnnounce` from `sender` to `receiver` over the virtual DHT wire.
    async fn inject_dht_pk_announce(sender: &AnnouncePeer, receiver: &AnnouncePeer) {
        let dht_shared_secret = SalsaBox::new(&receiver.dht_pk, &sender.dht.sk);
        let announce_shared_secret = SalsaBox::new(&receiver.real_pk, &sender.real_sk);
        let dht_pk_announce = DhtPkAnnounce::new(
            &announce_shared_secret,
            sender.real_pk.clone(),
            &DhtPkAnnouncePayload::new(sender.dht_pk.clone(), vec![]),
        );
        let packet = DhtPacket::DhtRequest(DhtRequest::new(
            &dht_shared_secret,
            receiver.dht_pk.clone(),
            sender.dht_pk.clone(),
            &DhtRequestPayload::DhtPkAnnounce(dht_pk_announce),
        ));
        sender
            .dht
            .tx
            .clone()
            .send((packet, receiver.udp_addr))
            .await
            .expect("failed to inject the DhtPkAnnounce packet");
    }

    /// Virtual UDP network between two peers
    async fn run_cross_router(
        mut alice_rx: mpsc::Receiver<(DhtPacket, SocketAddr)>,
        mut bob_rx: mpsc::Receiver<(DhtPacket, SocketAddr)>,
        alice: PeerHandle,
        bob: PeerHandle,
    ) {
        loop {
            futures::select! {
                packet = alice_rx.next().fuse() => {
                    match packet {
                        Some((packet, _to)) => bob.dispatch_from(packet, alice.udp_addr).await,
                        None => return,
                    }
                }
                packet = bob_rx.next().fuse() => {
                    match packet {
                        Some((packet, _to)) => alice.dispatch_from(packet, bob.udp_addr).await,
                        None => return,
                    }
                }
            }
        }
    }

    type DriverFut<'a> = Pin<Box<dyn Future<Output = ()> + 'a>>;

    async fn pump_until<F, Fut>(
        drivers: &mut FuturesUnordered<DriverFut<'_>>,
        budget: Duration,
        label: &str,
        mut condition: F,
    ) where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            if condition().await {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("timed out while waiting for: {}", label);
            }
            tokio::time::advance(Duration::from_millis(50)).await;
            futures::select_biased! {
                _ = drivers.next().fuse() => {},
                _ = tokio::task::yield_now().fuse() => {},
            }
        }
    }

    /// End-to-end friendship handshake: `add_friend` -> DhtPkAnnounce via
    /// DhtRequest -> friend.dht_pk registration ->
    /// cookie handshake -> Established -> lossless delivery.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn handshake_from_dhtpk_announce_to_established() {
        // The drivers are not `Send` (the onion and crypto layers use
        // `rand::ThreadRng`), so they must be polled on a single thread.
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async { handshake_from_dhtpk_announce_to_established_inner().await })
            .await;
    }

    /// Body of the end-to-end friendship handshake test, executed inside a `LocalSet`
    async fn handshake_from_dhtpk_announce_to_established_inner() {
        let alice = TestPeer::new("127.0.0.1:33445".parse().unwrap());
        let bob = TestPeer::new("127.0.0.1:33446".parse().unwrap());

        let alice_announce = AnnouncePeer::new(&alice);
        let bob_announce = AnnouncePeer::new(&bob);

        let (alice_status_tx, mut alice_status_rx) = mpsc::unbounded();
        alice
            .friend_connections
            .set_connection_status_sink(alice_status_tx)
            .await;
        let (bob_status_tx, mut bob_status_rx) = mpsc::unbounded();
        bob.friend_connections.set_connection_status_sink(bob_status_tx).await;

        let alice_handle = PeerHandle {
            udp_addr: alice.udp_addr,
            real_pk: alice.real_pk.clone(),
            dht_pk: alice.dht_pk.clone(),
            dht: alice.dht.clone(),
            onion_client: alice.onion_client.clone(),
            net_crypto: alice.net_crypto.clone(),
            friend_connections: alice.friend_connections.clone(),
        };
        let bob_handle = PeerHandle {
            udp_addr: bob.udp_addr,
            real_pk: bob.real_pk.clone(),
            dht_pk: bob.dht_pk.clone(),
            dht: bob.dht.clone(),
            onion_client: bob.onion_client.clone(),
            net_crypto: bob.net_crypto.clone(),
            friend_connections: bob.friend_connections.clone(),
        };

        let mut drivers: FuturesUnordered<DriverFut<'_>> = FuturesUnordered::new();
        drivers.push(Box::pin(alice_handle.friend_connections.run().map(|_| ())));
        drivers.push(Box::pin(alice_handle.net_crypto.run().map(|_| ())));
        drivers.push(Box::pin(alice_handle.onion_client.run().map(|_| ())));
        drivers.push(Box::pin(alice_handle.dht.run().map(|_| ())));
        drivers.push(Box::pin(bob_handle.friend_connections.run().map(|_| ())));
        drivers.push(Box::pin(bob_handle.net_crypto.run().map(|_| ())));
        drivers.push(Box::pin(bob_handle.onion_client.run().map(|_| ())));
        drivers.push(Box::pin(bob_handle.dht.run().map(|_| ())));

        for _ in 0..16 {
            tokio::task::yield_now().await;
        }

        // Virtual UDP network between the peers
        let router = tokio::task::spawn_local(run_cross_router(
            alice.udp_rx,
            bob.udp_rx,
            alice_handle.clone(),
            bob_handle.clone(),
        ));

        alice_handle
            .friend_connections
            .add_friend(bob_handle.real_pk.clone())
            .await;
        bob_handle
            .friend_connections
            .add_friend(alice_handle.real_pk.clone())
            .await;

        alice_handle.dht.add_friend(bob_handle.dht_pk.clone()).await;
        bob_handle.dht.add_friend(alice_handle.dht_pk.clone()).await;
        alice_handle
            .dht
            .ping_node(PackedNode::new(bob_handle.udp_addr, bob_handle.dht_pk.clone()))
            .await
            .unwrap();
        bob_handle
            .dht
            .ping_node(PackedNode::new(alice_handle.udp_addr, alice_handle.dht_pk.clone()))
            .await
            .unwrap();

        let alice_dht = alice_handle.dht.clone();
        let bob_dht = bob_handle.dht.clone();
        let bob_dht_pk = bob_handle.dht_pk.clone();
        let alice_dht_pk = alice_handle.dht_pk.clone();
        pump_until(
            &mut drivers,
            Duration::from_secs(10),
            "DHT peers to learn each other",
            || {
                let (alice_dht, bob_dht) = (alice_dht.clone(), bob_dht.clone());
                let (bob_dht_pk, alice_dht_pk) = (bob_dht_pk.clone(), alice_dht_pk.clone());
                Box::pin(async move {
                    let alice_knows_bob = alice_dht.get_closest(&bob_dht_pk, 1, false).await.len() == 1;
                    let bob_knows_alice = bob_dht.get_closest(&alice_dht_pk, 1, false).await.len() == 1;
                    alice_knows_bob && bob_knows_alice
                })
            },
        )
        .await;

        assert!(
            alice_handle.dht.get_closest(&bob_dht_pk, 1, false).await.len() == 1,
            "alice did not learn bob's DHT node"
        );
        assert!(
            bob_handle.dht.get_closest(&alice_dht_pk, 1, false).await.len() == 1,
            "bob did not learn alice's DHT node"
        );

        inject_dht_pk_announce(&alice_announce, &bob_announce).await;
        inject_dht_pk_announce(&bob_announce, &alice_announce).await;

        let bob_onion = bob_handle.onion_client.clone();
        let alice_real_pk = alice_handle.real_pk.clone();
        pump_until(
            &mut drivers,
            Duration::from_secs(20),
            "friend.dht_pk registration",
            || {
                let bob_onion = bob_onion.clone();
                let alice_real_pk = alice_real_pk.clone();
                Box::pin(async move { bob_onion.friend_dht_pk(&alice_real_pk).await.is_some() })
            },
        )
        .await;

        assert_eq!(
            bob_handle.onion_client.friend_dht_pk(&alice_handle.real_pk).await,
            Some(alice_handle.dht_pk.clone()),
            "bob did not register alice's DHT key via the DhtPkAnnounce bridge"
        );
        assert_eq!(
            alice_handle.onion_client.friend_dht_pk(&bob_handle.real_pk).await,
            Some(bob_handle.dht_pk.clone()),
            "alice did not register bob's DHT key via the DhtPkAnnounce bridge"
        );

        // The registered DHT key must have triggered `NetCrypto::add_connection`
        // through `FriendConnections::handle_dht_pk`.
        let alice_net_crypto = alice_handle.net_crypto.clone();
        let bob_net_crypto = bob_handle.net_crypto.clone();
        let alice_real_pk = alice_handle.real_pk.clone();
        let bob_real_pk = bob_handle.real_pk.clone();
        pump_until(
            &mut drivers,
            Duration::from_secs(10),
            "crypto connection creation",
            || {
                let (alice_net_crypto, bob_net_crypto) = (alice_net_crypto.clone(), bob_net_crypto.clone());
                let (alice_real_pk, bob_real_pk) = (alice_real_pk.clone(), bob_real_pk.clone());
                Box::pin(async move {
                    alice_net_crypto.connection_dht_pk(&bob_real_pk).await.is_some()
                        && bob_net_crypto.connection_dht_pk(&alice_real_pk).await.is_some()
                })
            },
        )
        .await;

        assert_eq!(
            alice_handle.net_crypto.connection_dht_pk(&bob_handle.real_pk).await,
            Some(bob_handle.dht_pk.clone()),
            "alice has no crypto connection for bob"
        );
        assert_eq!(
            bob_handle.net_crypto.connection_dht_pk(&alice_handle.real_pk).await,
            Some(alice_handle.dht_pk.clone()),
            "bob has no crypto connection for alice"
        );

        pump_until(&mut drivers, Duration::from_secs(30), "cookie handshake", || {
            let (alice_net_crypto, bob_net_crypto) = (alice_net_crypto.clone(), bob_net_crypto.clone());
            let (alice_real_pk, bob_real_pk) = (alice_real_pk.clone(), bob_real_pk.clone());
            Box::pin(async move {
                alice_net_crypto.is_connection_established(&bob_real_pk).await
                    && bob_net_crypto.is_connection_established(&alice_real_pk).await
            })
        })
        .await;

        assert!(
            alice_handle
                .net_crypto
                .is_connection_established(&bob_handle.real_pk)
                .await,
            "alice's connection to bob is not established"
        );
        assert!(
            bob_handle
                .net_crypto
                .is_connection_established(&alice_handle.real_pk)
                .await,
            "bob's connection to alice is not established"
        );

        // The orchestrator must have consumed the Online event from net crypto
        let alice_fc = alice_handle.friend_connections.clone();
        let bob_fc = bob_handle.friend_connections.clone();
        let alice_check_pk = bob_handle.real_pk.clone();
        let bob_check_pk = alice_handle.real_pk.clone();
        pump_until(
            &mut drivers,
            Duration::from_secs(10),
            "orchestrator online state",
            || {
                let (alice_fc, bob_fc) = (alice_fc.clone(), bob_fc.clone());
                let (alice_check_pk, bob_check_pk) = (alice_check_pk.clone(), bob_check_pk.clone());
                Box::pin(async move {
                    alice_fc.friend_is_connected(&alice_check_pk).await
                        && bob_fc.friend_is_connected(&bob_check_pk).await
                })
            },
        )
        .await;

        assert!(
            alice_handle
                .friend_connections
                .friend_is_connected(&bob_handle.real_pk)
                .await,
            "alice's orchestrator does not consider bob connected"
        );
        assert!(
            bob_handle
                .friend_connections
                .friend_is_connected(&alice_handle.real_pk)
                .await,
            "bob's orchestrator does not consider alice connected"
        );
        let (status_pk, status) = alice_status_rx.next().await.expect("no status event for alice");
        assert_eq!(status_pk, bob_handle.real_pk);
        assert!(status, "alice received a non-online status event");
        let (status_pk, status) = bob_status_rx.next().await.expect("no status event for bob");
        assert_eq!(status_pk, alice_handle.real_pk);
        assert!(status, "bob received a non-online status event");

        // A lossless packet must now be deliverable in both directions.
        alice_handle
            .net_crypto
            .send_lossless(bob_handle.real_pk.clone(), vec![PACKET_ID_ALIVE])
            .await
            .expect("failed to send the lossless packet");

        let mut bob_lossless = bob.lossless_rx;
        let received = tokio::time::timeout(Duration::from_secs(10), bob_lossless.next()).await;
        let received = received
            .expect("timed out waiting for lossless packet")
            .expect("lossless channel closed");
        assert_eq!(received.0, alice_handle.real_pk);
        assert_eq!(received.1, vec![PACKET_ID_ALIVE]);

        router.abort();
    }
}
