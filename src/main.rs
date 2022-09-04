#![type_length_limit="65995950"]

#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;

mod node_config;
mod motd;

use std::convert::TryInto;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddr;

use anyhow::Error;
use futures::{channel::mpsc, StreamExt};
use futures::{future, Future, TryFutureExt, FutureExt};
use itertools::Itertools;
use rand::thread_rng;
use tokio::net::{TcpListener, UdpSocket};
use tokio::runtime;
use tox::crypto::*;
use tox::core::dht::server::Server as DhtServer;
use tox::core::dht::server_ext::dht_run_socket;
use tox::core::dht::lan_discovery::LanDiscoverySender;
use tox::core::udp::Server as UdpServer;
use tox::packet::onion::InnerOnionResponse;
use tox::packet::relay::OnionRequest;
use tox::core::relay::server::{Server as TcpServer, tcp_run};
use tox::core::stats::Stats;
#[cfg(unix)]
use syslog::Facility;

use crate::node_config::*;
use crate::motd::{Motd, Counters};

/// Channel size for onion messages between UDP and TCP relay.
const ONION_CHANNEL_SIZE: usize = 32;
/// Channel size for DHT packets.
const DHT_CHANNEL_SIZE: usize = 32;

/// Get version in format 3AAABBBCCC, where A B and C are major, minor and patch
/// versions of node. `tox-bootstrapd` uses similar scheme but with leading 1.
/// Before it used format YYYYMMDDVV so the leading numeral was 2. To make a
/// difference with these schemes we use 3.
fn version() -> u32 {
    let major: u32 = env!("CARGO_PKG_VERSION_MAJOR").parse().expect("Invalid major version");
    let minor: u32 = env!("CARGO_PKG_VERSION_MINOR").parse().expect("Invalid minor version");
    let patch: u32 = env!("CARGO_PKG_VERSION_PATCH").parse().expect("Invalid patch version");
    assert!(major < 1000, "Invalid major version");
    assert!(minor < 1000, "Invalid minor version");
    assert!(patch < 1000, "Invalid patch version");
    3_000_000_000 + major * 1_000_000 + minor * 1000 + patch
}

/// Bind a UDP listener to the socket address.
async fn bind_socket(addr: SocketAddr) -> UdpSocket {
    let socket = UdpSocket::bind(&addr).await.expect("Failed to bind UDP socket");
    socket.set_broadcast(true).expect("set_broadcast call failed");
    if addr.is_ipv6() {
        socket.set_multicast_loop_v6(true).expect("set_multicast_loop_v6 call failed");
    }
    socket
}

/// Save DHT keys to a binary file.
fn save_keys(keys_file: &str, pk: PublicKey, sk: &SecretKey) {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    #[cfg(not(unix))]
    let mut file = File::create(keys_file).expect("Failed to create the keys file");

    #[cfg(unix)]
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o600)
        .open(keys_file)
        .expect("Failed to create the keys file");

    file.write_all(pk.as_ref()).expect("Failed to save public key to the keys file");
    file.write_all(sk.as_bytes()).expect("Failed to save secret key to the keys file");
}

/// Load DHT keys from a binary file.
fn load_keys(mut file: File) -> (PublicKey, SecretKey) {
    let mut buf = [0; crypto_box::KEY_SIZE * 2];
    file.read_exact(&mut buf).expect("Failed to read keys from the keys file");
    let pk_bytes: [u8; crypto_box::KEY_SIZE] = buf[..crypto_box::KEY_SIZE].try_into().expect("Failed to read public key from the keys file");
    let sk_bytes: [u8; crypto_box::KEY_SIZE] = buf[crypto_box::KEY_SIZE..].try_into().expect("Failed to read secret key from the keys file");
    let pk = PublicKey::from(pk_bytes);
    let sk = SecretKey::from(sk_bytes);
    assert!(pk == sk.public_key(), "The loaded public key does not correspond to the loaded secret key");
    (pk, sk)
}

/// Load DHT keys from a binary file or generate and save them if file does not
/// exist.
fn load_or_gen_keys(keys_file: &str) -> (PublicKey, SecretKey) {
    match File::open(keys_file) {
        Ok(file) => load_keys(file),
        Err(ref e) if e.kind() == ErrorKind::NotFound => {
            info!("Generating new DHT keys and storing them to '{}'", keys_file);
            let sk = SecretKey::generate(&mut thread_rng());
            let pk = sk.public_key();
            save_keys(keys_file, pk.clone(), &sk);
            (pk, sk)
        },
        Err(e) => panic!("Failed to read the keys file: {}", e)
    }
}

/// Run a future with the runtime specified by config.
fn run<F>(future: F, threads: Threads)
    where F: Future<Output = Result<(), Error>> + 'static
{
    if threads == Threads::N(1) {
        let runtime = runtime::Runtime::new().expect("Failed to create runtime");
        runtime.block_on(future).expect("Execution was terminated with error");
    } else {
        let mut builder = runtime::Builder::new_multi_thread();
        match threads {
            Threads::N(n) => { builder.worker_threads(n as usize); },
            Threads::Auto => { }, // builder will detect number of cores automatically
        }
        let runtime = builder
            .build()
            .expect("Failed to create runtime");
        runtime.block_on(future).expect("Execution was terminated with error");
    };
}

/// Onion sink and stream for TCP.
struct TcpOnion {
    /// Sink for onion packets from TCP to UDP.
    tx: mpsc::Sender<(OnionRequest, SocketAddr)>,
    /// Stream of onion packets from TCP to UDP.
    rx: mpsc::Receiver<(InnerOnionResponse, SocketAddr)>,
}

/// Onion sink and stream for UDP.
struct UdpOnion {
    /// Sink for onion packets from UDP to TCP.
    tx: mpsc::Sender<(InnerOnionResponse, SocketAddr)>,
    /// Stream of onion packets from TCP to UDP.
    rx: mpsc::Receiver<(OnionRequest, SocketAddr)>,
}

/// Create onion streams for TCP and UDP servers communication.
fn create_onion_streams() -> (TcpOnion, UdpOnion) {
    let (udp_onion_tx, udp_onion_rx) = mpsc::channel(ONION_CHANNEL_SIZE);
    let (tcp_onion_tx, tcp_onion_rx) = mpsc::channel(ONION_CHANNEL_SIZE);
    let tcp_onion = TcpOnion {
        tx: tcp_onion_tx,
        rx: udp_onion_rx,
    };
    let udp_onion = UdpOnion {
        tx: udp_onion_tx,
        rx: tcp_onion_rx,
    };
    (tcp_onion, udp_onion)
}

async fn run_tcp(config: &NodeConfig, dht_sk: SecretKey, mut tcp_onion: TcpOnion, stats: Stats) -> Result<(), Error> {
    if config.tcp_addrs.is_empty() {
        // If TCP address is not specified don't start TCP server and only drop
        // all onion packets from DHT server
        while tcp_onion.rx.next().await.is_some() {}

        return Ok(())
    }

    let onion_tx = tcp_onion.tx;
    let mut onion_rx = tcp_onion.rx;

    let mut tcp_server = TcpServer::new();
    tcp_server.set_udp_onion_sink(onion_tx);

    let tcp_server_c = tcp_server.clone();
    let tcp_server_futures = config.tcp_addrs.iter().map(move |&addr| {
        let tcp_server_c = tcp_server_c.clone();
        let stats = stats.clone();
        let dht_sk = dht_sk.clone();
        async move {
            let listener = TcpListener::bind(&addr).await.expect("Failed to bind TCP listener");
            tcp_run(&tcp_server_c, listener, dht_sk, stats.clone(), config.tcp_connections_limit)
                .await
                .map_err(Error::from)
        }.boxed()
    });

    let tcp_server_future = async {
        future::select_all(tcp_server_futures)
            .await
            .0
    };

    // let tcp_onion_rx = tcp_onion.rx.clone()
    let tcp_onion_future = async {
        while let Some((onion_response, addr)) = onion_rx.next().await {
            let res = tcp_server
                .handle_udp_onion_response(addr.ip(), addr.port(), onion_response)
                .await;

            if let Err(err) = res {
                warn!("Failed to handle UDP onion response: {:?}", err);
            }
        }

        Ok(())
    };

    info!("Running TCP relay on {}", config.tcp_addrs.iter().format(","));

    futures::try_join!(tcp_server_future, tcp_onion_future)?;

    Ok(())
}

async fn run_udp(config: &NodeConfig, dht_pk: PublicKey, dht_sk: &SecretKey, mut udp_onion: UdpOnion, tcp_stats: Stats) -> Result<(), Error> {
    let udp_addr = if let Some(udp_addr) = config.udp_addr {
        udp_addr
    } else {
        // If UDP address is not specified don't start DHT server and only drop
        // all onion packets from TCP server
        while udp_onion.rx.next().await.is_some() {}

        return Ok(())
    };

    let socket = bind_socket(udp_addr).await;
    let udp_stats = Stats::new();

    // Create a channel for server to communicate with network
    let (tx, rx) = mpsc::channel(DHT_CHANNEL_SIZE);

    let tx_clone = tx.clone();
    let dht_pk_c = dht_pk.clone();
    let lan_discovery_future = async move {
        if config.lan_discovery_enabled {
            LanDiscoverySender::new(tx_clone, dht_pk_c, udp_addr.is_ipv6())
                .run()
                .map_err(Error::from)
                .await
        }
        else { Ok(()) }
    };

    let (onion_tx, mut onion_rx) = (udp_onion.tx, udp_onion.rx);

    let mut dht_server = DhtServer::new(tx, dht_pk, dht_sk.clone());
    let counters = Counters::new(tcp_stats, udp_stats.clone());
    let motd = Motd::new(config.motd.clone(), counters);
    dht_server.set_bootstrap_info(version(), Box::new(move |_| motd.format().as_bytes().to_owned()));
    dht_server.enable_lan_discovery(config.lan_discovery_enabled);
    dht_server.set_tcp_onion_sink(onion_tx);
    dht_server.enable_ipv6_mode(udp_addr.is_ipv6());

    let dht_server_c = dht_server.clone();
    let udp_onion_future = async move {
        while let Some((onion_request, addr)) = onion_rx.next().await {
            let res = dht_server_c
                .handle_tcp_onion_request(onion_request, addr)
                .await;

            if let Err(err) = res {
                warn!("Failed to handle TCP onion request: {:?}", err);
            }
        }

        Ok(())
    };

    if config.bootstrap_nodes.is_empty() {
        warn!("No bootstrap nodes!");
    }

    for node in config.bootstrap_nodes.iter().flat_map(|node| node.resolve()) {
        dht_server.add_initial_bootstrap(node);
    }

    let udp_server = UdpServer::new(dht_server);

    info!("Running DHT server on {}", udp_addr);

    let udp_server_future = dht_run_socket(&udp_server, socket, rx, udp_stats).map_err(Error::from);

    futures::try_join!(udp_server_future, lan_discovery_future, udp_onion_future)?;

    Ok(())
}

fn main() {
    let config = cli_parse();

    match config.log_type {
        LogType::Stderr => {
            let env = env_logger::Env::default()
                .filter_or("RUST_LOG", "info");
            env_logger::Builder::from_env(env)
                .init();
        },
        LogType::Stdout => {
            let env = env_logger::Env::default()
                .filter_or("RUST_LOG", "info");
            env_logger::Builder::from_env(env)
                .target(env_logger::fmt::Target::Stdout)
                .init();
        },
        #[cfg(unix)]
        LogType::Syslog => {
            syslog::init(Facility::LOG_USER, log::LevelFilter::Info, None)
                .expect("Failed to initialize syslog backend.");
        },
        LogType::None => { },
    }

    for key in config.unused.keys() {
        warn!("Unused configuration key: {:?}", key);
    }

    let (dht_pk, dht_sk) = if let Some(ref sk) = config.sk {
        (sk.public_key(), sk.clone())
    } else if let Some(ref keys_file) = config.keys_file {
        load_or_gen_keys(keys_file)
    } else {
        panic!("Neither secret key nor keys file is specified")
    };

    if config.tcp_addrs.is_empty() && config.udp_addr.is_none() {
        panic!("Both TCP addresses and UDP address are not defined.")
    }

    if config.sk_passed_as_arg {
        warn!("You should not pass the secret key via arguments due to \
               security reasons. Use the environment variable instead");
    }

    info!("DHT public key: {}", hex::encode(dht_pk.as_ref()).to_uppercase());

    let (tcp_onion, udp_onion) = create_onion_streams();

    let udp_tcp_stats = Stats::new();
    let tcp_tcp_stats = udp_tcp_stats.clone();

    let udp_config = config.clone();
    let udp_dht_sk = dht_sk.clone();
    let udp_server_future = async move {
        run_udp(&udp_config, dht_pk, &udp_dht_sk, udp_onion, udp_tcp_stats.clone()).await
    };

    let tcp_config = config.clone();
    let tcp_dht_sk = dht_sk;
    let tcp_server_future = async move {
        run_tcp(&tcp_config, tcp_dht_sk, tcp_onion, tcp_tcp_stats).await
    };

    let future = async move {
        futures::select! {
            res = udp_server_future.fuse() => res,
            res = tcp_server_future.fuse() => res,
        }
    };

    run(future, config.threads);
}
