// an example of DHT node with current code
//
#[macro_use]
extern crate log;

use std::io::{Error, ErrorKind};

use futures::future::FutureExt;
use futures::channel::mpsc;
use failure::Fail;

use std::net::SocketAddr;

use tox::toxcore::dht::server::*;
use tox::toxcore::dht::server_ext::ServerExt;
use tox::toxcore::dht::lan_discovery::*;
use tox::toxcore::dht::packed_node::PackedNode;
use tox::toxcore::crypto_core::*;
use tox::toxcore::stats::Stats;


mod common;

fn as_packed_node(pk: &str, saddr: &str) -> PackedNode {
    let pk_bytes: [u8; 32] = hex::FromHex::from_hex(pk).unwrap();
    let pk = PublicKey::from_slice(&pk_bytes).unwrap();
    let saddr: SocketAddr = saddr.parse().unwrap();

    PackedNode::new(saddr, &pk)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    if crypto_init().is_err() {
        panic!("Crypto initialization failed.");
    }

    let (server_pk, server_sk) = gen_keypair();

    // Create a channel for server to communicate with network
    let (tx, rx) = mpsc::channel(32);

    let local_addr: SocketAddr = "0.0.0.0:33445".parse()?; // 0.0.0.0 for IPv4
    // let local_addr: SocketAddr = "[::]:33445".parse().unwrap(); // [::] for IPv6

    let stats = Stats::new();

    let lan_discovery_sender =
        LanDiscoverySender::new(tx.clone(), server_pk, local_addr.is_ipv6());

    let mut server = Server::new(tx, server_pk, server_sk);
    server.set_bootstrap_info(3_000_000_000, Box::new(|_| b"This is tox-rs".to_vec()));
    server.enable_lan_discovery(true);
    server.enable_ipv6_mode(local_addr.is_ipv6());

    // Bootstrap from nodes
    for &(pk, saddr) in &common::BOOTSTRAP_NODES {
        let bootstrap_pn = as_packed_node(pk, saddr);

        server.add_initial_bootstrap(bootstrap_pn);
    }

    let future = async move {
        let socket = common::bind_socket(local_addr).await;
        let server_fut = server.run_socket(socket, rx, stats)
            .boxed();
        let res =
            futures::select! {
                res = server_fut.fuse() => res,
                res = lan_discovery_sender.run().fuse() =>
                    res.map_err(|e| Error::new(ErrorKind::Other, e.compat()))
            };

        if let Err(ref e) = res {
            error!("Processing ended with error: {:?}", e)
        }

        res
    };

    info!("Running DHT server on {}", local_addr);

    let mut runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(future)?;

    Ok(())
}
