//! This is a standalone DHT node example that doesn't require already running other nodes.
//!
//! Just spawn the first node with no arguments:
//!
//! ```
//! cargo run --example dht_node
//! ```
//!
//! It will print node's listening port and public key. Use this info to spawn subsequent nodes
//! and connect them together:
//!
//! ```
//! cargo run --example dht_node -- --node-addr 127.0.0.1:54708 \
//!    --pub-key 9680D026A24F87B6776E2E3A79A1459ACD94DFF921C2202D2FCF19AABE07A81
//! ```

#[macro_use]
extern crate log;
#[macro_use]
extern crate unwrap;

use clap::{Arg, App};
use hex::{self, FromHex};
use futures::*;
use futures::sync::mpsc;
use tokio::net::UdpSocket;
use tokio::runtime::current_thread::Runtime;

use std::net::SocketAddr;

use tox::toxcore::dht::packed_node::PackedNode;
use tox::toxcore::dht::server::*;
use tox::toxcore::dht::server_ext::ServerExt;
use tox::toxcore::crypto_core::*;
use tox::toxcore::stats::Stats;

type BoxFuture<T, E> = Box<Future<Item = T, Error = E>>;

#[derive(Debug)]
struct Args {
    node_info: Option<PackedNode>,
}

fn main() {
    env_logger::init();

    let args = match parse_cli_args() {
        Ok(args) => args,
        Err(e) => e.exit(),
    };

    if crypto_init().is_err() {
        panic!("Crypto initialization failed.");
    }

    let local_addr: SocketAddr = unwrap!("0.0.0.0:0".parse());
    let socket = bind_socket(local_addr);
    let stats = Stats::new();

    let (our_pk, our_sk) = gen_keypair();
    println!("Our public key: {:?}", hex::encode_upper(our_pk.0));
    let local_addr = unwrap!(socket.local_addr());
    println!("Our address: {}", local_addr);

    // Create a channel for server to communicate with network
    let (tx, rx) = mpsc::channel(32);
    let server = Server::new(tx, our_pk, our_sk);

    let try_connect_with_node: BoxFuture<(), ()> = if let Some(ref node_info) = args.node_info {
        Box::new(server.send_ping_req(node_info, &mut server.request_queue.write())
            .map_err(|e| {
                error!("Failed to send ping request: {}", e);
                ()
            }))
    } else {
        Box::new(future::ok(()))
    };

    let future = server.run_socket(socket, rx, stats)
        .map_err(|err| {
            error!("Processing ended with error: {:?}", err);
            ()
        }).join(try_connect_with_node)
        .map(|_| ());

    info!("Running DHT server on {}", local_addr);
    let mut evloop = unwrap!(Runtime::new());
    unwrap!(evloop.block_on(future));
}

fn parse_cli_args() -> Result<Args, clap::Error> {
    let matches = App::new("DHT node used to form a P2P network")
        .about("DHT node that can be run as the very first node others will bootstrap off or try \
               to connect with already running nodes. If you want to run the first network node,
               don't specify node address and public key."
        ).arg(
            Arg::with_name("node-addr")
                .long("node-addr")
                .value_name("ADDR")
                .help("Node socket address: IP:port")
                .takes_value(true),
        ).arg(
            Arg::with_name("pub-key")
                .long("pub-key")
                .value_name("KEY")
                .help("Node public key in hex format.")
                .takes_value(true)
        ).get_matches();

    let node_info = match matches.value_of("node-addr") {
        Some(addr) => {
            let addr = unwrap!(addr.parse());
            let pub_key = matches
                .value_of("pub-key")
                .map(|hex_pk| {
                    let pk_bytes: [u8; 32] = unwrap!(FromHex::from_hex(hex_pk));
                    unwrap!(PublicKey::from_slice(&pk_bytes))
                })
                .ok_or_else(|| {
                    clap::Error::with_description(
                        "If node address is given, public key must be present too.",
                        clap::ErrorKind::EmptyValue,
                    )
                })?;
            Some(PackedNode::new(addr, &pub_key))
        }
        None => None,
    };
    Ok(Args { node_info })
}

/// Bind a UDP listener to the socket address.
fn bind_socket(addr: SocketAddr) -> UdpSocket {
    let socket = UdpSocket::bind(&addr).expect("Failed to bind UDP socket");
    socket.set_broadcast(true).expect("set_broadcast call failed");
    socket
}
