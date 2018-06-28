#[macro_use]
extern crate clap;
extern crate env_logger;
extern crate failure;
extern crate futures;
extern crate hex;
extern crate itertools;
#[macro_use]
extern crate log;
extern crate tokio;
extern crate tox;

use std::io::{Error, ErrorKind};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use clap::{Arg, App};
use futures::sync::mpsc;
use futures::{future, Future, Sink, Stream};
use hex::FromHex;
use itertools::Itertools;
use log::LevelFilter;
use tokio::net::{UdpSocket, UdpFramed};
use tox::toxcore::crypto_core::*;
use tox::toxcore::dht::codec::{DecodeError, DhtCodec};
use tox::toxcore::dht::packed_node::PackedNode;
use tox::toxcore::dht::server::Server;
use tox::toxcore::dht::lan_discovery::LanDiscoverySender;

/// Config parsed from command line arguments.
#[derive(Clone, PartialEq, Eq, Debug)]
struct CliConfig {
    /// List of bootstrap nodes.
    bootstrap_nodes: Vec<PackedNode>,
}

/// Parse command line arguments.
fn cli_parse() -> CliConfig {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .arg(Arg::with_name("bootstrap-node")
            .short("b")
            .long("bootstrap-node")
            .help("Node to perform initial bootstrap")
            .multiple(true)
            .takes_value(true)
            .number_of_values(2)
            .value_names(&["public key", "address"]))
        .get_matches();

    let bootstrap_nodes = matches
        .values_of("bootstrap-node")
        .into_iter()
        .flat_map(|values| values)
        .tuples()
        .map(|(pk, saddr)| {
            // get PK bytes of the bootstrap node
            let bootstrap_pk_bytes: [u8; 32] = FromHex::from_hex(pk).expect("Invalid node key");
            // create PK from bytes
            let bootstrap_pk = PublicKey::from_slice(&bootstrap_pk_bytes).expect("Invalid node key");

            let saddr = saddr
                .to_socket_addrs()
                .expect("Invalid node address")
                .next()
                .expect("Invalid node address");
            PackedNode::new(true, saddr, &bootstrap_pk)
        })
        .collect();

    CliConfig {
        bootstrap_nodes
    }
}

/// Bind a UDP listener to the socket address.
fn bind_socket(addr: SocketAddr) -> UdpSocket {
    let socket = UdpSocket::bind(&addr).expect("Failed to bind UDP socket");
    socket.set_broadcast(true).expect("set_broadcast call failed");
    if addr.is_ipv6() {
        socket.set_multicast_loop_v6(true).expect("set_multicast_loop_v6 call failed");
    }
    socket
}

fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(LevelFilter::Info)
        .init();

    if !crypto_init() {
        panic!("Crypto initialization failed.");
    }

    let cli_config = cli_parse();

    let local_addr: SocketAddr = "0.0.0.0:33445".parse().unwrap(); // 0.0.0.0 for ipv4
    // let local_addr: SocketAddr = "[::]:33445".parse().unwrap(); // [::] for ipv6

    let socket = bind_socket(local_addr);
    let (sink, stream) = UdpFramed::new(socket, DhtCodec).split();

    let (dht_pk, dht_sk) = gen_keypair();

    // Create a channel for server to communicate with network
    let (tx, rx) = mpsc::unbounded();

    let lan_discovery_sender = LanDiscoverySender::new(tx.clone(), dht_pk, local_addr.is_ipv6());

    let mut server = Server::new(tx, dht_pk, dht_sk);
    server.set_bootstrap_info(07032018, b"This is tox-rs".to_vec());

    for node in cli_config.bootstrap_nodes {
        assert!(server.try_add_to_close_nodes(&node));
    }

    // The server task asynchronously iterates over and processes each
    // incoming packet.
    let server_c = server.clone();
    let network_reader = stream.then(future::ok).filter(|event| // TODO: use filter_map from futures 0.2 to avoid next `expect`
        match event {
            &Ok(_) => true,
            &Err(ref e) => {
                error!("packet receive error = {:?}", e);
                // ignore packet decode errors
                e.cause().downcast_ref::<DecodeError>().is_none()
            }
        }
    ).then(|event: Result<_, ()>|
        event.expect("always ok")
    ).for_each(move |(packet, addr)| {
        trace!("Received packet {:?}", packet);
        server_c.handle_packet(packet, addr).or_else(|err| {
            error!("Failed to handle packet: {:?}", err);
            future::ok(())
        })
    }).map_err(|e| Error::new(ErrorKind::Other, e.compat()));

    let network_writer = rx
        .map_err(|()| Error::new(ErrorKind::Other, "rx error"))
        // filter out IPv6 packets if node is running in IPv4 mode
        .filter(move |&(ref _packet, addr)| !(local_addr.is_ipv4() && addr.is_ipv6()))
        .fold(sink, move |sink, (packet, mut addr)| {
            if local_addr.is_ipv6() {
                if let IpAddr::V4(ip) = addr.ip() {
                    addr = SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), addr.port());
                }
            }
            trace!("Sending packet {:?} to {:?}", packet, addr);
            sink.send((packet, addr)).map_err(|e| Error::new(ErrorKind::Other, e.compat()))
        })
        // drop sink when rx stream is exhausted
        .map(|_sink| ());

    let future = network_writer.select(network_reader).map(|_| ()).map_err(|(e, _)| e);
    let future = future.select(server.run()).map(|_| ()).map_err(|(e, _)| e);
    let future = future.select(lan_discovery_sender.run()).map(|_| ()).map_err(|(e, _)| e);
    let future = future.map_err(|err| {
        error!("Processing ended with error: {:?}", err);
        ()
    });

    info!("Running server on {}", local_addr);
    tokio::run(future);
}
