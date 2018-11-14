// an example of DHT node with current code
//
extern crate tox;
extern crate failure;
extern crate futures;
extern crate tokio;
extern crate hex;

//#[macro_use]
extern crate log;
extern crate env_logger;
/*
use futures::*;
use futures::sync::mpsc;
use hex::FromHex;
use tokio::net::{UdpSocket, UdpFramed};

use std::net::{SocketAddr, IpAddr};
use std::io::{ErrorKind, Error};

use tox::toxcore::dht::codec::*;
use tox::toxcore::dht::server::*;
use tox::toxcore::dht::packed_node::*;
use tox::toxcore::dht::lan_discovery::*;
use tox::toxcore::crypto_core::*;

const BOOTSTRAP_NODES: [(&str, &str); 9] = [
    // Impyy
    ("1D5A5F2F5D6233058BF0259B09622FB40B482E4FA0931EB8FD3AB8E7BF7DAF6F", "198.98.51.198:33445"),
    // nurupo
    ("F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67", "67.215.253.85:33445"),
    // Manolis
    ("461FA3776EF0FA655F1A05477DF1B3B614F7D6B124F7DB1DD4FE3C08B03B640F", "130.133.110.14:33445"),
    // Busindre
    ("A179B09749AC826FF01F37A9613F6B57118AE014D4196A0E1105A98F93A54702", "205.185.116.116:33445"),
    // ray65536
    ("8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832", "85.172.30.117:33445"),
    // fluke571
    ("3CEE1F054081E7A011234883BC4FC39F661A55B73637A5AC293DDF1251D9432B", "194.249.212.109:33445"),
    // MAH69K
    ("DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43", "185.25.116.107:33445"),
    // clearmartin
    ("CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707", "46.101.197.175:443"),
    // tastytea
    ("2B2137E094F743AC8BD44652C55F41DFACC502F125E99E4FE24D40537489E32F", "5.189.176.217:5190"),
];

/// Bind a UDP listener to the socket address.
fn bind_socket(addr: SocketAddr) -> UdpSocket {
    let socket = UdpSocket::bind(&addr).expect("Failed to bind UDP socket");
    socket.set_broadcast(true).expect("set_broadcast call failed");
    if addr.is_ipv6() {
        socket.set_multicast_loop_v6(true).expect("set_multicast_loop_v6 call failed");
    }
    socket
}
*/
fn main() {
    /*
    env_logger::init();

    if !crypto_init() {
        panic!("Crypto initialization failed.");
    }

    let (server_pk, server_sk) = gen_keypair();

    // Create a channel for server to communicate with network
    let (tx, rx) = mpsc::unbounded();

    let local_addr: SocketAddr = "0.0.0.0:33445".parse().unwrap(); // 0.0.0.0 for IPv4
    // let local_addr: SocketAddr = "[::]:33445".parse().unwrap(); // [::] for IPv6

    let socket = bind_socket(local_addr);
    let (sink, stream) = UdpFramed::new(socket, DhtCodec).split();

    let lan_discovery_sender = LanDiscoverySender::new(tx.clone(), server_pk, local_addr.is_ipv6());

    let mut server = Server::new(tx, server_pk, server_sk);
    server.set_bootstrap_info(07032018, Box::new(|_| "This is tox-rs".as_bytes().to_owned()));
    server.enable_lan_discovery(true);
    server.enable_ipv6_mode(local_addr.is_ipv6());

    // Bootstrap from nodes
    for &(pk, saddr) in &BOOTSTRAP_NODES {
        // get PK bytes of the bootstrap node
        let bootstrap_pk_bytes: [u8; 32] = FromHex::from_hex(pk).unwrap();
        // create PK from bytes
        let bootstrap_pk = PublicKey::from_slice(&bootstrap_pk_bytes).unwrap();

        let saddr: SocketAddr = saddr.parse().unwrap();
        let bootstrap_pn = PackedNode::new(saddr, &bootstrap_pk);
        server.add_initial_bootstrap(bootstrap_pn);
    }

    // The server task asynchronously iterates over and processes each
    // incoming packet.
    let server_c = server.clone();
    let network_reader = stream.then(future::ok).filter(|event| // TODO: use filter_map from futures 0.2 to avoid next `expect`
        match event {
            Ok(_) => true,
            Err(ref e) => {
                error!("packet receive error = {:?}", e);
                // ignore packet decode errors
                e.as_fail().downcast_ref::<DecodeError>().is_none()
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

    let future = network_reader
        .select(network_writer).map(|_| ()).map_err(|(e, _)| e)
        .select(server.run()).map(|_| ()).map_err(|(e, _)| e)
        .select(lan_discovery_sender.run()).map(|_| ()).map_err(|(e, _)| e)
        .map_err(|err| {
            error!("Processing ended with error: {:?}", err);
            ()
        });

    info!("Running DHT server on {}", local_addr);

    tokio::run(future);
    */
}
