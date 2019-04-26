#[macro_use]
extern crate log;

use std::net::{SocketAddr, IpAddr};

use failure::Error;
use futures::*;
use futures::sync::mpsc;
use hex::FromHex;
use tokio::net::{UdpSocket, UdpFramed};

use tox::toxcore::dht::codec::*;
use tox::toxcore::dht::packed_node::*;
use tox::toxcore::dht::packet::*;
use tox::toxcore::dht::server::Server;
use tox::toxcore::crypto_core::*;
use tox::toxcore::onion::client::*;
use tox::toxcore::tcp::client::Connections;
use tox::toxcore::stats::Stats;

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

const SELF_SK: &str = "1A5EC1D6C3F1FA720A313C01F432B6AE0D4649A5121964C9992DDF32871E8DFD";

const FRIEND_PK: &str = "3E6A06DA48D1AB98549AD76890770B704AE9116D8654FBCD35C9BF2DB9233E21";

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
    env_logger::init();

    let (dht_pk, dht_sk) = gen_keypair();

    let real_sk_bytes: [u8; 32] = FromHex::from_hex(SELF_SK).unwrap();
    let real_sk = SecretKey::from_slice(&real_sk_bytes).unwrap();
    let real_pk = real_sk.public_key();

    // Create a channel for server to communicate with network
    let (tx, rx) = mpsc::channel(32);

    let local_addr: SocketAddr = "0.0.0.0:33445".parse().unwrap(); // 0.0.0.0 for IPv4
    // let local_addr: SocketAddr = "[::]:33445".parse().unwrap(); // [::] for IPv6

    let socket = bind_socket(local_addr);

    let (dht_pk_tx, dht_pk_rx) = mpsc::unbounded();

    let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();

    let dht_server = Server::new(tx.clone(), dht_pk, dht_sk.clone());
    let tcp_connections = Connections::new(dht_pk, dht_sk, tcp_incoming_tx);
    let onion_client = OnionClient::new(dht_server, tcp_connections, dht_pk_tx, real_sk, real_pk);

    for &(pk, saddr) in &BOOTSTRAP_NODES {
        // get PK bytes of the bootstrap node
        let bootstrap_pk_bytes: [u8; 32] = FromHex::from_hex(pk).unwrap();
        // create PK from bytes
        let bootstrap_pk = PublicKey::from_slice(&bootstrap_pk_bytes).unwrap();

        let node = PackedNode::new(saddr.parse().unwrap(), &bootstrap_pk);

        onion_client.add_path_node(node);
    }

    let friend_pk_bytes: [u8; 32] = FromHex::from_hex(FRIEND_PK).unwrap();
    let friend_pk = PublicKey::from_slice(&friend_pk_bytes).unwrap();

    onion_client.add_friend(friend_pk);

    let stats = Stats::new();
    let codec = DhtCodec::new(stats);
    let (sink, stream) = UdpFramed::new(socket, codec).split();

    let onion_client_c = onion_client.clone();

    let network_reader = stream.then(future::ok).filter(|event|
        match event {
            Ok(_) => true,
            Err(ref e) => {
                error!("packet receive error = {:?}", e);
                // ignore packet decode errors
                *e.kind() == DecodeErrorKind::Io
            }
        }
    ).and_then(|event| event).for_each(move |(packet, addr)| {
        trace!("Received packet {:?}", packet);
        match packet {
            Packet::OnionAnnounceResponse(packet) => {
                Box::new(onion_client_c.handle_announce_response(&packet, addr).map_err(Error::from))
                    as Box<dyn Future<Item = _, Error = _> + Send>
            },
            Packet::OnionDataResponse(packet) => {
                Box::new(onion_client_c.handle_data_response(&packet).map_err(Error::from))
            },
            _ => Box::new(future::ok(())),
        }.or_else(|err| {
            error!("Failed to handle packet: {:?}", err);
            future::ok(())
        })
    }).map_err(Error::from);

    let network_writer = rx
        .map_err(|()| unreachable!("rx can't fail"))
        // filter out IPv6 packets if node is running in IPv4 mode
        .filter(move |&(ref _packet, addr)| !(local_addr.is_ipv4() && addr.is_ipv6()))
        .fold(sink, move |sink, (packet, mut addr)| {
            if local_addr.is_ipv6() {
                if let IpAddr::V4(ip) = addr.ip() {
                    addr = SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), addr.port());
                }
            }
            trace!("Sending packet {:?} to {:?}", packet, addr);
            sink.send((packet, addr)).map_err(Error::from)
        })
        // drop sink when rx stream is exhausted
        .map(|_sink| ());

    let dht_pk_future = dht_pk_rx
        .map_err(|()| unreachable!("rx can't fail"))
        .for_each(|(real_pk, dht_pk)| {
            println!("Found DHT PK for {} - {}", hex::encode(real_pk.as_ref()), hex::encode(dht_pk));
            future::ok(())
        });

    let future = network_reader
        .select(network_writer)
        .map(|_| ())
        .map_err(|(e, _)| e)
        .select(onion_client.run().map_err(Error::from))
        .map(|_| ())
        .map_err(|(e, _)| e)
        .select(dht_pk_future)
        .map(|_| ())
        .map_err(|(e, _)| error!("Processing ended with error: {:?}", e));

    info!("Running onion client on {}", local_addr);

    tokio::run(future);
}
