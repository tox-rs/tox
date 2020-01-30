#[macro_use]
extern crate log;

use std::net::{SocketAddr, IpAddr};

use failure::Error;
use futures::future::{FutureExt};
use futures::stream::{StreamExt};
use futures::sink::SinkExt;
use futures::channel::mpsc;
use tokio_util::udp::UdpFramed;

use tox::toxcore::dht::codec::*;
use tox::toxcore::dht::ip_port::IsGlobal;
use tox::toxcore::dht::packet::*;
use tox::toxcore::dht::server::Server;
use tox::toxcore::dht::packed_node::PackedNode;
use tox::toxcore::crypto_core::*;
use tox::toxcore::onion::client::*;
use tox::toxcore::tcp::client::Connections;
use tox::toxcore::stats::Stats;

mod common;

const SELF_SK: &str = "1A5EC1D6C3F1FA720A313C01F432B6AE0D4649A5121964C9992DDF32871E8DFD";
const FRIEND_PK: &str = "3E6A06DA48D1AB98549AD76890770B704AE9116D8654FBCD35C9BF2DB9233E21";

fn as_packed_node(pk: &str, saddr: &str) -> PackedNode {
    let pk_bytes: [u8; 32] = hex::FromHex::from_hex(pk).unwrap();
    let pk = PublicKey::from_slice(&pk_bytes).unwrap();
    let saddr: SocketAddr = saddr.parse().unwrap();

    PackedNode::new(saddr, &pk)
}

fn load_keypair() -> (PublicKey, SecretKey) {
    use hex::FromHex;

    let real_sk_bytes: [u8; 32] = FromHex::from_hex(SELF_SK).unwrap();
    let real_sk = SecretKey::from_slice(&real_sk_bytes).unwrap();
    let real_pk = real_sk.public_key();

    (real_pk, real_sk)
}

async fn main_task(
    local_addr: SocketAddr,
    onion_client: OnionClient,
    mut net_rx: mpsc::Receiver<(tox::toxcore::dht::packet::Packet, SocketAddr)>,
    dht_pk_rx: mpsc::UnboundedReceiver<(PublicKey, tox::toxcore::crypto_core::curve25519xsalsa20poly1305::PublicKey)>,
) {
    let is_ipv4 = local_addr.is_ipv4();
    let socket = common::bind_socket(local_addr).await;
    let stats = Stats::new();
    let codec = DhtCodec::new(stats);

    let (mut sink, mut stream) = UdpFramed::new(socket, codec).split();

    let client = onion_client.clone();
    let network_reader = async move {
        while let Some(event) = stream.next().await {
            let (packet, addr) = match event {
                Ok(ev) => ev,
                Err(ref e) => {
                    error!("packet receive error = {:?}", e);

                    if *e.kind() == DecodeErrorKind::Io { continue }
                    else { unimplemented!() }
                }
            };

            trace!("Received packet {:?}", packet);

            let res = match packet {
                Packet::OnionAnnounceResponse(packet) => {
                    let is_global = IsGlobal::is_global(&addr.ip());

                    client.handle_announce_response(&packet, is_global).await
                        .map_err(Error::from)
                },
                Packet::OnionDataResponse(packet) =>
                    client.handle_data_response(&packet).await
                        .map_err(Error::from),
                _ => Ok(()),
            };

            if let Err(err) = res {
                error!("Failed to handle packet: {:?}", err);

                return Err(err)
            }
        }

        Ok(())
    };

    let network_writer = async move {
        while let Some((packet, mut addr)) = net_rx.next().await {
            if is_ipv4 && addr.is_ipv6() { continue }

            if !is_ipv4 {
                if let IpAddr::V4(ip) = addr.ip() {
                    addr = SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), addr.port());
                }
            }

            trace!("Sending packet {:?} to {:?}", packet, addr);
            sink.send((packet, addr)).await
                .map_err(Error::from)?
        }

        Ok(())
    };

    let dht_pk_future = dht_pk_rx
        .for_each(|(real_pk, dht_pk)| {
            let real_pk = hex::encode(real_pk.as_ref());
            let dht_pk = hex::encode(dht_pk);

            println!("Found DHT PK for {} - {}", real_pk, dht_pk);

            futures::future::ready(())
        });

    let res = futures::select! {
        res = network_reader.fuse() => res,
        res = network_writer.fuse() => res,
        res = onion_client.run().fuse() =>
            res.map_err(Error::from),
        res = dht_pk_future.fuse() => Ok(res),
    };

    if let Err(ref e) = res {
        error!("Processing ended with error: {:?}", e);
    }
}

fn main() {
    env_logger::init();

    let (dht_pk, dht_sk) = gen_keypair();
    let (real_pk, real_sk) = load_keypair();

    // Create a channel for server to communicate with network
    let (tx, rx) = mpsc::channel(32);

    let local_addr: SocketAddr = "0.0.0.0:33445".parse().unwrap(); // 0.0.0.0 for IPv4
    // let local_addr: SocketAddr = "[::]:33445".parse().unwrap(); // [::] for IPv6

    let (dht_pk_tx, dht_pk_rx) = mpsc::unbounded();
    let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();

    let dht_server = Server::new(tx.clone(), dht_pk, dht_sk.clone());
    let tcp_connections = Connections::new(dht_pk, dht_sk, tcp_incoming_tx);
    let onion_client = OnionClient::new(dht_server, tcp_connections, real_sk, real_pk);

    onion_client.set_dht_pk_sink(dht_pk_tx);

    for &(pk, saddr) in &common::BOOTSTRAP_NODES {
        let node = as_packed_node(pk, saddr);

        onion_client.add_path_node(node);
    }

    let friend_pk_bytes: [u8; 32] = hex::FromHex::from_hex(FRIEND_PK).unwrap();
    let friend_pk = PublicKey::from_slice(&friend_pk_bytes).unwrap();

    onion_client.add_friend(friend_pk);

    info!("Running onion client on {}", local_addr);
    let main_fut = main_task(local_addr, onion_client, rx, dht_pk_rx);

    let mut runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(main_fut);
}
