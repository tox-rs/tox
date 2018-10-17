extern crate tox;
extern crate futures;
extern crate tokio;
extern crate tokio_codec;
extern crate env_logger;
extern crate failure;

use tox::toxcore::crypto_core::{PublicKey, SecretKey};
use tox::toxcore::tcp::packet::*;
use tox::toxcore::tcp::connections::*;

use futures::{Future, Sink, Stream};

use failure::{Error};

fn main() {
    env_logger::init();

    // Use `gen_keypair` to generate random keys
    // Client constant keypair for examples/tests
    let client_pk = PublicKey([252, 72, 40, 127, 213, 13, 0, 95,
        13, 230, 176, 49, 69, 252, 220, 132,
        48, 73, 227, 58, 218, 154, 215, 245,
        23, 189, 223, 216, 153, 237, 130, 88]);
    let client_sk = SecretKey([157, 128, 29, 197, 1, 72, 47, 56,
        65, 81, 191, 67, 220, 225, 108, 193,
        46, 163, 145, 242, 139, 125, 159,
        137, 174, 14, 225, 7, 138, 120, 185, 153]);

    // local tcp relay server from example
    let addr = "0.0.0.0:12345".parse().unwrap();
    // Server constant PK for examples/tests
    let server_pk = PublicKey([177, 185, 54, 250, 10, 168, 174,
        148, 0, 93, 99, 13, 131, 131, 239,
        193, 129, 141, 80, 158, 50, 133, 100,
        182, 179, 183, 234, 116, 142, 102, 53, 38]);

    let connections = Connections::new(client_pk.clone(), client_sk.clone());

    // Create ConnectionsProcessor
    let ConnectionsProcessor {
        from_net_crypto_tx,
        to_net_crypto_rx,
        from_server_tx,
        to_server_rx,
        processor
    } = ConnectionsProcessor::new();

    let add_relay = connections.add_relay(&addr, &server_pk, from_server_tx)
        .map_err(Error::from);

    let network_writer = to_server_rx
        .map_err(|()| unreachable!("rx can't fail"))
        .for_each(move |(packet, _connection_id)| {
            connections.send_packet(&server_pk, packet)
        })
        .map(|_| ());

    // Read incoming messages
    let incomings = to_net_crypto_rx
        .map_err(|()| unreachable!("rx can't fail"))
        .for_each(|packet| {
            println!("Got packet: {:?}", packet);
            // We may send something to server using `from_client_tx`
            //  but for now we do nothing
            Ok(())
        })
        .map(|_| ());

    let processor = processor
        .map_err(Error::from)
        .join(add_relay)
        .map(|_| ());

    // Combine network with incomings
    let net_crypto = processor
        .map_err(Error::from)
        .select(network_writer)
        .map(|_| ())
        .map_err(|(e,_)| e)
        .select(incomings)
        .map(|_| ())
        .map_err(|(_e,_)| ());

    {
        // Send RouteRequest to server
        let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
            192, 117, 0, 225, 119, 43, 48, 117,
            84, 109, 112, 57, 243, 216, 4, 171,
            185, 111, 33, 146, 221, 31, 77, 118]);

        from_net_crypto_tx.clone().send((OutgoingPacket::RouteRequest(
            RouteRequest { pk: friend_pk }
        ), server_pk)).wait().unwrap();
    }

    // Connect to server and wait for incoming packets.
    // Ping/Pong will be sent automatically
    tokio::run(net_crypto);
}
