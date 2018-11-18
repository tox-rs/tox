extern crate tox;
extern crate futures;
extern crate tokio;
extern crate tokio_codec;
extern crate env_logger;
extern crate failure;

use tox::toxcore::crypto_core::{PublicKey, SecretKey};
use tox::toxcore::tcp::packet::*;
use tox::toxcore::tcp::handshake::make_client_handshake;
use tox::toxcore::tcp::codec;
use tox::toxcore::tcp::client::*;

use failure::{Error, err_msg};
use futures::{Future, Sink, Stream};

use tokio_codec::Framed;
use tokio::net::TcpStream;

fn main() {
    env_logger::init();

    // Use `gen_keypair` to generate random keys
    // Client constant keypair for examples/tests
    let client_pk = PublicKey([
        252, 72, 40, 127, 213, 13, 0, 95,
        13, 230, 176, 49, 69, 252, 220, 132,
        48, 73, 227, 58, 218, 154, 215, 245,
        23, 189, 223, 216, 153, 237, 130, 88
    ]);
    let client_sk = SecretKey([
        157, 128, 29, 197, 1, 72, 47, 56,
        65, 81, 191, 67, 220, 225, 108, 193,
        46, 163, 145, 242, 139, 125, 159,
        137, 174, 14, 225, 7, 138, 120, 185, 153
    ]);

    // local tcp relay server from example
    let addr = "0.0.0.0:12345".parse().unwrap();
    // Server constant PK for examples/tests
    let server_pk = PublicKey([
        177, 185, 54, 250, 10, 168, 174,
        148, 0, 93, 99, 13, 131, 131, 239,
        193, 129, 141, 80, 158, 50, 133, 100,
        182, 179, 183, 234, 116, 142, 102, 53, 38
    ]);

    // Create ClientProcessor
    let ClientProcessor {
        from_client_tx,
        to_client_rx,
        from_server_tx,
        to_server_rx,
        processor
    } = ClientProcessor::new();

    // Initialize network communication
    let network = TcpStream::connect(&addr)
        .map_err(Error::from)
        .and_then(move |socket| {
            make_client_handshake(socket, &client_pk, &client_sk, &server_pk)
                .map_err(Error::from)
        })
        .and_then(|(socket, channel)| {
            let secure_socket = Framed::new(socket, codec::Codec::new(channel));
            let (to_server, from_server) = secure_socket.split();

            let writer = to_server_rx
                .map_err(|()| unreachable!("rx can't fail"))
                .forward(to_server)
                .map(|_| ());

            let reader = from_server
                .map_err(Error::from)
                .forward(from_server_tx
                    .sink_map_err(|e| {
                        err_msg(format!("Could not forward message from server to connection {:?}", e))
                    })
                )
                .map(|_| {
                    println!("Connection closed");
                });

            let network = reader.select(writer).map(|_| ()).map_err(|(err, _select_next)| err);

            processor
                .map_err(Error::from)
                .select(network).map_err(|(err, _select_next)| err)
        })
        .map(|_| ());

    // Read incoming messages
    let incomings = to_client_rx
        .map_err(|()| unreachable!("rx can't fail"))
        .for_each(|packet| {
            println!("Got packet: {:?}", packet);
            // We may send something to server using `from_client_tx`
            //  but for now we do nothing
            Ok(())
        })
        .map(|_| ());

    // Combine network with incomings
    let client = network.select(incomings)
        .map(|_| ())
        .map_err(|(err, _select_next)| {
            println!("Error: {:?}", err);
        });

    {
        // Send RouteRequest to server
        let friend_pk = PublicKey([
            15, 107, 126, 130, 81, 55, 154, 157,
            192, 117, 0, 225, 119, 43, 48, 117,
            84, 109, 112, 57, 243, 216, 4, 171,
            185, 111, 33, 146, 221, 31, 77, 118
        ]);

        from_client_tx.clone().send(OutgoingPacket::RouteRequest(
            RouteRequest { pk: friend_pk }
        )).wait().unwrap();
    }

    // Connect to server and wait for incoming packets.
    // Ping/Pong will be sent automatically
    tokio::run( client );
}
