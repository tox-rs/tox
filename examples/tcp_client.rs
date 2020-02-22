#[macro_use]
extern crate log;

use tox::toxcore::crypto_core::*;
use tox::toxcore::dht::packet::CryptoData;
use tox::toxcore::tcp::connection_id::ConnectionId;
use tox::toxcore::tcp::packet::*;
use tox::toxcore::tcp::handshake::make_client_handshake;
use tox::toxcore::tcp::codec;
use tox::toxcore::stats::Stats;

use failure::{Error, err_msg};

use hex::FromHex;

use futures::prelude::*;
use futures::future;
use futures::channel::mpsc;

use tokio_util::codec::Framed;
use tokio::net::TcpStream;

// Notice that create_client create a future of client processing.
//  The future will live untill all copies of tx is dropped or there is a IO error
//  Since we pass a copy of tx as arg (to send PongResponses), the client will live untill IO error
//  Comment out pong responser and client will be destroyed when there will be no messages to send
async fn create_client(mut rx: mpsc::Receiver<Packet>, tx: mpsc::Sender<Packet>) -> Result<(), Error> {
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

    let (addr, server_pk) = match 1 {
        1 => {
            // local tcp relay server from example
            let addr: std::net::SocketAddr = "0.0.0.0:12345".parse().unwrap();
            // Server constant PK for examples/tests
            let server_pk = PublicKey([177, 185, 54, 250, 10, 168, 174,
                                    148, 0, 93, 99, 13, 131, 131, 239,
                                    193, 129, 141, 80, 158, 50, 133, 100,
                                    182, 179, 183, 234, 116, 142, 102, 53, 38]);
            (addr, server_pk)
        },
        2 => {
            // remote tcp relay server
            let server_pk_bytes: [u8; 32] = FromHex::from_hex("461FA3776EF0FA655F1A05477DF1B3B614F7D6B124F7DB1DD4FE3C08B03B640F").unwrap();
            let server_pk = PublicKey::from_slice(&server_pk_bytes).unwrap();
            let addr = "130.133.110.14:33445".parse().unwrap();
            (addr, server_pk)
        },
        3 => {
            // local C DHT node, TODO remove this case
            let server_pk_bytes: [u8; 32] = FromHex::from_hex("C4B8D288C391704E3C8840A8A7C19B21D0B76CAF3B55341D37C5A9732887F879").unwrap();
            let server_pk = PublicKey::from_slice(&server_pk_bytes).unwrap();
            let addr = "0.0.0.0:33445".parse().unwrap();
            (addr, server_pk)
        }
        _ => {
            unreachable!()
        }
    };

    let stats = Stats::new();

    let socket = TcpStream::connect(&addr).await?;
    let (socket, channel) = make_client_handshake(socket, &client_pk, &client_sk, &server_pk).await?;
    debug!("Handshake complited");
    let secure_socket = Framed::new(socket, codec::Codec::new(channel, stats));
    let (mut to_server, mut from_server) = secure_socket.split();

    let reader = async {
        while let Some(packet) = from_server.next().await {
            let packet = packet?;
            debug!("Got packet {:?}", packet);
            // Simple pong responser
            if let Packet::PingRequest(ping) = packet {
                tx.clone().send(Packet::PongResponse(
                    PongResponse { ping_id: ping.ping_id }
                ))
                .map_err(|_| err_msg("Could not send pong") )
                .await?;
            }
        }
        Ok(())
    };
    let reader = reader.inspect(|res| println!("Reader ended with {:?}", res));

    let writer = async {
        while let Some(packet) = rx.next().await {
            debug!("Send packet {:?}", packet);
            to_server.send(packet).await?;
        }
        Ok(())
    };
    let writer = writer.inspect(|res| println!("Writer ended with {:?}", res));

    futures::try_join!(reader, writer).map(drop)
}

fn main() {
    env_logger::init();

    let (mut tx, rx) = mpsc::channel(1);

    let client = create_client(rx, tx.clone())
        .inspect(|res| println!("Client ended with {:?}", res));

    let packet_sender = async {
        let mut i = 0u64;
        while i < 1000000 {
            if i % 10000 == 0 {
                println!("i = {}", i);
            }
            i += 1;
            if i == 1 {
                // Client friend constant PK for examples/tests
                let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
                                        192, 117, 0, 225, 119, 43, 48, 117,
                                        84, 109, 112, 57, 243, 216, 4, 171,
                                        185, 111, 33, 146, 221, 31, 77, 118]);
                tx.send(Packet::RouteRequest(RouteRequest { pk: friend_pk } )).await?;
            } else {
                tx.send(Packet::Data(Data {
                    connection_id: ConnectionId::from_index(0),
                    data: DataPayload::CryptoData(CryptoData {
                        nonce_last_bytes: 42,
                        payload: vec![42; 123],
                    }),
                })).await?;
            }
        }
        Result::<(), Error>::Ok(())
    };

    let client = future::try_select(client.boxed(), packet_sender.boxed());

    let mut runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(client).map_err(|e| e.into_inner().0).unwrap();
}
