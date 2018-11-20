extern crate tox;
extern crate futures;
extern crate tokio;
extern crate tokio_codec;

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate hex;
extern crate failure;

use tox::toxcore::crypto_core::*;
use tox::toxcore::tcp::packet::*;
use tox::toxcore::tcp::handshake::make_client_handshake;
use tox::toxcore::tcp::codec;
use tox::toxcore::io_tokio::IoFuture;
use tox::toxcore::utils::Stats;

use failure::{Error, err_msg};

use hex::FromHex;

use futures::prelude::*;
use futures::future;
use futures::future::Either;
use futures::sync::mpsc;

use tokio_codec::Framed;
use tokio::net::TcpStream;

use std::{thread, time};

// Notice that create_client create a future of client processing.
//  The future will live untill all copies of tx is dropped or there is a IO error
//  Since we pass a copy of tx as arg (to send PongResponses), the client will live untill IO error
//  Comment out pong responser and client will be destroyed when there will be no messages to send
fn create_client(rx: mpsc::Receiver<Packet>, tx: mpsc::Sender<Packet>) -> IoFuture<()> {
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
            let addr = "0.0.0.0:12345".parse().unwrap();
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

    let client = TcpStream::connect(&addr)
        .map_err(Error::from)
        .and_then(move |socket| {
            make_client_handshake(socket, &client_pk, &client_sk, &server_pk)
                .map_err(Error::from)
        })
        .and_then(move |(socket, channel)| {
            debug!("Handshake complited");

            let secure_socket = Framed::new(socket, codec::Codec::new(channel, stats.clone()));
            let (to_server, from_server) = secure_socket.split();

            let reader = from_server.map_err(Error::from).for_each(move |packet| {
                debug!("Got packet {:?}", packet);
                // Simple pong responser
                if let Packet::PingRequest(ping) = packet {
                    Either::A(
                        tx.clone().send(Packet::PongResponse(
                            PongResponse { ping_id: ping.ping_id }
                        ))
                        .map(|_| () )
                        .map_err(|_| err_msg("Could not send pong") )
                    )
                } else {
                    Either::B( future::ok(()) )
                }
            })
            .then(|res| {
                debug!("Reader ended with {:?}", res);
                res
            });

            let writer = rx
                .map_err(|()| unreachable!("rx can't fail"))
                .fold(to_server, move |to_server, packet| {
                    debug!("Send packet {:?}", packet);
                    to_server.send(packet)
                })
                // drop to_client when rx stream is exhausted
                .map(|_to_client| {
                    debug!("Stream rx is exhausted");
                    ()
                })
                .map_err(|err| {
                    error!("Writer err: {}", err);
                    err
                });;

            reader.select(writer).map(|_| ()).map_err(|(err, _select_next)| err)
        })
        .then(|res| {
            debug!("client ended with {:?}", res);
            Ok(())
        });

    Box::new(client)
}

#[allow(dead_code)]
fn send_packets(tx: mpsc::Sender<Packet>) {
    // Client friend constant PK for examples/tests
    let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
                            192, 117, 0, 225, 119, 43, 48, 117,
                            84, 109, 112, 57, 243, 216, 4, 171,
                            185, 111, 33, 146, 221, 31, 77, 118]);

    let mut i = 0u64;
    loop {
        let sleep_duration = time::Duration::from_millis(1);
        match tx.clone().send(Packet::RouteRequest(RouteRequest {pk: friend_pk } )).wait() {
            Ok(_tx) => (),
            Err(e) => {
                error!("send_packets: {:?}", e);
                break
            },
        };
        if i % 10000 == 0 {
            thread::sleep(sleep_duration);
            println!("i = {}", i);
        }
        i = i + 1;

    }
    /*
    let packets = vec![
        Packet::RouteRequest(RouteRequest {pk: friend_pk } ),
        Packet::RouteRequest(RouteRequest {pk: friend_pk } ),
        Packet::RouteRequest(RouteRequest {pk: friend_pk } ),
        Packet::RouteRequest(RouteRequest {pk: friend_pk } )
    ];

    let sleep_duration = time::Duration::from_millis(1500);
    for packet in packets {
        match tx.clone().send(packet).wait() {
            Ok(_tx) => (),
            Err(e) => {
                error!("send_packets: {:?}", e);
                break
            },
        };
        thread::sleep(sleep_duration);
    }
    thread::sleep(sleep_duration);
    */
}

fn main() {
    env_logger::init();

    let (tx, rx) = mpsc::channel(1);

    let client = create_client(rx, tx.clone())
        .map_err(|_| ());

    // variant 1. send packets in the same thread, combine with select(...)
    let mut i = 0u64;
    let packet_sender = future::loop_fn(tx.clone(), move |tx| {
        if i % 10000 == 0 {
            println!("i = {}", i);
        }
        i = i + 1;
        // Client friend constant PK for examples/tests
        let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
                                192, 117, 0, 225, 119, 43, 48, 117,
                                84, 109, 112, 57, 243, 216, 4, 171,
                                185, 111, 33, 146, 221, 31, 77, 118]);

        let request = if i == 1 {
            tx.send(Packet::RouteRequest(RouteRequest {pk: friend_pk } ))
        } else {
            tx.send(Packet::Data(Data { connection_id: 16, data: vec![42; 42] } ))
        };

        request
            .and_then(|tx| Ok(future::Loop::Continue(tx)) )
            .or_else(|e| Ok(future::Loop::Break(e)) )
    }).map(|_| ());
    let client = client.select(packet_sender).map(|_| ()).map_err(|_| ());

    // variant 2. send packets in a separate thread
    //thread::spawn(move || send_packets(tx));

    tokio::run( client );
}
