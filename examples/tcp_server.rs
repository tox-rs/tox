/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2017 Roman Proskuryakov <humbug@deeptown.org>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

extern crate tox;
extern crate futures;
extern crate bytes;
extern crate nom;
extern crate tokio_core;
extern crate tokio_io;

use tox::toxcore::crypto_core::*;
use tox::toxcore::tcp::make_server_handshake;
use tox::toxcore::tcp::codec;
use tox::toxcore::tcp::server::{Server, Client};

use futures::{Sink, Stream, Future};
use futures::sync::mpsc;

use tokio_io::*;
use tokio_core::reactor::Core;
use tokio_core::net::TcpListener;

fn main() {
    // Some constant keypair
    let server_pk = PublicKey([177, 185, 54, 250, 10, 168, 174,
                            148, 0, 93, 99, 13, 131, 131, 239,
                            193, 129, 141, 80, 158, 50, 133, 100,
                            182, 179, 183, 234, 116, 142, 102, 53, 38]);
    let server_sk = SecretKey([74, 163, 57, 111, 32, 145, 19, 40,
                            44, 145, 233, 210, 173, 67, 88, 217,
                            140, 147, 14, 176, 106, 255, 54, 249,
                            159, 12, 18, 39, 123, 29, 125, 230]);
    let addr = "0.0.0.0:12345".parse().unwrap();
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let listener = TcpListener::bind(&addr, &handle).unwrap();

    println!("Listening on {} using PK {:?}", addr, &server_pk.0);

    let server_inner = Server::new();

    // TODO move this processing future into a standalone library function
    let server = listener.incoming().for_each(|(socket, addr)| {
        println!("A new client connected from {}", addr);

        let server_inner_c = server_inner.clone();
        let register_client = make_server_handshake(socket, server_sk.clone())
            .map_err(|e| {
                println!("handshake error: {}", e);
                e
            })
            .and_then(move |(socket, channel, client_pk)| {
                println!("Handshake for client {:?} complited", &client_pk);
                let (tx, rx) = mpsc::unbounded();
                server_inner_c.insert(Client::new(tx, &client_pk));

                Ok((socket, channel, client_pk, rx))
            });
        let server_inner_c = server_inner.clone();
        let process_connection = register_client
            .and_then(move |(socket, channel, client_pk, rx)| {
                let secure_socket = socket.framed(codec::Codec::new(channel));
                let (to_client, from_client) = secure_socket.split();

                // reader = for each Packet from client process it
                let server_inner_c_c = server_inner_c.clone();
                let reader = from_client.for_each(move |packet| {
                    println!("Handle {:?} => {:?}", client_pk, packet);
                    server_inner_c_c.handle_packet(&client_pk, packet)
                });

                // writer = for each Packet from rx send it to client
                let writer = rx
                    .map_err(|()| unreachable!("rx can't fail"))
                    .fold(to_client, move |to_client, packet| {
                        println!("Send {:?} => {:?}", client_pk, packet);
                        to_client.send(packet)
                    })
                    // drop to_client when rx stream is exhausted
                    .map(|_to_client| ());

                // TODO ping request = each 30s send PingRequest to client

                let server_inner_c_c = server_inner_c.clone();
                reader.select(writer)
                    .map(|_| ())
                    .map_err(move |(err, _select_next)| {
                        println!("Processing client {:?} ended with error: {:?}", &client_pk, err);
                        err
                    })
                    .then(move |r_processing| {
                        println!("shutdown PK {:?}", &client_pk);
                        server_inner_c_c.shutdown_client(&client_pk)
                            .then(move |r_shutdown| r_processing.and(r_shutdown))
                    })
            });
        handle.spawn(process_connection.then(|r| {
            println!("end of processing with result {:?}", r);
            Ok(())
        }));

        Ok(())
    });
    core.run(server).unwrap();
}
