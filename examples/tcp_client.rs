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
use tox::toxcore::tcp::*;
use tox::toxcore::tcp::codec;

use std::io::{Error, ErrorKind};
use futures::{Stream, Sink, Future};

use tokio_io::*;
use tokio_core::reactor::Core;
use tokio_core::net::TcpStream;

fn main() {
    // Server constant PK for examples/tests
    // Use `gen_keypair` to generate random keys
    let server_pk = PublicKey([177, 185, 54, 250, 10, 168, 174,
                            148, 0, 93, 99, 13, 131, 131, 239,
                            193, 129, 141, 80, 158, 50, 133, 100,
                            182, 179, 183, 234, 116, 142, 102, 53, 38]);
    // Some constant keypair for client
    let client_pk = PublicKey([252, 72, 40, 127, 213, 13, 0, 95,
                              13, 230, 176, 49, 69, 252, 220, 132,
                              48, 73, 227, 58, 218, 154, 215, 245,
                              23, 189, 223, 216, 153, 237, 130, 88]);
    let client_sk = SecretKey([157, 128, 29, 197, 1, 72, 47, 56,
                              65, 81, 191, 67, 220, 225, 108, 193,
                              46, 163, 145, 242, 139, 125, 159,
                              137, 174, 14, 225, 7, 138, 120, 185, 153]);

    let addr = "0.0.0.0:12345".parse().unwrap();
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let tcp = TcpStream::connect(&addr, &handle);
    let process_handshake = tcp
        .and_then(|socket| {
            // create handshake
            futures::done(create_client_handshake(client_pk, client_sk, server_pk))
                .map(|(session, common_key, handshake)| (socket, session, common_key, handshake))
        })
        .and_then(|(socket, session, common_key, handshake)| {
            // send handshake
            socket.framed(handshake::ClientCodec)
                .send(handshake)
                .map_err(|e| {
                    Error::new(
                        ErrorKind::Other,
                        format!("Could not send handshake::Client {:?}", e),
                    )
                })
                .map(move |socket| {
                    (socket.into_inner(), session, common_key)
                })
        })
        .and_then(|(socket, session, common_key)| {
            // receive handshake from server
            socket.framed(handshake::ServerCodec)
                .into_future()
                .map_err(|(e, _socket)| {
                    Error::new(
                        ErrorKind::Other,
                        format!("Could not read handshake::Server {:?}", e),
                    )
                })
                .and_then(|(handshake, socket)| {
                    // `handshake` here is an `Option<handshake::Server>`
                    handshake.map_or_else(
                        || Err(Error::new(ErrorKind::Other, "Option<handshake::Server> is empty")),
                        |handshake| Ok(( socket.into_inner(), common_key, session, handshake ))
                    )
                })
        })
        .and_then(|(socket, common_key, session, handshake)| {
            // handle it
            handle_server_handshake(common_key, session, handshake)
                .map(|channel| {
                    (socket, channel)
                })
        });

    let client = process_handshake.and_then(|(socket, channel)| {
        println!("Handshake complited");
        let secure_socket = socket.framed(codec::Codec::new(channel));
        let (_to_server, _from_server) = secure_socket.split();
        // use example https://github.com/jgallagher/tokio-chat-example/blob/master/tokio-chat-client/src/main.rs
        Ok(())
    });

    core.run(client).unwrap();
}
