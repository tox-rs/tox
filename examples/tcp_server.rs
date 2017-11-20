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

    let server = listener.incoming().for_each(|(socket, addr)| {
        println!("A new client connected from {}", addr);

        let server_sk = server_sk.clone();

        let process_handshake = socket.framed(handshake::ClientCodec)
            .into_future()
            .map_err(|(e, _socket)| {
                Error::new(
                    ErrorKind::Other,
                    format!("Could not read handshake::Client {:?}", e),
                )
            })
            .and_then(|(handshake, socket)| {
                // `handshake` here is an `Option<handshake::Client>`
                handshake.map_or_else(
                    || Err(Error::new(ErrorKind::Other, "Option<handshake::Client> is empty")),
                    |handshake| Ok(( socket.into_inner(), handshake ))
                )
            })
            .and_then(move |(socket, handshake)| {
                handle_client_handshake(server_sk, handshake)
                    .map(|(channel, client_pk, server_handshake)| {
                        (socket, channel, client_pk, server_handshake)
                    })
            })
            .and_then(|(socket, channel, client_pk, server_handshake)| {
                socket.framed(handshake::ServerCodec)
                    .send(server_handshake)
                    .map_err(|e| {
                        Error::new(
                            ErrorKind::Other,
                            format!("Could not send handshake::Server {:?}", e),
                        )
                    })
                    .map(move |socket| {
                        (socket.into_inner(), channel, client_pk)
                    })
            })
        ;

        let process_messages = process_handshake.and_then(|(socket, channel, client_pk)| {
            println!("Handshake for client {:?} complited", &client_pk);
            let secure_socket = socket.framed(codec::Codec::new(channel));
            let (_to_client, _from_client) = secure_socket.split();
            // use example https://github.com/jgallagher/tokio-chat-example/blob/master/tokio-chat-server/src/main.rs
            Ok(())
        }).map_err(|e| {
            println!("error: {}", e);
        });
        handle.spawn(process_messages);

        Ok(())
    });
    core.run(server).unwrap();
}
