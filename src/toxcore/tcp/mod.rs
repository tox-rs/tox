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

/*! TCP handshake and Packet handling

*/

use toxcore::crypto_core::*;

pub mod binary_io;
pub mod handshake;
pub mod secure;
pub mod packet;
pub mod codec;


use futures::{self, Stream, Sink, Future};
use std::io::{Error, ErrorKind};
use tokio_io::*;
use tokio_core::net::TcpStream;
use self::binary_io::*;

/// Create a handshake from client to server
pub fn create_client_handshake(client_pk: PublicKey,
                           client_sk: SecretKey,
                           server_pk: PublicKey)
    -> Result<(secure::Session, PrecomputedKey, handshake::Client), Error>
{
    let session = secure::Session::new();
    let payload = handshake::Payload { session_pk: *session.pk(), session_nonce: *session.nonce() };

    let mut serialized_payload = [0; handshake::PAYLOAD_SIZE];
    let (serialized_payload, _) = payload.to_bytes((&mut serialized_payload, 0)).unwrap();

    let common_key = encrypt_precompute(&server_pk, &client_sk);
    let nonce = gen_nonce();
    let encrypted_payload = encrypt_data_symmetric(&common_key, &nonce, &serialized_payload);

    let handshake = handshake::Client { pk: client_pk, nonce: nonce, payload: encrypted_payload };
    Ok((session, common_key, handshake))
}

/// Handle received client handshake on the server side.
/// Return secure::Channel, Client PK, server handshake
pub fn handle_client_handshake(server_sk: SecretKey,
                           client_handshake: handshake::Client)
    -> Result<(secure::Channel, PublicKey, handshake::Server), Error>
{
    let common_key = encrypt_precompute(&client_handshake.pk, &server_sk);
    let payload_bytes = decrypt_data_symmetric(&common_key, &client_handshake.nonce, &client_handshake.payload)
        .map_err(
            |_| Error::new(ErrorKind::Other, "Failed to decrypt handshake::Client payload")
        )?;

    let payload = handshake::Payload::from_bytes(&payload_bytes).to_full_result().unwrap();

    let client_pk = payload.session_pk;
    let client_nonce = payload.session_nonce;

    let session = secure::Session::new();
    let server_payload = handshake::Payload { session_pk: *session.pk(), session_nonce: *session.nonce() };

    let mut serialized_payload = [0; handshake::PAYLOAD_SIZE];
    let (serialized_payload, _) = server_payload.to_bytes((&mut serialized_payload, 0)).unwrap();

    let nonce = gen_nonce();
    let server_encrypted_payload = encrypt_data_symmetric(&common_key, &nonce, &serialized_payload);

    let server_handshake = handshake::Server { nonce: nonce, payload: server_encrypted_payload };
    let channel = secure::Channel::new(session, &client_pk, &client_nonce);
    Ok((channel, client_handshake.pk, server_handshake))
}

/// Handle received server handshake on the client side.
pub fn handle_server_handshake(common_key: PrecomputedKey,
                           client_session: secure::Session,
                           server_handshake: handshake::Server)
   -> Result<secure::Channel, Error>
{
    let payload_bytes = decrypt_data_symmetric(&common_key, &server_handshake.nonce, &server_handshake.payload)
        .map_err(
            |_| Error::new(ErrorKind::Other, "Failed to decrypt handshake::Server payload")
        )?;
    let payload = handshake::Payload::from_bytes(&payload_bytes).to_full_result().unwrap();

    let server_pk = payload.session_pk;
    let server_nonce = payload.session_nonce;

    let channel = secure::Channel::new(client_session, &server_pk, &server_nonce);
    Ok(channel)
}

/// Sends handshake to the server, receives handshake from the server
/// and processes it
pub fn make_client_handshake(socket: TcpStream,
    client_pk: PublicKey,
    client_sk: SecretKey,
    server_pk: PublicKey
) -> IoFuture<(TcpStream, secure::Channel)>
{
    let res = futures::done(create_client_handshake(client_pk, client_sk, server_pk))
        .and_then(|(session, common_key, handshake)| {
            // send handshake
            socket.framed(handshake::ClientCodec)
                .send(handshake)
                .map_err(|e| {
                    Error::new(
                        ErrorKind::Other,
                        format!("Could not send handshake::Client {:?}", e),
                    )
                })
                .map(|socket| {
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
    Box::new(res)
}

/// Receives handshake from the client, processes it and
/// sends handshake to the client
pub fn make_server_handshake(socket: TcpStream,
    server_sk: SecretKey
) -> IoFuture<(TcpStream, secure::Channel, PublicKey)>
{
    let res = socket.framed(handshake::ClientCodec)
        .into_future() // receive handshake from client
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
        .and_then(|(socket, handshake)| {
            // handle handshake
            handle_client_handshake(server_sk, handshake)
                .map(|(channel, client_pk, server_handshake)| {
                    (socket, channel, client_pk, server_handshake)
                })
        })
        .and_then(|(socket, channel, client_pk, server_handshake)| {
            // send handshake
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
        });
    Box::new(res)
}

#[cfg(test)]
mod tests {
    use ::toxcore::tcp::*;
    fn create_channels_with_handshake() -> (secure::Channel, secure::Channel) {
        let (client_pk, client_sk) = gen_keypair();
        let (server_pk, server_sk) = gen_keypair();

        // client creates a handshake packet
        let (client_session, common_key, client_handshake) = create_client_handshake(client_pk, client_sk, server_pk).unwrap();
        assert_eq!(handshake::ENC_PAYLOAD_SIZE, client_handshake.payload.len());
        // sends client_handshake via network
        // ..
        // .. network
        // ..
        // server receives a handshake packet
        // handles it & creates a secure Channel
        let (server_channel, received_client_pk, server_handshake) = handle_client_handshake(server_sk, client_handshake).unwrap();
        assert_eq!(received_client_pk, client_pk);
        // sends server_handshake via network
        // ..
        // .. network
        // ..
        // client receives the reply
        // handles it & creates a secure Channel
        let client_channel = handle_server_handshake(common_key, client_session, server_handshake).unwrap();
        // now they are ready to communicate via secure Channels
        (client_channel, server_channel)
    }
    #[test]
    fn secure_communication_with_handshake() {
        let (alice_channel, bob_channel) = create_channels_with_handshake();

        // And now they may communicate sending encrypted data to each other

        // Alice encrypts the message
        let alice_msg = "Hello Bob!";
        let alice_msg_encrypted = alice_channel.encrypt(alice_msg.as_bytes());
        assert_ne!(alice_msg.as_bytes().to_vec(), alice_msg_encrypted);
        // Alice sends it somehow

        // Bob receives and decrypts
        assert_eq!( alice_msg.as_bytes().to_vec(), bob_channel.decrypt(alice_msg_encrypted.as_ref()).unwrap() );

        // Now Bob encrypts his message
        let bob_msg = "Oh hello Alice!";
        let bob_msg_encrypted = bob_channel.encrypt(bob_msg.as_bytes());
        assert_ne!(bob_msg.as_bytes().to_vec(), bob_msg_encrypted);
        // And sends it back to Alice

        assert_eq!( bob_msg.as_bytes().to_vec(), alice_channel.decrypt(bob_msg_encrypted.as_ref()).unwrap() );
    }
    #[test]
    fn client_handshake_with_different_keypair() {
        let (client_pk, client_sk) = gen_keypair();
        let (server_pk, _) = gen_keypair();
        let (_, mallory_sk) = gen_keypair();

        let (_client_session, _common_key, client_handshake) = create_client_handshake(client_pk, client_sk, server_pk).unwrap();
        assert!(handle_client_handshake(mallory_sk, client_handshake).is_err());
    }
    #[test]
    fn server_handshake_with_different_keypair() {
        let (client_pk, client_sk) = gen_keypair();
        let (server_pk, server_sk) = gen_keypair();
        let (_, mallory_sk) = gen_keypair();

        let (client_session, _common_key, client_handshake) = create_client_handshake(client_pk, client_sk, server_pk).unwrap();
        let (_server_channel, _client_pk, server_handshake) = handle_client_handshake(server_sk, client_handshake).unwrap();
        let common_key = encrypt_precompute(&client_pk, &mallory_sk);
        assert!(handle_server_handshake(common_key, client_session, server_handshake).is_err());
    }
}
