/*! Handshake packets to establish a confirmed connection via
handshake using [`Diagram`](https://zetok.github.io/tox-spec/#handshake-diagram)

*/

pub mod packet;
pub mod codec;

pub use self::packet::*;
pub use self::codec::*;

use crypto_box::{SalsaBox, aead::{Aead, AeadCore, Error as AeadError}};
use tox_binary_io::*;
use tox_crypto::*;
use crate::relay::secure;

use futures::{self, StreamExt, SinkExt, TryFutureExt};
use std::io::{Error, ErrorKind};
use tokio_util::codec::Framed;
use tokio::net::TcpStream;

/// Create a handshake from client to server
pub fn create_client_handshake(client_pk: &PublicKey,
                           client_sk: &SecretKey,
                           server_pk: &PublicKey)
    -> Result<(secure::Session, SalsaBox, ClientHandshake), Error> {
    let session = secure::Session::random();
    let payload = HandshakePayload { session_pk: session.pk().clone(), session_nonce: *session.nonce() };

    let mut serialized_payload = [0; PAYLOAD_SIZE];
    // HandshakePayload::to_bytes may not fail because we created buffer with enough size
    let (serialized_payload, _) = payload.to_bytes((&mut serialized_payload, 0)).unwrap();

    let common_key = SalsaBox::new(server_pk, client_sk);
    let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
    let encrypted_payload = common_key.encrypt(&nonce, &serialized_payload[..]).unwrap();

    let handshake = ClientHandshake {
        pk: client_pk.clone(),
        nonce: nonce.into(),
        payload: encrypted_payload,
    };
    Ok((session, common_key, handshake))
}

/// Handle received client handshake on the server side.
/// Return secure::Channel, Client PK, server handshake
pub fn handle_client_handshake(server_sk: &SecretKey,
                           client_handshake: &ClientHandshake)
    -> Result<(secure::Channel, PublicKey, ServerHandshake), Error> {
    let common_key = SalsaBox::new(&client_handshake.pk, server_sk);
    let payload_bytes = common_key.decrypt((&client_handshake.nonce).into(), &client_handshake.payload[..])
        .map_err(
            |AeadError| Error::new(ErrorKind::Other, "Failed to decrypt ClientHandshake payload")
        )?;

    let (_, payload) = HandshakePayload::from_bytes(&payload_bytes)
        .map_err(
            |_| Error::new(ErrorKind::Other, "Failed to deserialize ClientHandshake payload")
        )?;

    let client_pk = payload.session_pk;
    let client_nonce = payload.session_nonce;

    let session = secure::Session::random();
    let server_payload = HandshakePayload { session_pk: session.pk().clone(), session_nonce: *session.nonce() };

    let mut serialized_payload = [0; PAYLOAD_SIZE];
    // HandshakePayload::to_bytes may not fail because we created buffer with enough size
    let (serialized_payload, _) = server_payload.to_bytes((&mut serialized_payload, 0)).unwrap();

    let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
    let server_encrypted_payload = common_key.encrypt(&nonce, &serialized_payload[..]).unwrap();

    let server_handshake = ServerHandshake {
        nonce: nonce.into(),
        payload: server_encrypted_payload,
    };
    let channel = secure::Channel::new(&session, &client_pk, &client_nonce);
    Ok((channel, client_handshake.pk.clone(), server_handshake))
}

/// Handle received server handshake on the client side.
pub fn handle_server_handshake(common_key: &SalsaBox,
                           client_session: &secure::Session,
                           server_handshake: &ServerHandshake)
    -> Result<secure::Channel, Error> {
    let payload_bytes = common_key.decrypt((&server_handshake.nonce).into(), &server_handshake.payload[..])
        .map_err(
            |AeadError| Error::new(ErrorKind::Other, "Failed to decrypt ServerHandshake payload")
        )?;
    let (_, payload) = HandshakePayload::from_bytes(&payload_bytes)
        .map_err(
            |_| Error::new(ErrorKind::Other, "Failed to deserialize ServerHandshake payload")
        )?;

    let server_pk = payload.session_pk;
    let server_nonce = payload.session_nonce;

    let channel = secure::Channel::new(client_session, &server_pk, &server_nonce);
    Ok(channel)
}

/// Sends handshake to the server, receives handshake from the server
/// and processes it
pub async fn make_client_handshake(
    socket: TcpStream,
    client_pk: &PublicKey,
    client_sk: &SecretKey,
    server_pk: &PublicKey
) -> Result<(TcpStream, secure::Channel), Error> {
    let (session, common_key, handshake) =
        create_client_handshake(client_pk, client_sk, server_pk)?;

    let mut client = Framed::new(socket, ClientHandshakeCodec);
    client.send(handshake)
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("Could not send ClientHandshake {:?}", e),
            )
        })
        .await?;

    let socket = client.into_inner();
    let server = Framed::new(socket, ServerHandshakeCodec);
    let (handshake, server_socket) = server.into_future().await;
    let handshake = match handshake {
        None => Err(Error::new(
            ErrorKind::Other, "Option<ServerHandshake> is empty"
        )),
        Some(Err(e)) => Err(Error::new(
            ErrorKind::Other,
            format!("Could not read ServerHandshake {:?}", e),
        )),
        Some(res) => res,
    }?;

    handle_server_handshake(&common_key, &session, &handshake)
        .map(|chan| (server_socket.into_inner(), chan))
}

/// Receives handshake from the client, processes it and
/// sends handshake to the client
pub async fn make_server_handshake(
    socket: TcpStream,
    server_sk: SecretKey
) -> Result<(TcpStream, secure::Channel, PublicKey), Error> {
    let client = Framed::new(socket, ClientHandshakeCodec);

    let (handshake, client) = client.into_future().await;
    let handshake = match handshake {
        None => Err(Error::new(
            ErrorKind::Other, "Option<ClientHandshake> is empty"
        )),
        Some(Err(e)) => Err(Error::new(
            ErrorKind::Other,
            format!("Could not read ClientHandshake {:?}", e),
        )),
        Some(res) => res,
    }?;

    let (channel, client_pk, server_handshake) =
        handle_client_handshake(&server_sk, &handshake)?;

    let socket = client.into_inner();
    let mut server = Framed::new(socket, ServerHandshakeCodec);
    server.send(server_handshake).await
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("Could not send ServerHandshake {:?}", e),
            )
        })?;

    let socket = server.into_inner();
    Ok((socket, channel, client_pk))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use rand::thread_rng;
    use tox_crypto::*;
    use crate::relay::*;
    use crate::relay::handshake::*;

    fn create_channels_with_handshake() -> (secure::Channel, secure::Channel) {
        let mut rng = thread_rng();
        let client_sk = SecretKey::generate(&mut rng);
        let client_pk = client_sk.public_key();
        let server_sk = SecretKey::generate(&mut rng);
        let server_pk = server_sk.public_key();

        // client creates a handshake packet
        let (client_session, common_key, client_handshake) = create_client_handshake(&client_pk, &client_sk, &server_pk).unwrap();
        assert_eq!(handshake::ENC_PAYLOAD_SIZE, client_handshake.payload.len());
        // sends client_handshake via network
        // ..
        // .. network
        // ..
        // server receives a handshake packet
        // handles it & creates a secure Channel
        let (server_channel, received_client_pk, server_handshake) = handle_client_handshake(&server_sk, &client_handshake).unwrap();
        assert_eq!(received_client_pk, client_pk);
        // sends server_handshake via network
        // ..
        // .. network
        // ..
        // client receives the reply
        // handles it & creates a secure Channel
        let client_channel = handle_server_handshake(&common_key, &client_session, &server_handshake).unwrap();
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
        let mut rng = thread_rng();
        let client_sk = SecretKey::generate(&mut rng);
        let client_pk = client_sk.public_key();
        let server_pk = SecretKey::generate(&mut rng).public_key();
        let mallory_sk = SecretKey::generate(&mut rng);

        let (_client_session, _common_key, client_handshake) = create_client_handshake(&client_pk, &client_sk, &server_pk).unwrap();
        assert!(handle_client_handshake(&mallory_sk, &client_handshake).is_err());
    }
    #[test]
    fn server_handshake_with_different_keypair() {
        let mut rng = thread_rng();
        let client_sk = SecretKey::generate(&mut rng);
        let client_pk = client_sk.public_key();
        let server_sk = SecretKey::generate(&mut rng);
        let server_pk = server_sk.public_key();
        let mallory_sk = SecretKey::generate(&mut rng);

        let (client_session, _common_key, client_handshake) = create_client_handshake(&client_pk, &client_sk, &server_pk).unwrap();
        let (_server_channel, _client_pk, server_handshake) = handle_client_handshake(&server_sk, &client_handshake).unwrap();
        let common_key = SalsaBox::new(&client_pk, &mallory_sk);
        assert!(handle_server_handshake(&common_key, &client_session, &server_handshake).is_err());
    }
    #[test]
    fn client_handshake_with_bad_payload() {
        let mut rng = thread_rng();
        let client_sk = SecretKey::generate(&mut rng);
        let client_pk = client_sk.public_key();
        let server_sk = SecretKey::generate(&mut rng);
        let server_pk = server_sk.public_key();

        let client_handshake = {
            let common_key = SalsaBox::new(&server_pk, &client_sk);
            let nonce = SalsaBox::generate_nonce(&mut rng);
            // bad payload [1,2,3]
            let encrypted_payload = common_key.encrypt(&nonce, &[1, 2, 3][..]).unwrap();

            ClientHandshake { pk: client_pk, nonce: nonce.into(), payload: encrypted_payload }
        };
        assert!(handle_client_handshake(&server_sk, &client_handshake).is_err());
    }
    #[test]
    fn server_handshake_with_bad_payload() {
        use self::secure::*;
        let mut rng = thread_rng();
        let client_pk = SecretKey::generate(&mut rng).public_key();
        let server_sk = SecretKey::generate(&mut rng);
        let common_key = SalsaBox::new(&client_pk, &server_sk);
        let client_session = Session::random();

        let server_handshake = {
            let nonce = SalsaBox::generate_nonce(&mut rng);
            // bad payload [1,2,3]
            let server_encrypted_payload = common_key.encrypt(&nonce, &[1, 2, 3][..]).unwrap();

            ServerHandshake { nonce: nonce.into(), payload: server_encrypted_payload }
        };
        assert!(handle_server_handshake(&common_key, &client_session, &server_handshake).is_err());
    }
    #[tokio::test]
    async fn network_handshake() {
        use tokio::net::{TcpListener, TcpStream};

        let mut rng = thread_rng();
        let client_sk = SecretKey::generate(&mut rng);
        let client_pk = client_sk.public_key();
        let server_sk = SecretKey::generate(&mut rng);
        let server_pk = server_sk.public_key();

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(&addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = async {
            let (connection, _) = listener.accept().await.unwrap();
            make_server_handshake(connection, server_sk.clone()).await
        };

        let client = async {
            let socket = TcpStream::connect(&addr).map_err(Error::from).await?;
            make_client_handshake(socket, &client_pk, &client_sk, &server_pk).await
        };

        let res = futures::try_join!(server, client);
        drop(res.unwrap())
    }
}
