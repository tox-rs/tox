/*! Extension trait for run TCP server on `TcpStream` and ping sender
*/

use std::io::Error as IoError;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::channel::mpsc;
use futures::{FutureExt, SinkExt, StreamExt, TryFutureExt, TryStreamExt};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::error::Error as TimerError;
use tokio_util::codec::Framed;

use crate::relay::codec::{Codec, DecodeError, EncodeError};
use crate::relay::handshake::make_server_handshake;
use crate::relay::server::{Client, Server};
use crate::stats::*;
use tox_crypto::*;

/// Interval of time for Tcp Ping sender
const TCP_PING_INTERVAL: Duration = Duration::from_secs(1);

/// Interval of time for the TCP handshake.
const TCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const SERVER_CHANNEL_SIZE: usize = 64;

/// Error that can happen during server execution
#[derive(Debug, Error)]
pub enum ServerRunError {
    /// Incoming IO error
    #[error("Incoming IO error: {:?}", error)]
    Incoming {
        /// IO error
        error: IoError,
    },
    /// Ping wakeups timer error
    #[error("Ping wakeups timer error: {:?}", error)]
    PingWakeups {
        /// Timer error
        error: TimerError,
    },
    /// Send pings error
    #[error("Send pings error: {:?}", error)]
    SendPings {
        /// Send pings error
        error: IoError,
    },
}

/// Error that can happen during TCP connection execution
#[derive(Debug, Error)]
pub enum ConnectionError {
    /// Error indicates that we couldn't get peer address
    #[error("Failed to get peer address: {}", error)]
    PeerAddr {
        /// Peer address error
        error: IoError,
    },
    /// Sending packet error
    #[error("Failed to send TCP packet: {}", error)]
    SendPacket { error: EncodeError },
    /// Decode incoming packet error
    #[error("Failed to decode incoming packet: {}", error)]
    DecodePacket { error: DecodeError },
    /// Incoming IO error
    #[error("Incoming IO error: {:?}", error)]
    Incoming {
        /// IO error
        error: IoError,
    },
    /// Server handshake error
    #[error("Server handshake error: {:?}", error)]
    ServerHandshakeTimeout {
        /// Server handshake error
        error: tokio::time::error::Elapsed,
    },
    #[error("Server handshake error: {:?}", error)]
    ServerHandshakeIo {
        /// Server handshake error
        error: IoError,
    },
    /// Packet handling error
    #[error("Packet handling error: {:?}", error)]
    PacketHandling {
        /// Packet handling error
        error: IoError,
    },
    /// Insert client error
    #[error("Packet handling error: {:?}", error)]
    InsertClient {
        /// Insert client error
        error: IoError,
    },

    #[error("Packet handling error: {:?}", error)]
    Shutdown {
        /// Insert client error
        error: IoError,
    },
}

/// Running TCP ping sender and incoming `TcpStream`. This function uses
/// `tokio::spawn` inside so it should be executed via tokio to be able to
/// get tokio default executor.
pub async fn tcp_run(
    server: &Server,
    listener: TcpListener,
    dht_sk: SecretKey,
    stats: Stats,
    connections_limit: usize,
) -> Result<(), ServerRunError> {
    let connections_count = Arc::new(AtomicUsize::new(0));

    let connections_future = async {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|error| ServerRunError::Incoming { error })?;
            if connections_count.load(Ordering::SeqCst) < connections_limit {
                connections_count.fetch_add(1, Ordering::SeqCst);
                let connections_count_c = connections_count.clone();
                let dht_sk = dht_sk.clone();
                let stats = stats.clone();
                let server = server.clone();

                tokio::spawn(async move {
                    let res = tcp_run_connection(&server, stream, dht_sk, stats).await;

                    if let Err(ref e) = res {
                        error!("Error while running tcp connection: {:?}", e)
                    }

                    connections_count_c.fetch_sub(1, Ordering::SeqCst);
                    res
                });
            } else {
                trace!("Tcp server has reached the limit of {} connections", connections_limit);
            }
        }
    };

    let mut wakeups = tokio::time::interval(TCP_PING_INTERVAL);
    let ping_future = async {
        loop {
            wakeups.tick().await;

            trace!("Tcp server ping sender wake up");
            server
                .send_pings()
                .await
                .map_err(|error| ServerRunError::SendPings { error })?;
        }
    };

    futures::select! {
        res = connections_future.fuse() => res,
        res = ping_future.fuse() => res,
    }
}

/// Running TCP server on incoming `TcpStream`
pub async fn tcp_run_connection(
    server: &Server,
    stream: TcpStream,
    dht_sk: SecretKey,
    stats: Stats,
) -> Result<(), ConnectionError> {
    let addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(error) => return Err(ConnectionError::PeerAddr { error }),
    };

    debug!("A new TCP client connected from {}", addr);

    let fut = tokio::time::timeout(TCP_HANDSHAKE_TIMEOUT, make_server_handshake(stream, dht_sk.clone()));
    let (stream, channel, client_pk) = match fut.await {
        Err(error) => Err(ConnectionError::ServerHandshakeTimeout { error }),
        Ok(Err(error)) => Err(ConnectionError::ServerHandshakeIo { error }),
        Ok(Ok(res)) => Ok(res),
    }?;

    debug!("Handshake for TCP client {:?} is completed", client_pk);

    let secure_socket = Framed::new(stream, Codec::new(channel, stats));
    let (mut to_client, from_client) = secure_socket.split();
    let (to_client_tx, mut to_client_rx) = mpsc::channel(SERVER_CHANNEL_SIZE);

    // processor = for each Packet from client process it
    let processor = from_client
        .map_err(|error| ConnectionError::DecodePacket { error })
        .try_for_each(|packet| {
            debug!("Handle {:?} => {:?}", client_pk, packet);
            server
                .handle_packet(&client_pk, packet)
                .map_err(|error| ConnectionError::PacketHandling { error })
        });

    let writer = async {
        while let Some(packet) = to_client_rx.next().await {
            trace!("Sending TCP packet {:?} to {:?}", packet, client_pk);
            to_client
                .send(packet)
                .await
                .map_err(|error| ConnectionError::SendPacket { error })?;
        }

        Ok(())
    };

    let client = Client::new(to_client_tx, &client_pk, addr.ip(), addr.port());
    server
        .insert(client)
        .await
        .map_err(|error| ConnectionError::InsertClient { error })?;

    let r_processing = futures::select! {
        res = processor.fuse() => res,
        res = writer.fuse() => res
    };

    debug!("Shutdown a client with PK {:?}", &client_pk);

    server
        .shutdown_client(&client_pk, addr.ip(), addr.port())
        .await
        .map_err(|error| ConnectionError::Shutdown { error })?;

    r_processing
}

#[cfg(test)]
mod tests {
    use super::*;
    use tox_binary_io::*;

    use rand::thread_rng;
    use std::io::{Error, ErrorKind};

    use crate::relay::codec::Codec;
    use crate::relay::handshake::make_client_handshake;
    use tox_packet::relay::{Packet, PingRequest, PongResponse};

    use crate::relay::server::client::*;

    #[tokio::test]
    async fn run_connection() {
        let mut rng = thread_rng();
        let client_sk = SecretKey::generate(&mut rng);
        let client_pk = client_sk.public_key();
        let server_sk = SecretKey::generate(&mut rng);
        let server_pk = server_sk.public_key();

        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(&addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let stats = Stats::new();
        let stats_c = stats.clone();
        let server = async {
            // take the first connection
            let (connection, _) = listener.accept().await.unwrap();
            tcp_run_connection(&Server::new(), connection, server_sk, stats.clone())
                .map_err(|e| Error::new(ErrorKind::Other, e))
                .await
        };

        let client = async {
            let socket = TcpStream::connect(&addr).map_err(Error::from).await?;
            let (stream, channel) = make_client_handshake(socket, &client_pk, &client_sk, &server_pk)
                .map_err(Error::from)
                .await?;
            let secure_socket = Framed::new(stream, Codec::new(channel, stats_c));
            let (mut to_server, mut from_server) = secure_socket.split();
            let packet = Packet::PingRequest(PingRequest { ping_id: 42 });

            to_server
                .send(packet)
                .map_err(|e| Error::new(ErrorKind::Other, e))
                .await
                .unwrap();
            let packet = from_server.next().await.unwrap();

            assert_eq!(packet.unwrap(), Packet::PongResponse(PongResponse { ping_id: 42 }));

            Ok(())
        };

        let result = futures::select!(
            res = server.fuse() => res,
            res = client.fuse() => res,
        );

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn run() {
        tokio::time::pause();

        let mut rng = thread_rng();
        let client_sk = SecretKey::generate(&mut rng);
        let client_pk = client_sk.public_key();
        let server_sk = SecretKey::generate(&mut rng);
        let server_pk = server_sk.public_key();

        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(&addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let stats = Stats::new();
        let server = async {
            tcp_run(&Server::new(), listener, server_sk, stats.clone(), 1)
                .await
                .map_err(|e| Error::new(ErrorKind::Other, e))
        };

        let client = async {
            let socket = TcpStream::connect(&addr).map_err(Error::from).await?;
            let (stream, channel) = make_client_handshake(socket, &client_pk, &client_sk, &server_pk)
                .map_err(Error::from)
                .await?;

            let secure_socket = Framed::new(stream, Codec::new(channel, stats.clone()));
            let (mut to_server, mut from_server) = secure_socket.split();
            let packet = Packet::PingRequest(PingRequest { ping_id: 42 });
            to_server
                .send(packet)
                .map_err(|e| Error::new(ErrorKind::Other, e))
                .await?;

            let packet = from_server.next().await.unwrap();
            assert_eq!(packet.unwrap(), Packet::PongResponse(PongResponse { ping_id: 42 }));
            // Set time when the client should be pinged
            tokio::time::advance(TCP_PING_FREQUENCY + Duration::from_secs(1)).await;
            while let Some(packet) = from_server.next().await {
                // check the packet
                let _ping_packet = unpack!(packet.unwrap(), Packet::PingRequest);
            }

            Ok(())
        };

        let result = futures::select!(
            res = server.fuse() => res,
            res = client.fuse() => res,
        );

        assert!(result.is_ok());
    }
}
