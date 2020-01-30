/*! Extension trait for run TCP server on `TcpStream` and ping sender
*/

use std::io::{Error as IoError};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration};
use std::pin::Pin;

use failure::Fail;
use futures::{future, Future, FutureExt, TryFutureExt, SinkExt, StreamExt, TryStreamExt};
use futures::channel::mpsc;
use tokio::net::{TcpStream, TcpListener};
use tokio_util::codec::Framed;
use tokio::time::{Error as TimerError};
// use tokio_timer::timeout::{Error as TimeoutError};

use crate::toxcore::crypto_core::*;
use crate::toxcore::tcp::codec::{DecodeError, EncodeError, Codec};
use crate::toxcore::tcp::handshake::make_server_handshake;
use crate::toxcore::tcp::server::{Client, Server};
use crate::toxcore::stats::*;

/// Interval of time for Tcp Ping sender
const TCP_PING_INTERVAL: Duration = Duration::from_secs(1);

/// Interval of time for the TCP handshake.
const TCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const SERVER_CHANNEL_SIZE: usize = 64;

/// Error that can happen during server execution
#[derive(Debug, Fail)]
pub enum ServerRunError {
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    IncomingError {
        /// IO error
        #[fail(cause)]
        error: IoError
    },
    /// Ping wakeups timer error
    #[fail(display = "Ping wakeups timer error: {:?}", error)]
    PingWakeupsError {
        /// Timer error
        error: TimerError
    },
    /// Send pings error
    #[fail(display = "Send pings error: {:?}", error)]
    SendPingsError {
        /// Send pings error
        #[fail(cause)]
        error: IoError
    },
}

/// Error that can happen during TCP connection execution
#[derive(Debug, Fail)]
pub enum ConnectionError {
    /// Error indicates that we couldn't get peer address
    #[fail(display = "Failed to get peer address: {}", error)]
    PeerAddrError {
        /// Peer address error
        #[fail(cause)]
        error: IoError,
    },
    /// Sending packet error
    #[fail(display = "Failed to send TCP packet: {}", error)]
    SendPacketError {
        error: EncodeError
    },
    /// Decode incoming packet error
    #[fail(display = "Failed to decode incoming packet: {}", error)]
    DecodePacketError {
        error: DecodeError
    },
    /// Incoming IO error
    #[fail(display = "Incoming IO error: {:?}", error)]
    IncomingError {
        /// IO error
        #[fail(cause)]
        error: IoError
    },
    /// Server handshake error
    #[fail(display = "Server handshake error: {:?}", error)]
    ServerHandshakeTimeoutError {
        /// Server handshake error
        #[fail(cause)]
        error: tokio::time::Elapsed
    },
    #[fail(display = "Server handshake error: {:?}", error)]
    ServerHandshakeIoError {
        /// Server handshake error
        #[fail(cause)]
        error: IoError,
    },
    /// Packet handling error
    #[fail(display = "Packet handling error: {:?}", error)]
    PacketHandlingError {
        /// Packet handling error
        #[fail(cause)]
        error: IoError
    },
    /// Insert client error
    #[fail(display = "Packet handling error: {:?}", error)]
    InsertClientError {
        /// Insert client error
        #[fail(cause)]
        error: IoError
    },

    #[fail(display = "Packet handling error: {:?}", error)]
    ShutdownError {
        /// Insert client error
        #[fail(cause)]
        error: IoError
    },
}

/// Extension trait for running TCP server on incoming `TcpStream` and ping sender
pub trait ServerExt {
    /// Running TCP ping sender and incoming `TcpStream`. This function uses
    /// `tokio::spawn` inside so it should be executed via tokio to be able to
    /// get tokio default executor.
    fn run(self: Self, listener: TcpListener, dht_sk: SecretKey, stats: Stats, connections_limit: usize) -> Pin<Box<dyn Future<Output = Result<(), ServerRunError>> + Send>>;
    /// Running TCP server on incoming `TcpStream`
    fn run_connection(self: Self, stream: TcpStream, dht_sk: SecretKey, stats: Stats) -> Box<dyn Future<Output = Result<(), ConnectionError>> + Send + Unpin>;
}

impl ServerExt for Server {
    fn run(self: Self, mut listener: TcpListener, dht_sk: SecretKey, stats: Stats, connections_limit: usize) -> Pin<Box<dyn Future<Output = Result<(), ServerRunError>> + Send>> {
        let connections_count = Arc::new(AtomicUsize::new(0));

        let self_c = self.clone();

        let connections_future = async move {
            listener.incoming()
                .map_err(|error| ServerRunError::IncomingError { error })
                .try_for_each(move |stream| {
                    if connections_count.load(Ordering::SeqCst) < connections_limit {
                        connections_count.fetch_add(1, Ordering::SeqCst);
                        let connections_count_c = connections_count.clone();
                        let self_cc = self_c.clone();
                        let dht_sk = dht_sk.clone();
                        let stats = stats.clone();

                        tokio::spawn(
                            async move {
                                let res: Result<_, ConnectionError> = self_cc
                                    .run_connection(stream, dht_sk, stats)
                                    .await;

                                if let Err(ref e) = res {
                                    error!("Error while running tcp connection: {:?}", e)
                                }

                                connections_count_c.fetch_sub(1, Ordering::SeqCst);
                                res
                            }
                        );
                    } else {
                        trace!("Tcp server has reached the limit of {} connections", connections_limit);
                    }

                    future::ok(())
                }).await
        };

        let mut wakeups = tokio::time::interval(TCP_PING_INTERVAL);
        let ping_future = async move {
            while let Some(_) = wakeups.next().await {
                trace!("Tcp server ping sender wake up");
                self.send_pings().await
                    .map_err(|error| ServerRunError::SendPingsError { error })?;
            }

            Ok(())
        };

        Box::pin(async move {
            let res = futures::select! {
                res = connections_future.fuse() => res,
                res = ping_future.fuse() => res,
            };

            res.map(drop)
        })
    }

    fn run_connection(self: Self, stream: TcpStream, dht_sk: SecretKey, stats: Stats) -> Box<dyn Future<Output = Result<(), ConnectionError>> + Send + Unpin> {
        let addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(error) => return Box::new(future::err(ConnectionError::PeerAddrError {
                error
            })),
        };

        debug!("A new TCP client connected from {}", addr);

        let process = async move {
            let fut = tokio::time::timeout(
                TCP_HANDSHAKE_TIMEOUT,
                make_server_handshake(stream, dht_sk.clone())
            );
            let (stream, channel, client_pk) = match fut.await {
                Err(error) => Err(
                    ConnectionError::ServerHandshakeTimeoutError { error }
                ),
                Ok(Err(error)) => Err(
                    ConnectionError::ServerHandshakeIoError { error }
                ),
                Ok(Ok(res)) => Ok(res)
            }?;

            debug!("Handshake for TCP client {:?} is completed", client_pk);

            let secure_socket = Framed::new(stream, Codec::new(channel, stats));
            let (mut to_client, from_client) = secure_socket.split();
            let (to_client_tx, mut to_client_rx) = mpsc::channel(SERVER_CHANNEL_SIZE);

            let server = self.clone();
            // processor = for each Packet from client process it
            let processor = from_client
                .map_err(|error| ConnectionError::DecodePacketError { error })
                .try_for_each(move |packet| {
                    debug!("Handle {:?} => {:?}", client_pk, packet);
                    server.handle_packet(&client_pk, packet)
                        .map_err(|error| ConnectionError::PacketHandlingError { error } )
                });

            let writer = async {
                while let Some(packet) = to_client_rx.next().await {
                    trace!("Sending TCP packet {:?} to {:?}", packet, client_pk);
                    to_client.send(packet).await
                        .map_err(|error| ConnectionError::SendPacketError {
                            error
                        })?;
                }

                Ok(())
            };

            let client = Client::new(
                to_client_tx,
                &client_pk,
                addr.ip(),
                addr.port()
            );
            self.insert(client).await
                .map_err(|error| ConnectionError::InsertClientError { error })?;

            let r_processing = futures::select! {
                res = processor.fuse() => res,
                res = writer.fuse() => res
            };

            debug!("Shutdown a client with PK {:?}", &client_pk);

            self.shutdown_client(&client_pk, addr.ip(), addr.port())
                .await
                .map_err(|error| ConnectionError::ShutdownError { error })?;

            r_processing
        };

        Box::new(process.boxed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use failure::Error;

    use crate::toxcore::tcp::codec::Codec;
    use crate::toxcore::tcp::handshake::make_client_handshake;
    use crate::toxcore::tcp::packet::{Packet, PingRequest, PongResponse};

    use crate::toxcore::tcp::server::client::*;

    #[tokio::test]
    async fn run_connection() {
        crypto_init().unwrap();
        let (client_pk, client_sk) = gen_keypair();
        let (server_pk, server_sk) = gen_keypair();

        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut listener = TcpListener::bind(&addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let stats = Stats::new();
        let stats_c = stats.clone();
        let server = async {
            // take the first connection
            let connection = listener.incoming().next().await.unwrap().unwrap();
            Server::new().run_connection(connection, server_sk, stats.clone())
                .map_err(Error::from).await
        };

        let client = async {
            let socket = TcpStream::connect(&addr).map_err(Error::from).await?;
            let (stream, channel) = make_client_handshake(socket, &client_pk, &client_sk, &server_pk)
                .map_err(Error::from).await?;
            let secure_socket = Framed::new(stream, Codec::new(channel, stats_c));
            let (mut to_server, mut from_server) = secure_socket.split();
            let packet = Packet::PingRequest(PingRequest {
                ping_id: 42
            });

            to_server.send(packet).map_err(Error::from).await.unwrap();
            let packet = from_server.next().await.unwrap();

            assert_eq!(packet.unwrap(), Packet::PongResponse(PongResponse {
                ping_id: 42
            }));
            Ok(())

        };

        let both = futures::future::select(server.boxed(), client.boxed());
        let r = both.await.into_inner().0;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn run() {
        tokio::time::pause();
        crypto_init().unwrap();

        let (client_pk, client_sk) = gen_keypair();
        let (server_pk, server_sk) = gen_keypair();

        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(&addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let stats = Stats::new();
        let server = Server::new().run(listener, server_sk, stats.clone(), 1)
            .map_err(Error::from);

        let client = async {
            let socket = TcpStream::connect(&addr).map_err(Error::from).await?;
            let (stream, channel) = make_client_handshake(socket, &client_pk, &client_sk, &server_pk)
                .map_err(Error::from).await?;

            let secure_socket = Framed::new(stream, Codec::new(channel, stats.clone()));
            let (mut to_server, mut from_server) = secure_socket.split();
            let packet = Packet::PingRequest(PingRequest {
                ping_id: 42
            });
            to_server.send(packet).map_err(Error::from).await?;
            let packet = from_server.next().await.unwrap();
            assert_eq!(packet.unwrap(), Packet::PongResponse(PongResponse {
                ping_id: 42
            }));
            // Set time when the client should be pinged
            tokio::time::advance(TCP_PING_FREQUENCY + Duration::from_secs(1)).await;
            while let Some(packet) = from_server.next().await {
                // check the packet
                let _ping_packet = unpack!(packet.unwrap(), Packet::PingRequest);
            }
            Ok(())
        };

        let both = futures::future::select(server.boxed(), client.boxed());
        let r = both.await.into_inner().0;
        assert!(r.is_ok());
    }
}
