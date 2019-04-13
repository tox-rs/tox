/*! Extension trait for run TCP server on `TcpStream` and ping sender
*/

use std::io::{Error as IoError};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use failure::Fail;
use futures::{future, Future, Sink, Stream};
use futures::sync::mpsc;
use tokio;
use tokio::net::{TcpStream, TcpListener};
use tokio::codec::Framed;
use tokio::prelude::FutureExt;
use tokio::timer::{Error as TimerError, Interval};
use tokio::timer::timeout::{Error as TimeoutError};

use crate::toxcore::crypto_core::*;
use crate::toxcore::tcp::codec::{DecodeError, EncodeError, Codec};
use crate::toxcore::tcp::handshake::make_server_handshake;
use crate::toxcore::tcp::server::{Client, Server};
use crate::toxcore::stats::*;

/// Interval in seconds for Tcp Ping sender
const TCP_PING_INTERVAL: u64 = 1;

/// Timeout in seconds for the TCP handshake.
const TCP_HANDSHAKE_TIMEOUT: u64 = 10;

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
    ServerHandshakeError {
        /// Server handshake error
        #[fail(cause)]
        error: TimeoutError<IoError>
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
}

/// Extension trait for running TCP server on incoming `TcpStream` and ping sender
pub trait ServerExt {
    /// Running TCP ping sender and incoming `TcpStream`. This function uses
    /// `tokio::spawn` inside so it should be executed via tokio to be able to
    /// get tokio default executor.
    fn run(self: Self, listner: TcpListener, dht_sk: SecretKey, stats: Stats, connections_limit: usize) -> Box<Future<Item = (), Error = ServerRunError> + Send>;
    /// Running TCP server on incoming `TcpStream`
    fn run_connection(self: Self, stream: TcpStream, dht_sk: SecretKey, stats: Stats) -> Box<Future<Item = (), Error = ConnectionError> + Send>;
}

impl ServerExt for Server {
    fn run(self: Self, listner: TcpListener, dht_sk: SecretKey, stats: Stats, connections_limit: usize) -> Box<Future<Item = (), Error = ServerRunError> + Send> {
        let connections_count = Arc::new(AtomicUsize::new(0));

        let self_c = self.clone();

        let connections_future = listner.incoming()
            .map_err(|error| ServerRunError::IncomingError { error })
            .for_each(move |stream| {
                if connections_count.load(Ordering::SeqCst) < connections_limit {
                    connections_count.fetch_add(1, Ordering::SeqCst);
                    let connections_count_c = connections_count.clone();
                    tokio::spawn(
                        self_c.clone()
                            .run_connection(stream, dht_sk.clone(), stats.clone())
                            .map_err(|e|
                                error!("Error while running tcp connection: {:?}", e)
                            ).then(move |res| {
                                connections_count_c.fetch_sub(1, Ordering::SeqCst);
                                res
                            })
                    );
                } else {
                    trace!("Tcp server has reached the limit of {} connections", connections_limit);
                }

                Ok(())
            });

        let interval = Duration::from_secs(TCP_PING_INTERVAL);
        let wakeups = Interval::new(Instant::now(), interval);
        let ping_future = wakeups
            .map_err(|error| ServerRunError::PingWakeupsError { error })
            .for_each(move |_instant| {
                trace!("Tcp server ping sender wake up");
                self.send_pings()
                    .map_err(|error| ServerRunError::SendPingsError { error })
            });

        let future = connections_future
            .select(ping_future)
            .map(|_| ()).map_err(|(e, _)| e);

        Box::new(future)
    }

    fn run_connection(self: Self, stream: TcpStream, dht_sk: SecretKey, stats: Stats) -> Box<Future<Item = (), Error = ConnectionError> + Send> {
        let addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(error) => return Box::new(future::err(ConnectionError::PeerAddrError {
                error
            })),
        };

        debug!("A new TCP client connected from {}", addr);

        let register_client = (make_server_handshake(stream, dht_sk.clone()))
            .timeout(Duration::from_secs(TCP_HANDSHAKE_TIMEOUT))
            .map_err(|error| ConnectionError::ServerHandshakeError { error })
            .map(|(stream, channel, client_pk)| {
                debug!("Handshake for TCP client {:?} is completed", client_pk);
                (stream, channel, client_pk)
            });

        let server_c = self.clone();
        let process = register_client.and_then(move |(stream, channel, client_pk)| {
            let secure_socket = Framed::new(stream, Codec::new(channel, stats));
            let (to_client, from_client) = secure_socket.split();
            let (to_client_tx, to_client_rx) = mpsc::channel(SERVER_CHANNEL_SIZE);

            let insert_future = server_c.insert(Client::new(to_client_tx, &client_pk, addr.ip(), addr.port()));

            let server_c_c = server_c.clone();
            // processor = for each Packet from client process it
            let processor = from_client
                .map_err(|error| ConnectionError::DecodePacketError { error })
                .for_each(move |packet| {
                    debug!("Handle {:?} => {:?}", client_pk, packet);
                    server_c_c.handle_packet(&client_pk, packet)
                        .map_err(|error| ConnectionError::PacketHandlingError { error } )
                });

            // writer = for each Packet from to_client_rx send it to client
            let writer = to_client_rx
                .map_err(|()| unreachable!("rx can't fail"))
                .fold(to_client, move |to_client, packet| {
                    trace!("Sending TCP packet {:?} to {:?}", packet, client_pk);
                    to_client.send(packet)
                        .map_err(|error| ConnectionError::SendPacketError {
                            error
                        })
                })
                // drop to_client when to_client_rx stream is exhausted
                .map(|_to_client| ());

            insert_future.map_err(|error| ConnectionError::InsertClientError { error }).and_then(move |()|
                processor
                    .select(writer).map(|_| ()).map_err(|(e, _)| e)
                    .then(move |r_processing| {
                        debug!("Shutdown a client with PK {:?}", &client_pk);
                        // ignore shutdown error since the client can be already
                        // shutdown at this moment
                        server_c.shutdown_client(&client_pk, addr.ip(), addr.port())
                            .then(move |_| r_processing)
                    })
            )
        });

        Box::new(process)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{ErrorKind as IoErrorKind};

    use failure::Error;

    use tokio;
    use tokio::runtime::Runtime;

    use crate::toxcore::tcp::codec::Codec;
    use crate::toxcore::tcp::handshake::make_client_handshake;
    use crate::toxcore::tcp::packet::{Packet, PingRequest, PongResponse};

    use tokio_executor;
    use tokio_timer::clock::*;

    use crate::toxcore::time::*;
    use crate::toxcore::tcp::server::client::*;

    #[test]
    fn server_run_error_display() {
        format!("{}", ServerRunError::IncomingError {
            error: IoError::new(IoErrorKind::Other, "io error"),
        });
        format!("{}", ServerRunError::PingWakeupsError {
            error: TimerError::shutdown(),
        });
        format!("{}", ServerRunError::SendPingsError {
            error: IoError::new(IoErrorKind::Other, "io error"),
        });
    }

    #[test]
    fn connection_error_display() {
        format!("{}", ConnectionError::PeerAddrError {
            error: IoError::new(IoErrorKind::Other, "io error"),
        });
        format!("{}", ConnectionError::SendPacketError {
            error: EncodeError::IoError {
                error: IoError::new(IoErrorKind::Other, "io error"),
            },
        });
        format!("{}", ConnectionError::DecodePacketError {
            error: DecodeError::DecryptError,
        });
        format!("{}", ConnectionError::IncomingError {
            error: IoError::new(IoErrorKind::Other, "io error"),
        });
        format!("{}", ConnectionError::ServerHandshakeError {
            error: TimeoutError::elapsed(),
        });
        format!("{}", ConnectionError::PacketHandlingError {
            error: IoError::new(IoErrorKind::Other, "io error"),
        });
    }

    #[test]
    fn run_connection() {
        let (client_pk, client_sk) = gen_keypair();
        let (server_pk, server_sk) = gen_keypair();

        let addr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(&addr).unwrap();
        let addr = listener.local_addr().unwrap();

        let stats = Stats::new();
        let stats_c = stats.clone();
        let server = listener.incoming()
            .into_future() // take the first connection
            .map_err(|(e, _other_incomings)| Error::from(e))
            .map(|(connection, _other_incomings)| connection.unwrap())
            .and_then(move |stream|
                Server::new().run_connection(stream, server_sk, stats.clone())
                    .map_err(Error::from)
            );

        let client = TcpStream::connect(&addr)
            .map_err(Error::from)
            .and_then(move |socket| {
                make_client_handshake(socket, &client_pk, &client_sk, &server_pk)
                    .map_err(Error::from)
            })
            .and_then(move |(stream, channel)| {
                let secure_socket = Framed::new(stream, Codec::new(channel, stats_c));
                let (to_server, from_server) = secure_socket.split();
                let packet = Packet::PingRequest(PingRequest {
                    ping_id: 42
                });
                to_server.send(packet)
                    .map(|_| from_server)
                    .map_err(Error::from)
            })
            .and_then(|from_server| {
                from_server.into_future()
                    .map(|(packet, _)| packet)
                    .map_err(|(e, _)| Error::from(e))
            })
            .map(|packet| {
                assert_eq!(packet.unwrap(), Packet::PongResponse(PongResponse {
                    ping_id: 42
                }));
            });


        let both = server.join(client)
            .then(|r| {
                assert!(r.is_ok());
                r
            })
            .map(|_| ()).map_err(|_| ());

        tokio::run(both);
    }

    #[test]
    fn run() {
        let (client_pk, client_sk) = gen_keypair();
        let (server_pk, server_sk) = gen_keypair();

        let addr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(&addr).unwrap();
        let addr = listener.local_addr().unwrap();

        let stats = Stats::new();
        let server = Server::new().run(listener, server_sk, stats.clone(), 1)
            .map_err(Error::from);

        let now = Instant::now();
        let mut_now = MutNow::new(now);
        let mut_now_c = mut_now.clone();

        let client = TcpStream::connect(&addr)
            .map_err(Error::from)
            .and_then(move |socket| {
                make_client_handshake(socket, &client_pk, &client_sk, &server_pk)
                    .map_err(Error::from)
            })
            .and_then(move |(stream, channel)| {
                let secure_socket = Framed::new(stream, Codec::new(channel, stats.clone()));
                let (to_server, from_server) = secure_socket.split();
                let packet = Packet::PingRequest(PingRequest {
                    ping_id: 42
                });
                to_server.send(packet)
                    .map(|_| from_server)
                    .map_err(Error::from)
            })
            .and_then(move |from_server| {
                from_server.into_future()
                    .map(move |(packet, from_server_c)| {
                        assert_eq!(packet.unwrap(), Packet::PongResponse(PongResponse {
                            ping_id: 42
                        }));
                        // Set time when the client should be pinged
                        mut_now_c.set(now + Duration::from_secs(TCP_PING_FREQUENCY + 1));
                        from_server_c
                    })
                    .map_err(|(e, _)| Error::from(e))
            })
            .and_then(|from_server| {
                from_server.into_future()
                    .map(|(packet, _)| {
                        let _ping_packet = unpack!(packet.unwrap(), Packet::PingRequest);
                    })
                    .map_err(|(e, _)| Error::from(e))
            });

        let both = server.select(client)
            .then(|r| {
                assert!(r.is_ok());
                r
            })
            .map(|_| ()).map_err(|_| ());

        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(mut_now);
        with_default(&clock, &mut enter, |enter| {
            let mut runtime = Runtime::new().unwrap();
            runtime.spawn(both);
            enter.block_on(runtime.shutdown_on_idle()).unwrap();
        });
    }
}
