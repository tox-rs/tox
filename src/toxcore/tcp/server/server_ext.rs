/*! Extension trait for run TCP server on `TcpStream` and ping sender
*/

use std::io::{Error, ErrorKind};
use std::time::{Duration, Instant};

use futures::{future, Future, Sink, Stream};
use futures::sync::mpsc;
use tokio;
use tokio::net::{TcpStream, TcpListener};
use tokio::util::FutureExt;
use tokio_codec::Framed;
use tokio::timer::Interval;

use toxcore::crypto_core::*;
use toxcore::io_tokio::IoFuture;
use toxcore::tcp::codec::Codec;
use toxcore::tcp::handshake::make_server_handshake;
use toxcore::tcp::server::{Client, Server};

/// Interval in seconds for Tcp Ping sender
const TCP_PING_INTERVAL: u64 = 1;

/// Extension trait for running TCP server on incoming `TcpStream` and ping sender
pub trait ServerExt {
    /// Running TCP ping sender and incoming `TcpStream`. This function uses
    /// `tokio::spawn` inside so it should be executed via tokio to be able to
    /// get tokio default executor.
    fn run(self: Self, listner: TcpListener, dht_sk: SecretKey) -> IoFuture<()>;
    /// Running TCP server on incoming `TcpStream`
    fn run_connection(self: Self, stream: TcpStream, dht_sk: SecretKey) -> IoFuture<()>;
}

impl ServerExt for Server {
    fn run(self: Self, listner: TcpListener, dht_sk: SecretKey) -> IoFuture<()> {
        let self_c = self.clone();

        let connections_future = listner.incoming()
            .for_each(move |stream| {
                tokio::spawn(
                    self_c.clone()
                        .run_connection(stream, dht_sk.clone())
                        .map_err(|e| {
                            error!("Error while running tcp connection: {:?}", e);
                            ()
                        })
                );
                Ok(())
            });

        let interval = Duration::from_secs(TCP_PING_INTERVAL);
        let wakeups = Interval::new(Instant::now(), interval);
        let ping_future = wakeups
            .map_err(|e| {
                Error::new(ErrorKind::Other, e)
            })
            .for_each(move |_instant| {
                trace!("Tcp server ping sender wake up");
                self.send_pings()
            });

        let future = connections_future
            .select(ping_future)
            .map(|_| ()).map_err(|(e, _)| e);

        Box::new(future)
    }

    fn run_connection(self: Self, stream: TcpStream, dht_sk: SecretKey) -> IoFuture<()> {
        let addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                error!("Could not get peer addr: {}", e);
                return Box::new(future::err(e))
            },
        };

        debug!("A new TCP client connected from {}", addr);

        let register_client = make_server_handshake(stream, dht_sk.clone())
            .map_err(|e|
                Error::new(ErrorKind::Other, format!("Handshake error: {}", e))
            )
            .map(|(stream, channel, client_pk)| {
                debug!("Handshake for TCP client {:?} is completed", client_pk);
                (stream, channel, client_pk)
            });

        let server_c = self.clone();
        let process = register_client.and_then(move |(stream, channel, client_pk)| {
            let secure_socket = Framed::new(stream, Codec::new(channel));
            let (to_client, from_client) = secure_socket.split();
            let (to_client_tx, to_client_rx) = mpsc::unbounded();

            server_c.insert(Client::new(to_client_tx, &client_pk, addr.ip(), addr.port()));

            let server_c_c = server_c.clone();
            // processor = for each Packet from client process it
            let processor = from_client
                .for_each(move |packet| {
                    debug!("Handle {:?} => {:?}", client_pk, packet);
                    server_c_c.handle_packet(&client_pk, packet)
                });

            // writer = for each Packet from to_client_rx send it to client
            let writer = to_client_rx
                .map_err(|()| Error::from(ErrorKind::UnexpectedEof))
                .fold(to_client, move |to_client, packet| {
                    trace!("Sending TCP packet {:?} to {:?}", packet, client_pk);
                    to_client.send(packet)
                        .timeout(Duration::from_secs(30))
                        .map_err(|e|
                            Error::new(ErrorKind::Other,
                                format!("Writer timed out {}", e))
                        )
                })
                // drop to_client when to_client_rx stream is exhausted
                .map(|_to_client| ());

            processor
                .select(writer).map(|_| ()).map_err(|(e, _)| e)
                .then(move |r_processing| {
                    debug!("Shutdown a client with PK {:?}", &client_pk);
                    server_c.shutdown_client(&client_pk)
                        .then(move |r_shutdown| r_processing.and(r_shutdown))
                })
        });

        Box::new(process)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio;

    use toxcore::tcp::codec::Codec;
    use toxcore::tcp::handshake::make_client_handshake;
    use toxcore::tcp::packet::{Packet, PingRequest, PongResponse};

    use tokio_executor;
    use tokio_timer::clock::*;

    use toxcore::time::*;
    use toxcore::tcp::server::client::*;

    #[test]
    fn run_connection() {
        let (client_pk, client_sk) = gen_keypair();
        let (server_pk, server_sk) = gen_keypair();

        let addr = "127.0.0.1:12345".parse().unwrap();

        let server = TcpListener::bind(&addr).unwrap().incoming()
            .into_future() // take the first connection
            .map_err(|(e, _other_incomings)| e)
            .map(|(connection, _other_incomings)| connection.unwrap())
            .and_then(move |stream|
                Server::new().run_connection(stream, server_sk)
            );

        let client = TcpStream::connect(&addr)
            .and_then(move |socket| {
                make_client_handshake(socket, &client_pk, &client_sk, &server_pk)
            })
            .and_then(|(stream, channel)| {
                let secure_socket = Framed::new(stream, Codec::new(channel));
                let (to_server, from_server) = secure_socket.split();
                let packet = Packet::PingRequest(PingRequest {
                    ping_id: 42
                });
                to_server.send(packet).map(|_| from_server)
            })
            .and_then(|from_server| {
                from_server.into_future()
                    .map(|(packet, _)| packet)
                    .map_err(|(e, _)| e)
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

        let addr = "127.0.0.1:12346".parse().unwrap();

        let listener = TcpListener::bind(&addr).unwrap();
        let server = Server::new().run(listener, server_sk);

        let now = Instant::now();
        let mut_now = MutNow::new(now);
        let mut_now_c = mut_now.clone();

        let client = TcpStream::connect(&addr)
            .and_then(move |socket| {
                make_client_handshake(socket, &client_pk, &client_sk, &server_pk)
            })
            .and_then(|(stream, channel)| {
                let secure_socket = Framed::new(stream, Codec::new(channel));
                let (to_server, from_server) = secure_socket.split();
                let packet = Packet::PingRequest(PingRequest {
                    ping_id: 42
                });
                to_server.send(packet).map(|_| from_server)
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
                    .map_err(|(e, _)| e)
            })
            .and_then(|from_server| {
                from_server.into_future()
                    .map(|(packet, _)| {
                        let _ping_packet = unpack!(packet.unwrap(), Packet::PingRequest);
                    })
                    .map_err(|(e, _)| e)
            });

        let both = server.select(client)
            .then(|r| {
                assert!(r.is_ok());
                r
            })
            .map(|_| ()).map_err(|_| ());

        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(mut_now);
        with_default(&clock, &mut enter, |_| {
            tokio::run(both);
        });
    }
}
