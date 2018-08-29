/*! Extension trait for run TCP server on `TcpStream` and ping sender
*/

use std::io::{Error, ErrorKind};
use std::time::{Duration, Instant};

use futures::{future, Future, Sink, Stream};
use tokio::net::{TcpStream, TcpListener};
use tokio::util::FutureExt;
use tokio_codec::Framed;
use tokio::timer::Interval;

use toxcore::crypto_core::*;
use toxcore::io_tokio::IoFuture;
use toxcore::tcp::codec::Codec;
use toxcore::tcp::handshake::make_server_handshake;
use toxcore::tcp::server::{Server, ServerProcessor};

/// Interval in seconds for Tcp Ping sender
const TCP_PING_INTERVAL: u64 = 1;

/// Extension trait for running TCP server on incoming `TcpStream` and ping sender
pub trait ServerExt {
    /// Running TCP ping sender and incoming `TcpStream`
    fn run(self: Self, listner: TcpListener, dht_sk: SecretKey) -> IoFuture<()>;
    /// Running TCP server on incoming `TcpStream`
    fn run_connection(self: Self, stream: TcpStream, dht_sk: SecretKey) -> IoFuture<()>;
}

impl ServerExt for Server {
    fn run(self: Self, listner: TcpListener, dht_sk: SecretKey) -> IoFuture<()> {
        let self_c = self.clone();

        let future = listner.incoming()
            .for_each(move |stream|
                self.clone().run_connection(stream, dht_sk.clone())
            );

        let interval = Duration::from_secs(TCP_PING_INTERVAL);
        let wakeups = Interval::new(Instant::now(), interval);
        let ping_sender = wakeups
            .map_err(|e| {
                Error::new(ErrorKind::Other, e)
            })
            .for_each(move |_instant| {
                trace!("Tcp server ping sender wake up");
                self_c.send_pings()
            });

        let future = future
            .select(ping_sender)
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
            let ServerProcessor { from_client_tx, to_client_rx, processor } =
                ServerProcessor::create(
                    server_c,
                    client_pk,
                    addr.ip(),
                    addr.port()
                );

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

            // reader = for each Packet from client send it to server processor
            let reader = from_client
                .forward(from_client_tx
                    .sink_map_err(|e|
                        Error::new(ErrorKind::Other,
                            format!("Could not forward message from TCP client to TCP server {}", e))
                    )
                )
                .map(|(_from_client, _sink_err)| ());

            processor
                .select(reader).map(|_| ()).map_err(|(e, _)| e)
                .select(writer).map(|_| ()).map_err(|(e, _)| e)
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
                make_client_handshake(socket, client_pk, client_sk, server_pk)
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

        let client = TcpStream::connect(&addr)
            .and_then(move |socket| {
                make_client_handshake(socket, client_pk, client_sk, server_pk)
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
                    .map(|(packet, from_server_c)| {
                        assert_eq!(packet.unwrap(), Packet::PongResponse(PongResponse {
                            ping_id: 42
                        }));
                        from_server_c
                    })
                    .map(|from_server_c| from_server_c)
                    .map_err(|(e, _)| e)
            })
            .and_then(|from_server| {
                from_server.into_future()
                    .map(|(packet, _)| {
                        let _ping_packet = unpack!(packet.unwrap(), Packet::PingRequest);
                    })
                    .map_err(|(e, _)| e)
            })
            .map(|_| ());

        let both = server.select(client)
            .then(|r| {
                assert!(r.is_ok());
                r
            })
            .map(|_| ()).map_err(|_| ());

        tokio::run(both);
    }
}
