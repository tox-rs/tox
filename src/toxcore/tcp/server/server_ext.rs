/*! Extension trait for run TCP server on `TcpStream`
*/

use std::io::{Error, ErrorKind};
use std::time::{Duration, Instant};

use futures::{future, Future, Sink, Stream};
use tokio::net::TcpStream;
use tokio::util::FutureExt;
use tokio_codec::Framed;

use toxcore::crypto_core::*;
use toxcore::io_tokio::IoFuture;
use toxcore::tcp::codec::Codec;
use toxcore::tcp::handshake::make_server_handshake;
use toxcore::tcp::server::{Server, ServerProcessor};

/// Extension trait for running TCP server on incoming `TcpStream`
pub trait ServerExt {
    /// Running TCP server on incoming `TcpStream`
    fn run(self: Self, stream: TcpStream, dht_sk: SecretKey) -> IoFuture<()>;
}

impl ServerExt for Server {
    fn run(self: Self, stream: TcpStream, dht_sk: SecretKey) -> IoFuture<()> {
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
                    trace!("Send TCP packet {:?} to {:?}", client_pk, packet);
                    to_client.send(packet)
                        .deadline(Instant::now() + Duration::from_secs(30))
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
    use tokio::net::TcpListener;

    use toxcore::tcp::codec::Codec;
    use toxcore::tcp::handshake::make_client_handshake;
    use toxcore::tcp::packet::{Packet, PingRequest, PongResponse};

    #[test]
    fn run() {
        let (client_pk, client_sk) = gen_keypair();
        let (server_pk, server_sk) = gen_keypair();

        let addr = "127.0.0.1:12345".parse().unwrap();

        let server = TcpListener::bind(&addr).unwrap().incoming()
            .into_future() // take the first connection
            .map_err(|(e, _other_incomings)| e)
            .map(|(connection, _other_incomings)| connection.unwrap())
            .and_then(move |stream|
                Server::new().run(stream, server_sk)
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
}
