//! Extension trait for running DHT server on `UdpSocket`

use std::io::{Error, ErrorKind};
use std::net::{SocketAddr, IpAddr};
use std::pin::Pin;

use futures::{Future, FutureExt, SinkExt, StreamExt};
use futures::channel::mpsc::Receiver;
use tokio::net::{UdpSocket};
use failure::Fail;

use crate::toxcore::dht::codec::*;
use crate::toxcore::dht::packet::Packet;
use crate::toxcore::dht::server::Server;
use crate::toxcore::stats::Stats;

/// Extension trait for running DHT server on `UdpSocket`.
pub trait ServerExt {
    /// Run DHT server on `UdpSocket`.
    fn run_socket(self, socket: UdpSocket, rx: Receiver<(Packet, SocketAddr)>, stats: Stats) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>;
}

impl ServerExt for Server {
    fn run_socket(
        self,
        socket: UdpSocket,
        mut rx: Receiver<(Packet, SocketAddr)>,
        stats: Stats
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send>> {
        let udp_addr = socket.local_addr()
            .expect("Failed to get socket address");

        let codec = DhtCodec::new(stats);
        let (mut sink, mut stream) =
            tokio_util::udp::UdpFramed::new(socket, codec).split();

        let self_c = self.clone();

        let network_reader = async move {
            while let Some(event) = stream.next().await {
                match event {
                    Ok((packet, addr)) => {
                        trace!("Received packet {:?}", packet);
                        let res = self_c.handle_packet(packet, addr).await;

                        if let Err(ref err) = res {
                            error!("Failed to handle packet: {:?}", err);
                        }
                    },
                    Err(e) => {
                        error!("packet receive error = {:?}", e);
                        // ignore packet decode errors
                        if *e.kind() != DecodeErrorKind::Io { continue }
                        else {
                            return Err(Error::new(ErrorKind::Other, e.compat()))
                        }
                    }
                }
            }

            Ok(())
        };

        let network_writer = async move {
            while let Some((packet, mut addr)) = rx.next().await {
                // filter out IPv6 packets if node is running in IPv4 mode
                if udp_addr.is_ipv4() && addr.is_ipv6() { continue }

                if udp_addr.is_ipv6() {
                    if let IpAddr::V4(ip) = addr.ip() {
                        addr = SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), addr.port());
                    }
                }

                trace!("Sending packet {:?} to {:?}", packet, addr);
                sink.send((packet, addr)).await
                    .map_err(|e| Error::new(ErrorKind::Other, e.compat()))?
            }

            Ok(())
        };

        let select = async move {
            futures::select! {
                read = network_reader.fuse() => read,
                write = network_writer.fuse() => write,
                run = self.run().fuse() => {
                    let res: Result<_, _> = run;
                    res.map_err(|e| Error::new(ErrorKind::Other, e.compat()))
                }
            }
        };

        Box::pin(select)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::channel::mpsc;
    use futures::TryStreamExt;

    use crate::toxcore::crypto_core::*;
    use crate::toxcore::dht::packet::*;

    #[tokio::test]
    async fn run_socket() {
        crypto_init().unwrap();
        let (client_pk, client_sk) = gen_keypair();
        let (server_pk, server_sk) = gen_keypair();
        let shared_secret = precompute(&server_pk, &client_sk);

        let (tx, rx) = mpsc::channel(32);

        let server = Server::new(tx, server_pk, server_sk);

        // Bind server socket
        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_socket = UdpSocket::bind(&server_addr).await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let stats = Stats::new();
        let server_future = server.run_socket(server_socket, rx, stats);

        // Bind client socket to communicate with the server
        let client_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let client_socket = UdpSocket::bind(&client_addr).await.unwrap();

        let client_future = async move {
            // Send invalid request first to ensure that the server won't crash
            let mut client_socket = client_socket;
            client_socket.send_to(&[42; 123][..], &server_addr)
                .await
                .map_err(|e| Error::new(ErrorKind::Other, e.compat()))?;

            let stats = Stats::new();
            let codec = DhtCodec::new(stats);
            let (mut sink, stream) = tokio_util::udp::UdpFramed::new(client_socket, codec).split();

            // Send ping request
            let ping_id = 42;
            let ping_request_payload = PingRequestPayload {
                id: ping_id,
            };
            let ping_request = PingRequest::new(&shared_secret, &client_pk, &ping_request_payload);

            sink.send((Packet::PingRequest(ping_request), server_addr)).await
                .map_err(|e| Error::new(ErrorKind::Other, e.compat()))?;

            // And wait for ping response
            let ping_response = stream
                .try_filter_map(|(packet, _)| futures::future::ok(
                    match packet {
                        Packet::PingResponse(ping_response) => Some(ping_response),
                        _ => None,
                    }
                ))
                .next()
                .await
                .unwrap();

            let ping_response = ping_response
                .map_err(|e| Error::new(ErrorKind::Other, e.compat()))?;
            let ping_response_payload = ping_response.get_payload(&shared_secret).unwrap();

            assert_eq!(ping_response_payload.id, ping_id);

            let res: Result<_, Error> = Ok(());
            res
        };

        futures::select! {
            res = client_future.fuse() => res.unwrap(),
            res = server_future.fuse() => ()
        };
    }
}
