//! Extension trait for running DHT server on `UdpSocket`

use std::io::{Error, ErrorKind};
use std::net::{SocketAddr, IpAddr};

use futures::{future, Future, Sink, Stream};
use futures::sync::mpsc::Receiver;
use tokio::net::{UdpSocket, UdpFramed};
use failure::Fail;

use crate::toxcore::dht::codec::*;
use crate::toxcore::dht::packet::Packet;
use crate::toxcore::dht::server::Server;
use crate::toxcore::stats::Stats;

/// Extension trait for running DHT server on `UdpSocket`.
pub trait ServerExt {
    /// Run DHT server on `UdpSocket`.
    fn run_socket(self, socket: UdpSocket, rx: Receiver<(Packet, SocketAddr)>, stats: Stats) -> Box<Future<Item = (), Error = Error> + Send>;
}

impl ServerExt for Server {
    fn run_socket(self, socket: UdpSocket, rx: Receiver<(Packet, SocketAddr)>, stats: Stats) -> Box<Future<Item = (), Error = Error> + Send> {
        let udp_addr = socket.local_addr()
            .expect("Failed to get socket address");

        let codec = DhtCodec::new(stats);
        let (sink, stream) = UdpFramed::new(socket, codec).split();

        let self_c = self.clone();
        let network_reader = stream.then(future::ok).filter(|event|
            match event {
                Ok(_) => true,
                Err(ref e) => {
                    error!("packet receive error = {:?}", e);
                    // ignore packet decode errors
                    *e.kind() == DecodeErrorKind::Io
                }
            }
        ).and_then(|event| event).for_each(move |(packet, addr)| {
            trace!("Received packet {:?}", packet);
            self_c.handle_packet(packet, addr).or_else(|err| {
                error!("Failed to handle packet: {:?}", err);
                future::ok(())
            })
        }).map_err(|e| Error::new(ErrorKind::Other, e.compat()));

        let network_writer = rx
            .map_err(|()| unreachable!("rx can't fail"))
            // filter out IPv6 packets if node is running in IPv4 mode
            .filter(move |&(ref _packet, addr)| !(udp_addr.is_ipv4() && addr.is_ipv6()))
            .fold(sink, move |sink, (packet, mut addr)| {
                if udp_addr.is_ipv6() {
                    if let IpAddr::V4(ip) = addr.ip() {
                        addr = SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), addr.port());
                    }
                }
                trace!("Sending packet {:?} to {:?}", packet, addr);
                sink.send((packet, addr))
                    .map_err(|e| Error::new(ErrorKind::Other, e.compat()))
            })
            // drop sink when rx stream is exhausted
            .map(|_sink| ());

        Box::new(network_reader
            .select(network_writer)
            .map(|_| ())
            .map_err(|(e, _)| e)
            .select(self.run()
                .map_err(|e| Error::new(ErrorKind::Other, e.compat())))
            .map(|_| ())
            .map_err(|(e, _)| e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::sync::mpsc;
    use tokio;

    use crate::toxcore::crypto_core::*;
    use crate::toxcore::dht::packet::*;

    #[test]
    fn run_socket() {
        crypto_init().unwrap();
        let (client_pk, client_sk) = gen_keypair();
        let (server_pk, server_sk) = gen_keypair();
        let shared_secret = precompute(&server_pk, &client_sk);

        let (tx, rx) = mpsc::channel(32);

        let server = Server::new(tx, server_pk, server_sk);

        // Bind server socket
        let server_addr = "127.0.0.1:0".parse().unwrap();
        let server_socket = UdpSocket::bind(&server_addr).unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let stats = Stats::new();
        let server_future = server.run_socket(server_socket, rx, stats);

        // Bind client socket to communicate with the server
        let client_addr = "127.0.0.1:0".parse().unwrap();
        let client_socket = UdpSocket::bind(&client_addr).unwrap();

        // Send invalid request first to ensure that the server won't crash
        let client_future = client_socket.send_dgram(&[42; 123][..], &server_addr).and_then(move |(client_socket, _)| {
            let stats = Stats::new();
            let codec = DhtCodec::new(stats);
            let (sink, stream) = UdpFramed::new(client_socket, codec).split();

            // Send ping request
            let ping_id = 42;
            let ping_request_payload = PingRequestPayload {
                id: ping_id,
            };
            let ping_request = PingRequest::new(&shared_secret, &client_pk, &ping_request_payload);
            let ping_request_future = sink.send((Packet::PingRequest(ping_request), server_addr))
                .map_err(|e| Error::new(ErrorKind::Other, e.compat()));

            // And wait for ping response
            let ping_response_future = stream.filter_map(|(packet, _)| match packet {
                Packet::PingResponse(ping_response) => Some(ping_response),
                _ => None,
            }).into_future().map(move |(ping_response, _)| {
                let ping_response = ping_response.unwrap();
                let ping_response_paylad = ping_response.get_payload(&shared_secret).unwrap();
                assert_eq!(ping_response_paylad.id, ping_id);
            }).map_err(|(e, _)| Error::new(ErrorKind::Other, e.compat()));

            ping_request_future.join(ping_response_future).map(|_| ())
        });

        let future = client_future.select(server_future).map(|_| ()).map_err(|(e, _)| e);
        let future = future.then(|r| {
            assert!(r.is_ok());
            r
        }).map_err(|_| ());

        tokio::run(future);
    }
}
