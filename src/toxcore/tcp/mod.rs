/*! TCP handshake and Packet handling

*/

pub mod handshake;
pub mod secure;
pub mod packet;
pub mod codec;
pub mod server;
pub mod client;

#[cfg(test)]
mod tests {
    use toxcore::crypto_core::*;
    use toxcore::tcp::server::*;
    use toxcore::tcp::client::*;
    use toxcore::tcp::packet::*;

    #[test]
    fn client_server_processor() {
        use futures::{Stream, Sink, Future};
        use std::io::{Error, ErrorKind};
        use tokio;

        let (client_pk, _sk) = gen_keypair();

        // Create ClientProcessor
        let ClientProcessor {
            from_client_tx,
            to_client_rx,
            from_server_tx,
            to_server_rx,
            processor
        } = ClientProcessor::new();
        let client_processor = processor;
        let outgoing_packets = from_client_tx;
        let incoming_packets = to_client_rx;

        // Create Server with no onion
        let server = Server::new();

        // Create ServerProcessor
        let ServerProcessor {
            from_client_tx,
            to_client_rx,
            processor
        } = ServerProcessor::create(
            server,
            client_pk,
            "0.0.0.0".parse().unwrap(),
            0
        );
        let server_processor = processor;

        let from_client_to_server = to_server_rx
            .map_err(|()| Error::from(ErrorKind::UnexpectedEof))
            .forward(from_client_tx.sink_map_err(|_| Error::from(ErrorKind::UnexpectedEof)))
            .map(|_| ());

        let from_server_to_client = to_client_rx
            .map_err(|()| Error::from(ErrorKind::UnexpectedEof))
            .forward(from_server_tx.sink_map_err(|_| Error::from(ErrorKind::UnexpectedEof)))
            .map(|_| ());

        let forwarders = from_client_to_server.join(from_server_to_client).map(|_|());

        let processors = client_processor.join(server_processor).map(|_|());

        let network = forwarders.join(processors).map(|_|());

        let friend_pk = PublicKey([15, 107, 126, 130, 81, 55, 154, 157,
                                192, 117, 0, 225, 119, 43, 48, 117,
                                84, 109, 112, 57, 243, 216, 4, 171,
                                185, 111, 33, 146, 221, 31, 77, 118]);

        let sender = outgoing_packets.clone()
            .send(OutgoingPacket::RouteRequest(
                RouteRequest { pk: friend_pk }
            ))
            .map(|_| ()).map_err(|_| Error::from(ErrorKind::UnexpectedEof));

        let receiver = incoming_packets
            .into_future().and_then(move |(packet, _tail)| {
                assert_eq!(packet.unwrap(), IncomingPacket::RouteResponse(RouteResponse {
                    connection_id: 16, pk: friend_pk
                }));
                Ok(())
            })
            .map(|_| ()).map_err(|_| Error::from(ErrorKind::UnexpectedEof));

        let sender_receiver = sender.join(receiver).map(|_|());

        let test = sender_receiver.select(network)
            .map(|_| ()).map_err(|(_err, _select_next)| ());

        tokio::run(test);
    }
}
