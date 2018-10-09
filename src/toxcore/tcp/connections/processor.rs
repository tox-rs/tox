/*! The implementation of TCP Connections Processor
*/

use toxcore::tcp::connections::connection::*;
use toxcore::io_tokio::IoFuture;
use toxcore::tcp::packet::*;
use toxcore::crypto_core::PublicKey;

use futures::prelude::*;
use futures::sync::mpsc;

use std::io::{Error, ErrorKind};

/** `ConnectionsProcessor` helps you to manage logic for multiple tcp connections.
*/
pub struct ConnectionsProcessor {
    /// Send packets of type `OutgoingPacket` to server
    pub from_net_crypto_tx: mpsc::UnboundedSender<(OutgoingPacket, PublicKey)>,
    /// NetCrypto is notified with each packets of type `IncomingPacket`
    pub to_net_crypto_rx: mpsc::UnboundedReceiver<(IncomingPacket, PublicKey)>,

    /// Send packets of type `Packet` to NetCrypto
    pub from_server_tx: mpsc::UnboundedSender<(Packet, PublicKey)>,
    /// NetCrypto is notified with each `Packet`
    pub to_server_rx: mpsc::UnboundedReceiver<(Packet, PublicKey)>,

    /// Run this future to process connections
    pub processor: IoFuture<()>
}

impl ConnectionsProcessor {
    /** Create a new `ConnectionsProcessor`
    */
    pub fn new() -> ConnectionsProcessor {
        let (from_net_crypto_tx, from_net_crypto_rx) = mpsc::unbounded();
        let (to_net_crypto_tx, to_net_crypto_rx) = mpsc::unbounded();

        let (from_server_tx, from_server_rx) = mpsc::unbounded();
        let (to_server_tx, to_server_rx) = mpsc::unbounded();

        let connection = Connection::new(to_server_tx.clone(), to_net_crypto_tx.clone());

        let connection_c = connection.clone();
        let process_messages_from_server = from_server_rx
            .map_err(|_| Error::from(ErrorKind::UnexpectedEof))
            .for_each(move |(packet, connection_id)| -> IoFuture<()> {
                debug!("Handle packet from server: {:?}", packet);
                connection_c.handle_from_server(packet, connection_id)
            })
            .then(|res| {
                debug!("process_messages_from_server ended with {:?}", res);
                res
            });

        let connection_c = connection.clone();
        let process_messages_from_net_crypto = from_net_crypto_rx
            .map_err(|()| Error::from(ErrorKind::UnexpectedEof))
            .for_each(move |(packet, connection_id)| -> IoFuture<()> {
                debug!("Handle packet from net_crypto: {:?}", packet);
                connection_c.handle_from_net_crypto(packet, connection_id)
            })
            .then(|res| {
                debug!("process_messages_from_net_crypto ended with {:?}", res);
                res
            });

        let processor = process_messages_from_server
            .select(process_messages_from_net_crypto)
            .map(|_| ())
            .map_err(|(err, _select_next)| err);

        let processor = Box::new(processor);

        ConnectionsProcessor { from_net_crypto_tx, to_net_crypto_rx, from_server_tx, to_server_rx, processor }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::Future;
    use tokio;

    #[test]
    fn connections_processor_shutdown_client() {
        // Create ClientProcessor
        let ConnectionsProcessor {
            from_net_crypto_tx,
            to_net_crypto_rx,
            from_server_tx,
            to_server_rx,
            processor
        } = ConnectionsProcessor::new();
        let connections_processor = processor.map_err(|_| ());

        // shutdown client channel = shutdown client
        drop(from_net_crypto_tx);
        drop(to_net_crypto_rx);

        let _from_server_tx = from_server_tx;
        let _to_server_rx = to_server_rx;

        tokio::run(connections_processor);
    }

    #[test]
    fn connections_processor_shutdown_server() {
        // Create ClientProcessor
        let ConnectionsProcessor {
            from_net_crypto_tx,
            to_net_crypto_rx,
            from_server_tx,
            to_server_rx,
            processor
        } = ConnectionsProcessor::new();
        let connections_processor = processor.map_err(|_| ());

        // shutdown server channel = shutdown server
        drop(from_server_tx);
        drop(to_server_rx);

        let _from_net_crypto_tx = from_net_crypto_tx;
        let _to_net_crypto_rx = to_net_crypto_rx;

        tokio::run(connections_processor);
    }
}
