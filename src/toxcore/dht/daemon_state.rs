/*!
Serialize or deserialize states of tox daemon.
When toxcore starts, it deserializes states from serialized file.
Toxcore daemon may serialize its states to file with some interval.
*/

use futures::{future, Future, Stream, stream};
use futures::future::Either;

use toxcore::dht::server::*;
use toxcore::dht::packed_node::*;
use toxcore::state_format::old::*;
use toxcore::binary_io::*;
use toxcore::dht::kbucket::*;
use toxcore::error::*;

/// Serialize or deserialize states of DHT close lists
#[derive(Clone, Debug)]
pub struct DaemonState;

/// Close list has DhtNode, but when we access it with iter(), DhtNode is reformed to PackedNode
pub const DHT_STATE_BUFFER_SIZE: usize =
    // Kbucket size
    (
        // PackedNode size
        (
            32 + // PK size
            19   // SocketAddr maximum size
        ) * KBUCKET_DEFAULT_SIZE as usize // num of DhtNodes per Kbucket : 8
    ) * KBUCKET_MAX_ENTRIES as usize; // 255

impl DaemonState {
    /// Serialize DHT states, old means that the format of seriaization is old version
    pub fn serialize_old(server: &Server) -> Vec<u8> {
        let close_nodes = server.close_nodes.read();

        let nodes = close_nodes.iter()
            .flat_map(|node| node.to_packed_node())
            .collect::<Vec<PackedNode>>();

        let mut buf = [0u8; DHT_STATE_BUFFER_SIZE];
        let (_, buf_len) = DhtState(nodes).to_bytes((&mut buf, 0)).expect("DhtState(nodes).to_bytes has failed");

        buf[..buf_len].to_vec()
    }

    /// Deserialize DHT close list and then re-setup close list, old means that the format of deserialization is old version
    pub fn deserialize_old(server: &Server, serialized_data: &[u8]) -> impl Future<Item=(), Error=Error> + Send {
        let nodes = match DhtState::from_bytes(serialized_data) {
            IResult::Done(_, DhtState(nodes)) => nodes,
            IResult::Incomplete(needed) =>
                return Either::A(future::err(Error::incomplete(needed, serialized_data.to_vec()))),
            IResult::Error(error) =>
                return Either::A(future::err(Error::deserialize(error, serialized_data.to_vec()))),
        };

        let mut request_queue = server.request_queue.write();
        let nodes_sender = nodes.iter()
            .map(|node| server.send_nodes_req(node, &mut request_queue, server.pk));

        let nodes_stream = stream::futures_unordered(nodes_sender).then(|_| Ok(()));
        Either::B(nodes_stream.for_each(|()| Ok(())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use toxcore::crypto_core::*;
    use toxcore::dht::packet::*;

    use futures::sync::mpsc;
    use std::net::SocketAddr;
    use nom::{Needed, ErrorKind as nomErrorKind};

    macro_rules! unpack {
        ($variable:expr, $variant:path) => (
            match $variable {
                $variant(inner) => inner,
                other => panic!("Expected {} but got {:?}", stringify!($variant), other),
            }
        )
    }

    #[test]
    fn daemon_state_serialize_deserialize() {
        let (pk, sk) = gen_keypair();
        let (tx, rx) = mpsc::unbounded::<(Packet, SocketAddr)>();
        let alice = Server::new(tx, pk, sk);

        let addr_org = "1.2.3.4:1234".parse().unwrap();
        let pk_org = gen_keypair().0;
        let pn = PackedNode { pk: pk_org, saddr: addr_org };
        alice.close_nodes.write().try_add(&pn);

        let serialized_vec = DaemonState::serialize_old(&alice);
        DaemonState::deserialize_old(&alice, &serialized_vec).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr_org);

        let sending_packet = unpack!(packet, Packet::NodesRequest);

        assert_eq!(sending_packet.pk, pk);

        // test with incompleted serialized data
        let serialized_vec = DaemonState::serialize_old(&alice);
        let serialized_len = serialized_vec.len();
        match DaemonState::deserialize_old(&alice, &serialized_vec[..serialized_len - 1]).wait() {
            Ok(_) => assert!(false),
            Err(error) => {
                assert_eq!(*error.kind(), ErrorKind::IncompleteData { needed: Needed::Size(55), data: serialized_vec[..serialized_len - 1].to_vec() });
            }
        }

        // test with serialized data corrupted
        let serialized_vec = [42; 10];
        match DaemonState::deserialize_old(&alice, &serialized_vec).wait() {
            Ok(_) => assert!(false),
            Err(error) => {
                assert_eq!(*error.kind(), ErrorKind::Deserialize { error: nomErrorKind::Tag, data: serialized_vec.to_vec() });
            }
        }

        // test with empty close list
        alice.close_nodes.write().remove(&pk_org);
        let serialized_vec = DaemonState::serialize_old(&alice);
        assert!(DaemonState::deserialize_old(&alice, &serialized_vec).wait().is_ok());
    }
}
