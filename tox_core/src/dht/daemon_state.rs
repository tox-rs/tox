/*!
Serialize or deserialize states of tox daemon.
When toxcore starts, it deserializes states from serialized file.
Toxcore daemon may serialize its states to file with some interval.
*/

use futures::future;

use crate::dht::server::*;
use crate::state_format::old::*;
use tox_binary_io::*;
use crate::dht::kbucket::*;
use crate::dht::ktree::*;

use thiserror::Error;
use nom::{Err, error::Error as NomError};

/// An error that can occur while serializing/deserializing object.
#[derive(Debug, PartialEq, Error)]
pub enum DeserializeError {
    /// Error indicates that object can't be parsed.
    #[error("Deserialize object error: {:?}, data: {:?}", error, data)]
    Deserialize {
        /// Parsing error.
        error: nom::Err<NomError<Vec<u8>>>,
        /// Object serialized data.
        data: Vec<u8>,
    },
}

impl DeserializeError {
    pub(crate) fn deserialize(e: Err<NomError<&[u8]>>, data: Vec<u8>) -> DeserializeError {
        DeserializeError::Deserialize { error: e.map(|e| NomError::new(e.input.to_vec(), e.code)), data }
    }
}

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
    pub async fn serialize_old(server: &Server) -> Vec<u8> {
        let nodes = server.get_all_nodes().await;

        let mut buf = [0u8; DHT_STATE_BUFFER_SIZE];
        let (_, buf_len) = DhtState(nodes).to_bytes((&mut buf, 0)).expect("DhtState(nodes).to_bytes has failed");

        buf[..buf_len].to_vec()
    }

    /// Deserialize DHT close list and then re-setup close list, old means that the format of deserialization is old version
    pub async fn deserialize_old(server: &Server, serialized_data: &[u8]) -> Result<(), DeserializeError> {
        let nodes = match DhtState::from_bytes(serialized_data) {
            Err(error) => {
                return Err(DeserializeError::deserialize(error, serialized_data.to_vec()))
            },
            Ok((_, DhtState(nodes))) => {
                nodes
            }
        };

        let nodes_sender = nodes.into_iter()
            .map(|node| server.ping_node(node));

        future::join_all(nodes_sender).await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::thread_rng;
    use tox_crypto::*;
    use tox_packet::dht::*;
    use tox_packet::dht::packed_node::*;

    use futures::channel::mpsc;
    use futures::StreamExt;
    use nom::error::ErrorKind as NomErrorKind;

    macro_rules! unpack {
        ($variable:expr, $variant:path) => (
            match $variable {
                $variant(inner) => inner,
                other => panic!("Expected {} but got {:?}", stringify!($variant), other),
            }
        )
    }

    #[tokio::test]
    async fn daemon_state_serialize_deserialize() {
        let mut rng = thread_rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let (tx, rx) = mpsc::channel(1);
        let alice = Server::new(tx, pk.clone(), sk);

        // test with empty close list
        let serialized_vec = DaemonState::serialize_old(&alice).await;
        assert!(DaemonState::deserialize_old(&alice, &serialized_vec).await.is_ok());

        let addr_org = "1.2.3.4:1234".parse().unwrap();
        let pk_org = SecretKey::generate(&mut rng).public_key();
        let pn = PackedNode { pk: pk_org.clone(), saddr: addr_org };
        alice.add_node(pn).await;

        let serialized_vec = DaemonState::serialize_old(&alice).await;
        DaemonState::deserialize_old(&alice, &serialized_vec).await.unwrap();

        let (received, _rx) = rx.into_future().await;
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr_org);

        let sending_packet = unpack!(packet, Packet::NodesRequest);

        assert_eq!(sending_packet.pk, pk);

        // test with incompleted serialized data
        let serialized_vec = DaemonState::serialize_old(&alice).await;
        let serialized_len = serialized_vec.len();
        let res = DaemonState::deserialize_old(&alice, &serialized_vec[..serialized_len - 1]).await;
        let error = res.err().unwrap();
        let mut input = vec![2, 1, 2, 3, 4, 4, 210];
        input.extend_from_slice(&pk_org.as_bytes()[..crypto_box::KEY_SIZE - 1]);
        assert_eq!(error, DeserializeError::Deserialize { error: Err::Error(NomError::new(
            input, NomErrorKind::Eof)), data: serialized_vec[..serialized_len - 1].to_vec() });

        // test with serialized data corrupted
        let serialized_vec = [42; 10];
        let res = DaemonState::deserialize_old(&alice, &serialized_vec).await;
        let error = res.err().unwrap();
        assert_eq!(error, DeserializeError::Deserialize { error: Err::Error(NomError::new(
            vec![42; 10], NomErrorKind::Tag)), data: serialized_vec.to_vec() });
    }
}
