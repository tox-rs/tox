/*!
Serialize or deserialize states of tox daemon.
When toxcore starts, it deserializes states from serialized file.
Toxcore daemon may serialize its states to file with some interval.
*/

use futures::{future, Future, Stream, stream};
use futures::future::Either;

use crate::toxcore::dht::server::*;
use crate::toxcore::dht::packed_node::*;
use crate::toxcore::state_format::old::*;
use crate::toxcore::binary_io::*;
use crate::toxcore::dht::kbucket::*;
use crate::toxcore::dht::ktree::*;

use std::fmt;

use failure::{Backtrace, Context, Fail};
use nom::{Needed, ErrorKind as NomErrorKind};

/// An error that can occur while serializing/deserializing object
#[derive(Debug)]
pub struct DeserializeError {
    ctx: Context<DeserializeErrorKind>,
}

impl DeserializeError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &DeserializeErrorKind {
        self.ctx.get_context()
    }

    pub(crate) fn incomplete(needed: Needed, data: Vec<u8>) -> DeserializeError {
        DeserializeError::from(DeserializeErrorKind::IncompleteData { needed, data })
    }

    pub(crate) fn deserialize(error: NomErrorKind, data: Vec<u8>) -> DeserializeError {
        DeserializeError::from(DeserializeErrorKind::Deserialize { error, data })
    }
}

impl Fail for DeserializeError {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeserializeErrorKind {
    /// Error indicates that object can't be parsed.
    Deserialize {
        /// Parsing error
        error: NomErrorKind,
        /// Object serialized data
        data: Vec<u8>,
    },
    /// Error indicates that more data is needed to parse serialized object.
    IncompleteData {
        /// Required data size to be parsed
        needed: Needed,
        /// Object serialized data
        data: Vec<u8>,
    },
}

impl fmt::Display for DeserializeErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DeserializeErrorKind::Deserialize { ref error, ref data } => {
                write!(f, "Deserialize object error: {:?}, data: {:?}", error, data)
            },
            DeserializeErrorKind::IncompleteData { ref needed, ref data } => {
                write!(f, "Bytes of object should not be incomplete: {:?}, data: {:?}", needed, data)
            },
        }
    }
}

impl From<DeserializeErrorKind> for DeserializeError {
    fn from(kind: DeserializeErrorKind) -> DeserializeError {
        DeserializeError::from(Context::new(kind))
    }
}

impl From<Context<DeserializeErrorKind>> for DeserializeError {
    fn from(ctx: Context<DeserializeErrorKind>) -> DeserializeError {
        DeserializeError { ctx }
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
    pub fn deserialize_old(server: &Server, serialized_data: &[u8]) -> impl Future<Item=(), Error=DeserializeError> + Send {
        let nodes = match DhtState::from_bytes(serialized_data) {
            IResult::Done(_, DhtState(nodes)) => nodes,
            IResult::Incomplete(needed) =>
                return Either::A(future::err(DeserializeError::incomplete(needed, serialized_data.to_vec()))),
            IResult::Error(error) =>
                return Either::A(future::err(DeserializeError::deserialize(error, serialized_data.to_vec()))),
        };

        let nodes_sender = nodes.iter()
            .map(|node| server.ping_node(node));

        let nodes_stream = stream::futures_unordered(nodes_sender).then(|_| Ok(()));
        Either::B(nodes_stream.for_each(|()| Ok(())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::toxcore::crypto_core::*;
    use crate::toxcore::dht::packet::*;

    use futures::sync::mpsc;

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
        let (tx, rx) = mpsc::channel(1);
        let alice = Server::new(tx, pk, sk);

        let addr_org = "1.2.3.4:1234".parse().unwrap();
        let pk_org = gen_keypair().0;
        let pn = PackedNode { pk: pk_org, saddr: addr_org };
        alice.close_nodes.write().try_add(pn);

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
        let res = DaemonState::deserialize_old(&alice, &serialized_vec[..serialized_len - 1]).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), DeserializeErrorKind::IncompleteData { needed: Needed::Size(55), data: serialized_vec[..serialized_len - 1].to_vec() });

        // test with serialized data corrupted
        let serialized_vec = [42; 10];
        let res = DaemonState::deserialize_old(&alice, &serialized_vec).wait();
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), DeserializeErrorKind::Deserialize { error: NomErrorKind::Tag, data: serialized_vec.to_vec() });

        // test with empty close list
        alice.close_nodes.write().remove(&pk_org);
        let serialized_vec = DaemonState::serialize_old(&alice);
        assert!(DaemonState::deserialize_old(&alice, &serialized_vec).wait().is_ok());
    }

    #[test]
    fn ser_de_error() {
        let error = DeserializeError::deserialize(NomErrorKind::Eof, vec![1,2,3,4]);
        assert!(error.cause().is_none());
        assert!(error.backtrace().is_some());
        assert_eq!(format!("{}", error), "Deserialize object error: Eof, data: [1, 2, 3, 4]".to_owned());
    }

    #[test]
    fn ser_de_error_kind() {
        let incomplete = DeserializeErrorKind::IncompleteData { needed: Needed::Size(5), data: vec![1,2,3,4] };
        assert_eq!(format!("{}", incomplete), "Bytes of object should not be incomplete: Size(5), data: [1, 2, 3, 4]".to_owned());
        let deserialize = DeserializeErrorKind::Deserialize { error: NomErrorKind::Eof, data: vec![1,2,3,4] };
        assert_eq!(format!("{}", deserialize), "Deserialize object error: Eof, data: [1, 2, 3, 4]".to_owned());
    }
}
