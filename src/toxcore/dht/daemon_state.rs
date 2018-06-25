/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2018 Namsoo CHO <nscho66@gmail.com>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/


/*!
serialize or deserialize states of tox daemon.
When toxcore start, it deserialize states from serialized file.
Toxcore daemon serializes its states to file every 10 minutes.
*/

use std::io::{Error, ErrorKind};

use futures::{future, Stream, stream};

use toxcore::dht::server::*;
use toxcore::dht::packed_node::*;
use toxcore::dht::server::client::*;
use toxcore::state_format::old::*;
use toxcore::binary_io::*;
use toxcore::io_tokio::*;
use toxcore::dht::kbucket::*;

/// serialize or deserialize states of DHT close lists
#[derive(Clone, Debug)]
pub struct DaemonState;

// close list has DhtNode, but when we access it with iter(), DhtNode is reformed to PackedNode
const DHT_STATE_BUFFER_SIZE: usize =
    // Bucket size
    (
        // PackedNode size
        (
            32 + // PK size
            19   // SocketAddr maximum size
        ) * BUCKET_DEFAULT_SIZE // num of DhtNodes per Bucket : 8
    ) * KBUCKET_MAX_ENTRIES as usize; // 255

impl DaemonState {
    /// serialize DHT states, old means that the format of seriaization is old version
    pub fn serialize_old(server: &Server) -> Vec<u8> {
        let nodes = server.close_nodes.read().iter() // DhtNode is reformed to PackedNode through iter()
            .map(|node| node)
            .collect::<Vec<PackedNode>>();

        let mut buf = [0u8; DHT_STATE_BUFFER_SIZE];
        let (_, buf_len) = DhtState(nodes).to_bytes((&mut buf, 0)).expect("DhtState(nodes).to_bytes has failed");

        buf[..buf_len].to_vec()
    }

    /// deserialize DHT close list and then re-setup close list, old means that the format of deserialization is old version
    pub fn deserialize_old(server: &Server, serialized_data: Vec<u8>) -> IoFuture<()> {
        let nodes = match DhtState::from_bytes(&serialized_data) {
            IResult::Done(_, DhtState(nodes)) => nodes,
            e => return Box::new(
                future::err(
                    Error::new(ErrorKind::Other, format!("Can't deserialize DHT states from serialized file(s) {:?}", e))
                )
            ),
        };

        let mut ping_map = server.ping_map.write();
        let nodes_sender = nodes.iter()
            .map(|node| {
                let client = ping_map.entry(node.pk).or_insert_with(PingData::new);

                server.send_nodes_req(*node, server.pk, client)
            });

        let nodes_stream = stream::futures_unordered(nodes_sender).then(|_| Ok(()));
        Box::new(nodes_stream.for_each(|()| Ok(())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use toxcore::crypto_core::*;
    use toxcore::dht::packet::*;

    use futures::sync::mpsc;
    use std::net::SocketAddr;
    use futures::Future;

    macro_rules! unpack {
        ($variable:expr, $variant:path) => (
            match $variable {
                $variant(inner) => inner,
                other => panic!("Expected {} but got {:?}", stringify!($variant), other),
            }
        )
    }

    #[test]
    fn daemon_state_serialize_deserialize_test() {
        let (pk, sk) = gen_keypair();
        let (tx, rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
        let alice = Server::new(tx, pk, sk);

        let addr_org = "1.2.3.4:1234".parse().unwrap();
        let pk_org = gen_keypair().0;
        let pn = PackedNode { pk: pk_org, saddr: addr_org };
        alice.close_nodes.write().try_add(&pn);

        let serialized_vec = DaemonState::serialize_old(&alice);
        DaemonState::deserialize_old(&alice, serialized_vec).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        assert_eq!(addr_to_send, addr_org);

        let sending_packet = unpack!(packet, DhtPacket::NodesRequest);

        assert_eq!(sending_packet.pk, pk);

        // test with incompleted serialized data
        let serialized_vec = DaemonState::serialize_old(&alice);
        let serialized_len = serialized_vec.len();
        assert!(DaemonState::deserialize_old(&alice, serialized_vec[..serialized_len - 1].to_vec()).wait().is_err());

        // test with empty close list
        alice.close_nodes.write().remove(&pk_org);
        let serialized_vec = DaemonState::serialize_old(&alice);
        assert!(DaemonState::deserialize_old(&alice, serialized_vec).wait().is_ok());
    }
}
