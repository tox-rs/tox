/*
    Copyright © 2017 Zetok Zalbavar <zexavexxe@gmail.com>

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
Managing requests IDs and timeouts.

Peers are to be timed out when they do not show any activity before
running into a timeout.

Data associated with timeouts that needs to be stored:

- request ID (from PingReq, GetNodes, ..other?)
- PK (unique identifier of a peer)
  - does it really need to be stored? can't it be a reference to PK
    stored somewhere else? it's "just" 32 bytes, but still
- Instant (when was the last interaction with given peer)

By what storage needs to be accessed:

- timeout, based on Instant::elapsed() < Duration::from_secs(TIMEOUT);
  - sorting according to increasing timeout?
    - multiple storages according to what the timeout is?
- PK (update Instant when receiving incoming packet from peer)
- Request ID (update Instant when receiving response for sent request)
*/


use std::time::{Duration, Instant};

use toxcore::crypto_core::*;


/**
Number of seconds to reach ping timeout. DHT node has to respond to a
[`PingReq`] in less than `PING_TIMEOUT` seconds.

Ping requests are used to check whether node is online, so that it could
be added to own [`DhtNode`]'s `Kbucket` of close nodes.

[`PingReq`]: ../dht/struct.PingReq.html
[`DhtNode`]: ../dht_node/struct.DhtNode.html
*/
pub const PING_TIMEOUT: u64 = 5;

/**
Number of seconds between each time that a DHT node needs to be checked
for responsiveness by sending to it a [`GetNodes`] request.

[`GetNodes`]: ../dht/struct.GetNodes.html
*/
// TODO: rename
pub const RESPONSE_CHECK: u64 = 60;

/**
Number of seconds after which DHT node is considered to be `Bad`. See
[`NodeState`].

[`NodeState`]: ./enum.NodeState.html
*/
pub const BAD_TIME: u64 = RESPONSE_CHECK * 2 + 2;

/**
Number of seconds after which DHT node is considered to be `Unresponsive`.
See [`NodeState`].

[`NodeState`]: ./enum.NodeState.html
*/
pub const UNRESPONSIVE_TIME: u64 = BAD_TIME + RESPONSE_CHECK;


/**
Enum stating whether we consider responsiveness of given DHT node
as `Good`, `Bad` or `Unresponsive`.

Node is considered to be `Good` when it responds to the periodically sent
[`GetNodes`] in less than [`RESPONSE_CHECK`].

When node doesn't respond for [`BAD_NODE_TIME`] seconds it is considered
to be `Bad`.

If a node that is considered to be `Bad` doesn't respond again for
[`RESPONSE_CHECK`] (total [`UNRESPONSIVE_TIME`]) it's marked
as `Unresponsive`, and no longer is being checked for being online.

`Unresponsive` nodes are still being kept around, since there exists a
possibility that due to a network disconnect (going offline due to
factors outside of Tox scope) all nodes would become `Unresponsive`.

In case where `Unresponsive` nodes were to be removed, it would not be
possible to reconnect to the network without bootstrapping again.

However, when all known nodes are `Unresponsive` and are not removed it
should be possible to reconnect to the network via `Unresponsive` nodes,
in which case responding nodes should be marked as `Good` again.

`Bad` and `Unresponsive` nodes should be prioritized for removal when
there are `Good` nodes to replace them.

State of a `Good` node that goes offline:

- `Good` node, [`GetNodes`] is sent
- no response after [`RESPONSE_CHECK`], sending [`GetNodes`] again
- no response after [`BAD_NODE_TIME`], mark node as `Bad`; sending
  [`GetNodes`] again
- no response after [`UNRESPONSIVE_TIME`], mark node as `Unresponsive`,
  do not send anything further to it
  - if all nodes are marked as `Unresponsive` try to send requests to
    them all, hoping that network will become available again

[`BAD_NODE_TIME`]: ./constant.BAD_NODE_TIME.html
[`GetNodes`]: ../dht/struct.GetNodes.html
[`RESPONSE_CHECK`]: ./constant.RESPONSE_CHECK.html
[`UNRESPONSIVE_TIME`]: ./constant.UNRESPONSIVE_TIME.html
*/
// TODO: rename
pub enum NodeState {
    /// Node responds within
    /// [`RESPONSE_CHECK`](./constant.RESPONSE_CHECK.html).
    Good,
    /// Node doesn't respond within
    /// [`BAD_NODE_TIME`](./constant.RESPONSE_CHECK.html).
    Bad,
    /// Node doesn't respond within
    /// [`UNRESPONSIVE_TIME`](./constant.UNRESPONSIVE_TIME.html).
    // TODO: rename
    Unresponsive,
}



/// A DHT node's associated timeout info.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeTimeout {
    /**
    `Instant` when we received a valid packet from the node or we sent
    a packet to it to check whether it's still online.

    To check whether timeout has passed:
    `Node.time.elapsed() > Duration::from_secs(SOME_TIMEOUT)`.
    */
    time: Instant,
    /// ID of last sent request.
    id: u64,
    /// PK of the node.
    pk: PublicKey,
}

impl NodeTimeout {
    /// Create a new `NodeTimeout`.
    pub fn new(pk: &PublicKey) -> Self {
        NodeTimeout { time: Instant::now(), id: 0, pk: *pk }
    }

    /// Get the ID of last sent request to the node.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Set the ID of last request sent.
    pub fn set_id(&mut self, id: u64) {
        self.id = id;
    }

    /// Get the PK of the node.
    pub fn pk(&self) -> &PublicKey {
        &self.pk
    }

    // TODO: add `active(&mut self)` fn to give it a new instant

    // TODO: add `is_timeout(u64) -> bool` fn to check whether given
    //       timeout has already happened
}


#[cfg(test)]
mod test {
    use quickcheck::{Arbitrary, Gen};

    use std::time::Duration;

    use toxcore::crypto_core::*;
    use toxcore::timeout::*;


    // NodeTimeout::

    impl Arbitrary for NodeTimeout {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let mut bytes = [0; PUBLICKEYBYTES];
            g.fill_bytes(&mut bytes);
            NodeTimeout::new(&PublicKey(bytes))
        }
    }


    // NodeTimeout::new()

    quickcheck! {
        fn node_timeout_new_test(nt: NodeTimeout) -> () {
            assert!(Duration::from_secs(1) > nt.time.elapsed());
            assert_eq!(0, nt.id);

            let pk = PublicKey([0; PUBLICKEYBYTES]);
            let nt2 = NodeTimeout::new(&pk);
            assert_eq!(nt2.pk(), &pk);
            assert_ne!(nt.pk(), nt2.pk());
            assert!(nt.time < nt2.time);
        }
    }

    // NodeTimeout::id()

    quickcheck! {
        fn node_timeout_id_test(nt: NodeTimeout, id: u64) -> () {
            let mut nt = nt;
            assert_eq!(0, nt.id());
            nt.id = id;
            assert_eq!(id, nt.id());
        }
    }

    // NodeTimeout::set_id()

    quickcheck! {
        fn node_timeout_set_id_test(nt: NodeTimeout, id: u64) -> () {
            let mut nt = nt;
            assert_eq!(0, nt.id());
            nt.set_id(id);
            assert_eq!(id, nt.id());
        }
    }

    // NodeTimeouts::pk()

    quickcheck! {
        fn node_timeout_pk_test(nt: NodeTimeout) -> () {
            assert_eq!(nt.pk(), &nt.pk);
        }
    }
}
