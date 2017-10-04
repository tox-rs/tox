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

# Timeout data to store:

- Instant (when was the last interaction with given peer)
- request ID (from PingReq, GetNodes, ..other?)
- PK (unique identifier of a peer)
  - does it really need to be stored? can't it be a reference to PK
    stored somewhere else? it's "just" 32 bytes, but still
    - can it be replaced by futures?

By what storage needs to be accessed:

- timeout, based on Instant::elapsed() < Duration::from_secs(TIMEOUT);
  - sorting according to increasing timeout?
    - multiple storages according to what the timeout is for?
- Request ID: remove NodeTimeout from the queue if IDs match and spawn
  TimeoutFuture


# How it is supposed to work

## Storage for timeouts

- store [`NodeTimeout`] in `VecDeque`
  - separate queues for each [`PacketKind`] request
- append new timeouts at the end of the queue
- `front()` to check if first timeout is to be triggered
  - `pop_front()` to remove timeout from queue if it's past it

### Dependant behaviour

- Once it's past the [`NodeTimeout`], remove it from both queue and:
  - initial implementation: from `Kbucket`
  - better implementation: modify [`NodeState`] in table of `NodeInfo`s,
    and act accordingly to the [`NodeState`]

## Timeout future

Possibly create a new `TimoutFuture` for each known node – future is
created to trigger [`GetNodes`] requests.


[`GetNodes`]: ../dht/struct.GetNodes.html
[`NodeState`]: ./enum.NodeState.html
[`NodeTimeout`]: ./struct.NodeTimeout.html
[`PacketKind`]: ../packet_kind/enum.PacketKind.html
*/

use tokio_proto::multiplex::RequestId;

use std::collections::VecDeque;
use std::ops::Deref;
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeTimeout {
    /**
    `Instant` when we received a valid packet from the node or we sent
    a packet to it to check whether it's still online.

    To check whether timeout has passed:
    `Node.time.elapsed() > Duration::from_secs(SOME_TIMEOUT)`.
    */
    time: Instant,
    /// ID of last sent request.
    id: RequestId,
    /// PK of the node.
    pk: PublicKey,
}

impl NodeTimeout {
    /// Create a new `NodeTimeout`.
    pub fn new(pk: &PublicKey, id: RequestId) -> Self {
        NodeTimeout { time: Instant::now(), id: id, pk: *pk }
    }

    /// Get the ID of last sent request to the node.
    pub fn id(&self) -> RequestId {
        self.id
    }

    /// Get the PK of the node.
    pub fn pk(&self) -> &PublicKey {
        &self.pk
    }

    /// Check whether it's already past the timeout.
    pub fn is_timed_out(&self, secs: u64) -> bool {
        self.time.elapsed() > Duration::from_secs(secs)
    }
}

/**
Store & manage timeout data.

To create new `TimeoutQueue` use `Default` trait:

```
use tox::toxcore::timeout::TimeoutQueue;

let _timeout_queue = TimeoutQueue::default();
```
*/
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TimeoutQueue {
    vec: VecDeque<NodeTimeout>,
}

impl TimeoutQueue {
    /// Number of currently stored timeouts.
    #[cfg(test)] // if used outside of tests add a test
    pub fn len(&self) -> usize {
        self.vec.len()
    }

    /**
    Push the timeout to queue.
    */
    pub fn push(&mut self, nt: NodeTimeout) {
        self.vec.push_back(nt)
    }

    /**
    Create new timeout and add it to the queue
    */
    pub fn add(&mut self, pk: &PublicKey, id: RequestId) {
        self.push(NodeTimeout::new(pk, id));
    }

    /**
    Remove timeout with supplied ID and all timeouts that have same PK
    as the removed timeout.

    Returns `true` if there was at least 1 timeout that was removed,
    `false` otherwise.
    */
    pub fn remove(&mut self, id: RequestId) -> bool {
        match self.vec.iter().position(|nt| nt.id() == id) {
            Some(pos) => {
                if let Some(rm) = self.vec.remove(pos) {
                    self.vec.retain(|nt| nt.pk() != rm.pk());
                }
                true
            },
            None => false
        }
    }

    /**
    Remove from `TimeoutQueue` and return all `PublicKey`s of nodes that
    timed out.

    **Note**: Returns an empty `Vec` if there are no nodes that have
    timed out.
    */
    pub fn get_timed_out(&mut self, secs: u64) -> Vec<PublicKey> {
        let mut ret = Vec::new();

        loop {
            match self.vec.front() {
                Some(node) if node.is_timed_out(secs) => {},
                // no timed out nodes remain
                _ => break,
            }

            if let Some(node) = self.vec.pop_front() {
                ret.push(*node.pk());
            }
        }

        ret
    }
}

impl Deref for TimeoutQueue {
    type Target = VecDeque<NodeTimeout>;

    fn deref(&self) -> &Self::Target {
        &self.vec
    }
}



#[cfg(test)]
mod test {
    use quickcheck::{Arbitrary, Gen, TestResult};

    use std::time::Duration;

    use toxcore::crypto_core::*;
    use toxcore::timeout::*;
    use std::thread;


    // NodeTimeout::

    impl Arbitrary for NodeTimeout {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let mut bytes = [0; PUBLICKEYBYTES];
            g.fill_bytes(&mut bytes);
            NodeTimeout::new(&PublicKey(bytes), g.gen())
        }
    }


    // NodeTimeout::new()

    quickcheck! {
        fn node_timeout_new_test(nt: NodeTimeout, id: u64) -> () {
            assert!(Duration::from_secs(1) > nt.time.elapsed());

            let pk = PublicKey([0; PUBLICKEYBYTES]);
            let nt2 = NodeTimeout::new(&pk, id);
            assert_eq!(nt2.pk(), &pk);
            assert_eq!(id, nt2.id);

            assert_ne!(nt.pk(), nt2.pk());
            assert!(nt.time < nt2.time);
        }
    }

    // NodeTimeout::id()

    quickcheck! {
        fn node_timeout_id_test(nt: NodeTimeout, id: u64) -> () {
            let mut nt = nt;
            nt.id = id;
            assert_eq!(id, nt.id());
        }
    }

    // NodeTimeout::pk()

    quickcheck! {
        fn node_timeout_pk_test(nt: NodeTimeout) -> () {
            assert_eq!(nt.pk(), &nt.pk);
        }
    }

    // NodeTimeout::timed_out()

    #[test]
    fn node_timeout_is_timed_out_test() {
        let nt = NodeTimeout::new(&PublicKey([0; PUBLICKEYBYTES]), 0);
        assert!(nt.is_timed_out(0));
        assert!(!nt.is_timed_out(1));
        thread::sleep(Duration::from_secs(1));
        assert!(nt.is_timed_out(1));
        thread::sleep(Duration::from_secs(1));
        assert!(nt.is_timed_out(2));
    }


    // TimeoutQueue::

    // TimeoutQueue::push()

    quickcheck! {
        fn timeout_queue_push_test(nts: Vec<NodeTimeout>) -> TestResult {
            if nts.is_empty() { return TestResult::discard() }

            let mut tq = TimeoutQueue::default();

            for (n, nt) in nts.iter().enumerate() {
                assert_eq!(n, tq.vec.len());
                tq.push(*nt);
                assert_eq!(nt, tq.vec.get(n).unwrap());
            }
            TestResult::passed()
        }
    }


    // TimeoutQueue::add()

    quickcheck! {
        fn timeout_queue_add_test(id: u64) -> () {
            let mut tq = TimeoutQueue::default();
            let (pk, _) = gen_keypair();
            tq.add(&pk, id);
            assert_eq!(&pk, tq.vec.get(0).unwrap().pk());
            assert_eq!(id, tq.vec.get(0).unwrap().id());
        }
    }

    // TimeoutQueue::remove()

    quickcheck! {
        fn timeout_queue_remove_test(nts: Vec<NodeTimeout>, id: u64)
            -> TestResult
        {
            if nts.is_empty() { return TestResult::discard() }

            let mut tq = TimeoutQueue::default();
            for nt in &nts {
                tq.push(*nt);
            }

            for (num, nt) in nts.iter().enumerate() {
                assert!(tq.remove(nt.id()));
                assert!(!tq.remove(nt.id()));
                assert_eq!(nts.len() - (num + 1), tq.vec.len());
                // rest of timeouts is still there
                assert_eq!(&nts[num + 1..],
                    tq.vec.iter().map(|n| *n)
                    .collect::<Vec<_>>().as_slice());
            }
            assert!(tq.vec.is_empty());

            // timeout with different ID, but same PK also get removed
            let ntout = NodeTimeout::new(nts[0].pk(), id);
            tq.push(nts[0]);
            tq.push(ntout);
            tq.remove(nts[0].id());
            assert!(tq.vec.is_empty());

            TestResult::passed()
        }
    }

    // TimeoutQueue::get_timed_out()

    quickcheck! {
        fn timeout_queue_get_timed_out_test(nts: Vec<NodeTimeout>)
            -> TestResult
        {
            if nts.is_empty() { return TestResult::discard() }

            let mut tq = TimeoutQueue::default();
            assert!(tq.get_timed_out(0).is_empty());

            for (n, nt) in nts.iter().enumerate() {
                tq.push(*nt);
                assert!(tq.get_timed_out(1).is_empty());
                assert_eq!(n + 1, tq.vec.len());
            }

            assert_eq!(nts.iter().map(|nt| *nt.pk()).collect::<Vec<_>>(),
                       tq.get_timed_out(0));
            assert!(tq.vec.is_empty());

            ////

            let nodetimeout = {
                let mut nt = nts[0];
                nt.time = nt.time - Duration::from_secs(1);
                nt
            };

            tq.push(nodetimeout);

            for nt in &nts[1..] {
                tq.push(*nt);
            }
            assert_eq!(vec![*nodetimeout.pk()], tq.get_timed_out(1));

            TestResult::passed()
        }
    }

    // TimeoutQueue::deref()

    #[test]
    fn timeout_queue_deref_test() {
        let tq = TimeoutQueue::default();
        assert_eq!(&tq.vec, tq.deref());
    }
}
