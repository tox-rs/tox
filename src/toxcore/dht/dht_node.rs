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

/*! Data structure used by Bucket.
PackedNode type contains PK and SocketAddress.
PackedNode does not contain status of Node, this struct contains status of node.
Bucket needs status of node, because BAD status node should be replaced with higher proirity than GOOD node.
Even GOOD node is farther than BAD node, BAD node should be replaced.
Here, GOOD node is the node responded within 162 seconds, BAD node is the node not responded over 162 seconds.
*/

use std::net::SocketAddr;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use toxcore::crypto_core::*;

/** Status of node in bucket.
Good means it is online and responded within 162 seconds
Bad means it is probably offline and did not responded for over 162 seconds
When new peer is added to bucket, Bad status node should be replace.
If there are no Bad nodes in bucket, node which is farther than peer is replaced.

Manage ping_id.
Generate ping_id on request packet, check ping_id on response packet.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NodeStatus {
    /// online
    Good,
    /// maybe offline
    Bad,
}

/** Struct used by Bucket, DHT maintains close node list, when we got new node,
we should make decision to add new node to close node list, or not.
the PK's distance and status of node help making decision.
Bad node have higher priority than Good node.
If both node is Good node, then we compare PK's distance.

Generate ping_id on request packet, check ping_id on response packet.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtNode {
    /// Socket addr of node.
    pub saddr: SocketAddr,
    /// Public Key of the node.
    pub pk: PublicKey,
    /// Status of node
    pub status: NodeStatus,
    /// hash of ping_ids to check PingResponse is correct
    pub ping_hash: HashMap<u64, Instant>,
    /// last received ping/nodes-response time
    pub last_resp_time: Instant,
    /// last sent ping-req time
    pub last_ping_req_time: Instant,
}

impl DhtNode {
    /// create DhtNode object
    pub fn new() -> DhtNode {
        DhtNode {
            pk : gen_keypair().0,
            saddr: "127.0.0.1:33445".parse().unwrap(),
            ping_hash: HashMap::new(),
            last_resp_time: Instant::now(),
            last_ping_req_time: Instant::now(),
            status: NodeStatus::Good,
        }
    }
    /// set new random ping id to the client and return it
    fn generate_ping_id(&mut self) -> u64 {
        loop {
            let ping_id = random_u64();
            if ping_id != 0 && !self.ping_hash.contains_key(&ping_id) {
                return ping_id;
            }
        }
    }

    /// clear timed out ping_id
    pub fn clear_timedout_pings(&mut self, timeout: Duration) {
        self.ping_hash.retain(|&_ping_id, &mut time|
            time.elapsed() <= timeout);
    }

    /// Add a Ping Hash Entry and return a new ping_id.
    pub fn insert_new_ping_id(&mut self) -> u64 {
        let ping_id = self.generate_ping_id();
        self.ping_hash.insert(ping_id, Instant::now());

        ping_id
    }

    /// Check if ping_id is valid and not timed out.
    pub fn check_ping_id(&mut self, ping_id: u64, timeout: Duration) -> bool {
        if ping_id == 0 {
            debug!("Given ping_id is 0");
            return false
        }

        let time_ping_sent = match self.ping_hash.remove(&ping_id) {
            None => {
                debug!("Given ping_id don't exist in PingHash");
                return false
            },
            Some(time) => time,
        };

        if time_ping_sent.elapsed() > timeout {
            debug!("Given ping_id is timed out");
            return false
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_data_clonable() {
        let client = DhtNode::new();
        let _ = client.clone();
    }

    #[test]
    fn client_data_insert_new_ping_id_test() {
        let mut client = DhtNode::new();

        let ping_id = client.insert_new_ping_id();

        assert!(client.ping_hash.contains_key(&ping_id));
    }

    #[test]
    fn client_data_check_ping_id_test() {
        let mut client = DhtNode::new();

        let ping_id = client.insert_new_ping_id();

        let dur = Duration::from_secs(1);
        // give incorrect ping_id
        assert!(!client.check_ping_id(0, dur));
        assert!(!client.check_ping_id(ping_id + 1, dur));

        // Though ping_id is correct, it is timed-out
        let dur = Duration::from_secs(0);
        assert!(!client.check_ping_id(ping_id, dur));

        // Now, timeout duration is 5 seconds
        let dur = Duration::from_secs(5);

        let ping_id = client.insert_new_ping_id();
        assert!(client.check_ping_id(ping_id, dur));
    }

    #[test]
    fn client_data_clear_timedout_pings_test() {
        let mut client = DhtNode::new();

        // ping_id should be removed
        let ping_id = client.insert_new_ping_id();
        let dur = Duration::from_secs(0);
        client.clear_timedout_pings(dur);
        let dur = Duration::from_secs(1);
        assert!(!client.check_ping_id(ping_id, dur));

        // ping_id should remain
        let ping_id = client.insert_new_ping_id();
        let dur = Duration::from_secs(1);
        client.clear_timedout_pings(dur);
        assert!(client.check_ping_id(ping_id, dur));
    }
}
