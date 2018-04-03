/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2018 Evgeny Kurnevsky <kurnevsky@gmail.com>

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

/*! The implementation of onion announce
*/

use std::cmp::Ordering;
use std::io::Error;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::onion::packet::*;
use toxcore::dht::kbucket::{Distance, Kbucket};

/// Number of secret random bytes to make onion ping id unique for each node.
pub const SECRET_BYTES_SIZE: usize = 32;

/// Maximum number of entries in onion announce list. When number of entries
/// exceeds this value farthest nodes are dropped using DHT distance function.
pub const ONION_ANNOUNCE_MAX_ENTRIES: usize = 160;

/// Number of seconds when onion ping id is valid after it was generated.
/// To be precise ping id will be valid `PING_ID_TIMEOUT` to
/// 2 * `PING_ID_TIMEOUT` seconds.
pub const PING_ID_TIMEOUT: u64 = 20;

/// Number of seconds that announce entry can be stored in onion announce list
/// without re-announcing.
pub const ONION_ANNOUNCE_TIMEOUT: u64 = 300;

/// Create onion ping id filled with zeros.
pub fn initial_ping_id() -> Digest {
    // can not fail since slice has enough length
    Digest::from_slice(&[0; DIGESTBYTES]).unwrap()
}

/** Entry that corresponds to announced onion node.

When node successfully announce itself this entry is added to announced nodes
list. It's considered expired after `ONION_ANNOUNCE_TIMEOUT` seconds.

*/
#[derive(Clone, Debug, Eq, PartialEq)]
struct OnionAnnounceEntry {
    /// Long term PublicKey of announced node
    pub pk: PublicKey,
    /// IP address of announced node
    pub ip_addr: IpAddr,
    /// Port of announced node
    pub port: u16,
    /// Onion return that should be used to send data packets to announced node
    pub onion_return: OnionReturn,
    /// PublicKey that should be used to encrypt data packets for announced node
    pub data_pk: PublicKey,
    /// Time when this entry was added to the list of announced nodes
    pub time: SystemTime
}

impl OnionAnnounceEntry {
    /// Create new `OnionAnnounceEntry` object using current unix time.
    pub fn new(pk: PublicKey, ip_addr: IpAddr, port: u16, onion_return: OnionReturn, data_pk: PublicKey) -> OnionAnnounceEntry {
        OnionAnnounceEntry {
            pk,
            ip_addr,
            port,
            onion_return,
            data_pk,
            time: SystemTime::now()
        }
    }

    /** Check if this entry is timed out.

    Entry considered timed out after `ONION_ANNOUNCE_TIMEOUT` seconds since it
    was created.

    */
    pub fn is_timed_out(&self) -> bool {
        self.time + Duration::from_secs(ONION_ANNOUNCE_TIMEOUT) <= SystemTime::now()
    }
}

/// Size of serialized `OnionPingData` struct.
const ONION_PING_DATA_SIZE: usize =
    SECRET_BYTES_SIZE +
    /* time */ 8 +
    PUBLICKEYBYTES +
    /* ip_type */ 1 +
    /* ip_addr */ 8 +
    /* port */ 2;

/** Data on the basis of which onion ping id is calculated.

Format of this struct is not specified by tox protocol and can be different in
different implementations. That's possible because this struct is used for onion
ping id generation and only node that generated it can verify it.

Serialized form:

Length   | Content
-------- | ------
`32`     | Secret bytes of onion node
`8`      | Unix time in seconds divided by PING_ID_TIMEOUT
`32`     | `PublicKey` of sender
`1`      | IP type of sender
`8`      | `IpAddr` of sender
`2`      | Port of sender

*/
struct OnionPingData {
    /// Secret bytes of onion node to make onion ping id unique
    pub secret_bytes: [u8; SECRET_BYTES_SIZE],
    /// Can be any time but only current time or current time + `PING_ID_TIMEOUT`
    /// should be used.
    pub time: SystemTime,
    /// `PublicKey` of sender
    pub pk: PublicKey,
    /// `IpAddr` of sender
    pub ip_addr: IpAddr,
    /// Port of sender
    pub port: u16
}

impl ToBytes for OnionPingData {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(&self.secret_bytes) >>
            gen_be_u64!(OnionPingData::unix_time(self.time) / PING_ID_TIMEOUT) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_be_u8!(self.ip_addr.is_ipv4() as u8) >>
            gen_call!(|buf, ip_addr| IpAddr::to_bytes(ip_addr, buf), &self.ip_addr) >>
            gen_be_u16!(self.port)
        )
    }
}

impl OnionPingData {
    /// Return number of seconds that have elapsed since Unix epoch.
    fn unix_time(time: SystemTime) -> u64 {
        let since_the_epoch = time.duration_since(UNIX_EPOCH)
            .expect("Current time is earlier than Unix epoch");
        since_the_epoch.as_secs()
    }

    /** Calculate onion ping id using sha256 hash of stored data.

    Time is divided by `PING_ID_TIMEOUT` so this hash remains unchanged for
    `PING_ID_TIMEOUT` seconds.

    */
    pub fn ping_id(&self) -> Digest {
        let mut buf = [0; ONION_PING_DATA_SIZE];
        // can not fail since buf has enough length
        self.to_bytes((&mut buf, 0)).unwrap();
        hash(&buf)
    }
}

/** Holds list of announced onion nodes and process announce requests.
*/
#[derive(Clone, Debug)]
pub struct OnionAnnounce {
    /// Secret bytes of onion node to make onion ping id unique
    secret_bytes: [u8; SECRET_BYTES_SIZE],
    /// List of announced onion nodes
    entries: Vec<OnionAnnounceEntry>,
    /// Short term DHT `PublicKey`
    dht_pk: PublicKey
}

impl OnionAnnounce {
    /// Create new `OnionAnnounce` instance.
    pub fn new(dht_pk: PublicKey) -> OnionAnnounce {
        let mut secret_bytes = [0; SECRET_BYTES_SIZE];
        randombytes_into(&mut secret_bytes);
        OnionAnnounce {
            secret_bytes,
            entries: Vec::with_capacity(ONION_ANNOUNCE_MAX_ENTRIES),
            dht_pk
        }
    }

    /** Calculate onion ping id using sha256 hash of arguments together with
    secret bytes stored in this struct.

    Time is divided by `PING_ID_TIMEOUT` so this hash remains unchanged for
    `PING_ID_TIMEOUT` seconds.

    */
    fn ping_id(&self, time: SystemTime, pk: PublicKey, ip_addr: IpAddr, port: u16) -> Digest {
        let data = OnionPingData {
            secret_bytes: self.secret_bytes,
            time,
            pk,
            ip_addr,
            port
        };
        data.ping_id()
    }

    /// Find entry by its `PublicKey` ignoring timed out entries
    fn find_in_entries(&self, pk: PublicKey) -> Option<&OnionAnnounceEntry> {
        self.entries.iter().find(|e| !e.is_timed_out() && e.pk == pk)
    }

    /** Try to add announce entry to onion announce list.

    Firstly we remove all timed out entries. Then if:
    - announce list already contains entry with such `PublicKey` then update
      entry and return it
    - announce list with new entry does not exceed `ONION_ANNOUNCE_MAX_ENTRIES`
      length add entry to the list and return it
    - the farthest entry from DHT `PublicKey` is farther than new entry then
      replace it with new entry

    Also we keep onion announce list sorted by distance to DHT `PublicKey` so
    we can easily find the farthest entry.

    */
    fn add_to_entries(&mut self, entry: OnionAnnounceEntry) -> Option<&OnionAnnounceEntry> {
        let dht_pk = &self.dht_pk;
        self.entries.retain(|e| !e.is_timed_out());
        //TODO: replace with `self.entries.iter_mut().find(|e| e.pk == entry.pk` when NLL get stabilized
        if let Some(i) = self.entries.iter().position(|e| e.pk == entry.pk) {
            // node with such pk already announced - just update the entry
            self.entries[i].clone_from(&entry);
            self.entries.get(i)
        } else if self.entries.len() < ONION_ANNOUNCE_MAX_ENTRIES {
            // adding new entry does not exceed the limit - just add it
            let pk = entry.pk;
            self.entries.push(entry);
            self.entries.sort_by(|e1, e2| dht_pk.distance(&e1.pk, &e2.pk));
            self.entries.iter().find(|e| e.pk == pk)
        } else if dht_pk.distance(&entry.pk, &self.entries.last().unwrap().pk) == Ordering::Less {
            // the farthest entry is farther than new entry - replace it
            // unwrap can not fail due to previous branch
            self.entries.last_mut().unwrap().clone_from(&entry);
            self.entries.sort_by(|e1, e2| dht_pk.distance(&e1.pk, &e2.pk));
            self.entries.iter().find(|e| e.pk == entry.pk)
        } else {
            None
        }
    }

    /** Handle `AnnounceRequest` packet and return `AnnounceResponse`.

    If `AnnounceRequest` packet contains valid onion ping id it's considered as
    announce request. Otherwise it's considered as search request. In case of
    announce request we try to add new entry to announce list and if succeed
    return status `AnnounceStatus::Announced`. In case of search request we try
    to find entry by `search_pk` key from request and if succeed return status
    `AnnounceStatus::Found`. If announce or search failed we return status
    `AnnounceStatus::Failed`.

    If request is a search request and we found requested node then
    `ping_id_or_pk` field in response packet will contain `PublicKey` that
    should be used to send data packets to requested node. Otherwise it will
    contain valid onion ping id that should be used to send announce requests
    to this node.

    Also response packet will contain up to 4 closest to `search_pk` nodes from
    kbucket. They are used to search closest to long term `PublicKey` nodes to
    announce.

    */
    pub fn handle_announce_request(&mut self, request: AnnounceRequest, dht_sk: &SecretKey, kbucket: &Kbucket, addr: SocketAddr) -> Result<AnnounceResponse, Error> {
        let shared_secret = precompute(&request.inner.pk, dht_sk);
        let payload = request.inner.get_payload(&shared_secret)?;

        let time = SystemTime::now();
        let ping_id_1 = self.ping_id(
            time,
            request.inner.pk,
            addr.ip(),
            addr.port()
        );
        let ping_id_2 = self.ping_id(
            time + Duration::from_secs(PING_ID_TIMEOUT),
            request.inner.pk,
            addr.ip(),
            addr.port()
        );

        let entry_opt = if payload.ping_id == ping_id_1 || payload.ping_id == ping_id_2 {
            let entry = OnionAnnounceEntry::new(request.inner.pk, addr.ip(), addr.port(), request.onion_return, payload.data_pk);
            self.add_to_entries(entry)
        } else {
            self.find_in_entries(payload.search_pk)
        };

        let (announce_status, ping_id_or_pk) = if let Some(entry) = entry_opt {
            if entry.pk == request.inner.pk {
                if entry.data_pk != payload.data_pk {
                    // failed to find ourselves with same long term pk but different data pk
                    // weird case, should we remove it?
                    (AnnounceStatus::Failed, ping_id_2)
                } else {
                    // successfully announced ourselves
                    (AnnounceStatus::Announced, ping_id_2)
                } 
            } else {
                // requested node is found by its long term pk
                (AnnounceStatus::Found, pk_as_digest(entry.data_pk))
            }
        } else {
            // requested node not found or failed to announce
            (AnnounceStatus::Failed, ping_id_2)
        };

        let response_payload = AnnounceResponsePayload {
            announce_status,
            ping_id_or_pk,
            nodes: kbucket.get_closest(&payload.search_pk)
        };
        let response = AnnounceResponse::new(&shared_secret, payload.sendback_data, response_payload);

        Ok(response)
    }
}
