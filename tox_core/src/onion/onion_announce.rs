/*! The implementation of onion announce
*/

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime};
use sha2::{Digest, Sha256};
use sha2::digest::typenum::Unsigned;
use sha2::digest::OutputSizeUser;
use rand::{CryptoRng, Rng};
use thiserror::Error;

use tox_binary_io::*;
use tox_crypto::*;
use crate::time::*;
use tox_packet::onion::*;
use crate::dht::kbucket::Distance;

/// Number of secret random bytes to make onion ping id unique for each node.
pub const SECRET_BYTES_SIZE: usize = 32;

/// Maximum number of entries in onion announce list. When number of entries
/// exceeds this value farthest nodes are dropped using DHT distance function.
pub const ONION_ANNOUNCE_MAX_ENTRIES: usize = 160;

/// Interval of time when onion ping id is valid after it was generated.
/// To be precise ping id will be valid for from `PING_ID_TIMEOUT` to
/// 2 * `PING_ID_TIMEOUT`.
pub const PING_ID_TIMEOUT: Duration = Duration::from_secs(300);

/// Diration of time for which announce entry can be stored in onion announce list
/// without re-announcing.
pub const ONION_ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(300);

/// Create onion ping id filled with zeros.
pub const INITIAL_PING_ID: PingId = [0; <Sha256 as OutputSizeUser>::OutputSize::USIZE];

/// Error that can happen when handling data request.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum HandleDataRequestError {
    /// No announced node with public key.
    #[error("No announced node with public key")]
    NoAnnouncedNode {
        pk: PublicKey,
    }
}

/** Entry that corresponds to announced onion node.

When node successfully announce itself this entry is added to announced nodes
list. It's considered expired after `ONION_ANNOUNCE_TIMEOUT`.

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
    pub time: Instant
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
            time: clock_now()
        }
    }

    /** Check if this entry is timed out.

    Entry considered timed out after `ONION_ANNOUNCE_TIMEOUT` since it
    was created.

    */
    pub fn is_timed_out(&self) -> bool {
        clock_elapsed(self.time) >= ONION_ANNOUNCE_TIMEOUT
    }
}

/// Size of serialized `OnionPingData` struct.
const ONION_PING_DATA_SIZE: usize =
    SECRET_BYTES_SIZE +
    /* time */ 8 +
    crypto_box::KEY_SIZE +
    /* ip_type */ 1 +
    /* ip_addr */ 16 +  // for IPv6
    /* port */ 2;

/** Data on the basis of which onion ping id is calculated.

Format of this struct is not specified by tox protocol and can be different in
different implementations. That's possible because this struct is used for onion
ping id generation and only node that generated it can verify it.

Serialized form:

Length   | Content
-------- | ------
`32`     | Secret bytes of onion node
`8`      | Unix time in seconds divided by number of seconds in PING_ID_TIMEOUT
`32`     | `PublicKey` of sender
`1`      | IP type of sender
`16`     | `IpAddr` of sender
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
            gen_be_u64!(unix_time(self.time) / PING_ID_TIMEOUT.as_secs()) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_be_u8!(self.ip_addr.is_ipv4() as u8) >>
            gen_call!(|buf, ip_addr| IpAddr::to_bytes(ip_addr, buf), &self.ip_addr) >>
            gen_be_u16!(self.port)
        )
    }
}

impl OnionPingData {
    /** Calculate onion ping id using sha256 hash of stored data.

    Time is divided by number of seconds in `PING_ID_TIMEOUT`
    so this hash remains unchanged for `PING_ID_TIMEOUT`.

    */
    pub fn ping_id(&self) -> PingId {
        let mut buf = [0; ONION_PING_DATA_SIZE];
        // can not fail since buf has enough length
        self.to_bytes((&mut buf, 0)).unwrap();
        Sha256::digest(&buf).into()
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
    pub fn new<R: Rng + CryptoRng>(rng: &mut R, dht_pk: PublicKey) -> OnionAnnounce {
        OnionAnnounce {
            secret_bytes: rng.gen(),
            entries: Vec::with_capacity(ONION_ANNOUNCE_MAX_ENTRIES),
            dht_pk
        }
    }

    /** Calculate onion ping id using sha256 hash of arguments together with
    secret bytes stored in this struct.

    Time is divided by number of seconds in `PING_ID_TIMEOUT`
    so this hash remains unchanged for `PING_ID_TIMEOUT`.

    */
    fn ping_id(&self, time: SystemTime, pk: PublicKey, ip_addr: IpAddr, port: u16) -> PingId {
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
        match self.entries.binary_search_by(|e| self.dht_pk.distance(&e.pk, &pk)) {
            //TODO: use Option::filter when it's stabilized
            Ok(idx) => if self.entries[idx].is_timed_out() { None } else { self.entries.get(idx) },
            Err(_) => None
        }
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
        //TODO: remove timed out entries by timer?
        self.entries.retain(|e| !e.is_timed_out());
        match self.entries.binary_search_by(|e| self.dht_pk.distance(&e.pk, &entry.pk)) {
            Ok(idx) => {
                // node with such pk already announced - just update the entry
                self.entries[idx].clone_from(&entry);
                self.entries.get(idx)
            },
            Err(idx) => {
                if self.entries.len() < ONION_ANNOUNCE_MAX_ENTRIES {
                    // adding new entry does not exceed the limit - just add it
                    self.entries.insert(idx, entry);
                    self.entries.get(idx)
                } else if idx < ONION_ANNOUNCE_MAX_ENTRIES {
                    // the farthest entry is farther than new entry - replace it
                    self.entries.pop();
                    self.entries.insert(idx, entry);
                    self.entries.get(idx)
                } else {
                    None
                }
            }
        }
    }

    /** Handle payload `OnionAnnounceRequest` packet and return `AnnounceStatus`
    with ping id or `PublicKey`.

    If `OnionAnnounceRequest` packet contains valid onion ping id it's
    considered as announce request. Otherwise it's considered as search request.
    In case of announce request we try to add new entry to announce list and if
    succeed return status `AnnounceStatus::Announced`. In case of search request
    we try to find entry by `search_pk` key from request and if succeed return
    status `AnnounceStatus::Found`. If announce or search failed we return
    status `AnnounceStatus::Failed`.

    If request is a search request and we found requested node then the result
    will contain `PublicKey` that should be used to send data packets to
    requested node. Otherwise it will contain valid onion ping id that should be
    used to send announce requests to this node.

    */
    pub fn handle_onion_announce_request(
        &mut self,
        payload: &OnionAnnounceRequestPayload,
        request_pk: PublicKey,
        onion_return: OnionReturn,
        addr: SocketAddr
    ) -> (AnnounceStatus, [u8; 32]) {
        let time = SystemTime::now();
        let ping_id_1 = self.ping_id(
            time,
            request_pk.clone(),
            addr.ip(),
            addr.port()
        );
        let ping_id_2 = self.ping_id(
            time + PING_ID_TIMEOUT,
            request_pk.clone(),
            addr.ip(),
            addr.port()
        );

        let entry_opt = if payload.ping_id == ping_id_1 || payload.ping_id == ping_id_2 {
            let entry = OnionAnnounceEntry::new(request_pk.clone(), addr.ip(), addr.port(), onion_return, payload.data_pk.clone());
            self.add_to_entries(entry)
        } else {
            self.find_in_entries(payload.search_pk.clone())
        };

        if let Some(entry) = entry_opt {
            if entry.pk == request_pk {
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
                (AnnounceStatus::Found, *entry.data_pk.as_bytes())
            }
        } else {
            // requested node not found or failed to announce
            (AnnounceStatus::Failed, ping_id_2)
        }
    }

    /** Handle data request and build `OnionResponse3` packet that should be
    sent to determined address.

    When onion node handles `OnionDataRequest` it checks if onion entry list
    contains destination node and when entry exists sends `OnionDataResponse`
    to this node through its onion path.

    */
    pub fn handle_data_request(&self, request: OnionDataRequest) -> Result<(OnionResponse3, SocketAddr), HandleDataRequestError> {
        if let Some(entry) = self.find_in_entries(request.inner.destination_pk.clone()) {
            let response_payload = OnionDataResponse {
                nonce: request.inner.nonce,
                temporary_pk: request.inner.temporary_pk,
                payload: request.inner.payload
            };
            let response = OnionResponse3 {
                onion_return: entry.onion_return.clone(),
                payload: InnerOnionResponse::OnionDataResponse(response_payload)
            };
            let saddr = SocketAddr::new(entry.ip_addr, entry.port);
            Ok((response, saddr))
        } else {
            Err(HandleDataRequestError::NoAnnouncedNode {
                pk: request.inner.destination_pk,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use crypto_box::{SalsaBox, aead::{AeadCore, generic_array::typenum::marker_traits::Unsigned}};

    use super::*;

    const ONION_RETURN_3_PAYLOAD_SIZE: usize = ONION_RETURN_3_SIZE - xsalsa20poly1305::NONCE_SIZE;

    #[test]
    fn announce_entry_valid() {
        let entry = OnionAnnounceEntry::new(
            PublicKey::from([1; 32]),
            "1.2.3.4".parse().unwrap(),
            12345,
            OnionReturn {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; 42]
            },
            SecretKey::generate(&mut thread_rng()).public_key()
        );
        assert!(!entry.is_timed_out());
    }

    #[tokio::test]
    async fn announce_entry_expired() {
        let entry = OnionAnnounceEntry::new(
            PublicKey::from([1; 32]),
            "1.2.3.4".parse().unwrap(),
            12345,
            OnionReturn {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; 42]
            },
            SecretKey::generate(&mut thread_rng()).public_key()
        );

        tokio::time::pause();
        tokio::time::advance(ONION_ANNOUNCE_TIMEOUT + Duration::from_secs(1)).await;

        assert!(entry.is_timed_out());
    }

    #[test]
    fn ping_id_respects_timeout_gap() {
        let mut rng = thread_rng();
        let dht_pk = SecretKey::generate(&mut rng).public_key();
        let onion_announce = OnionAnnounce::new(&mut rng, dht_pk);

        let time = SystemTime::now();
        let time_1 = time - Duration::from_secs(unix_time(time) % PING_ID_TIMEOUT.as_secs());
        let time_2 = time_1 + Duration::from_secs(PING_ID_TIMEOUT.as_secs() - 1);
        let pk = SecretKey::generate(&mut rng).public_key();
        let ip_addr = "1.2.3.4".parse().unwrap();
        let port = 12345;

        let ping_id_1 = onion_announce.ping_id(time_1, pk.clone(), ip_addr, port);
        let ping_id_2 = onion_announce.ping_id(time_2, pk, ip_addr, port);

        assert_eq!(ping_id_1, ping_id_2);
    }

    #[test]
    fn ping_id_depends_on_all_args() {
        let mut rng = thread_rng();
        let dht_pk = SecretKey::generate(&mut rng).public_key();
        let onion_announce = OnionAnnounce::new(&mut rng, dht_pk);

        let time_1 = SystemTime::now();
        let time_2 = time_1 + PING_ID_TIMEOUT;

        let pk_1 = SecretKey::generate(&mut rng).public_key();
        let pk_2 = SecretKey::generate(&mut rng).public_key();

        let ip_addr_1 = "1.2.3.4".parse().unwrap();
        let ip_addr_2 = "3.4.5.6".parse().unwrap();

        let port_1 = 12345;
        let port_2 = 54321;

        let ping_id = onion_announce.ping_id(time_1, pk_1.clone(), ip_addr_1, port_1);

        let ping_id_1 = onion_announce.ping_id(time_1, pk_1.clone(), ip_addr_1, port_1);
        let ping_id_2 = onion_announce.ping_id(time_2, pk_1.clone(), ip_addr_1, port_1);
        let ping_id_3 = onion_announce.ping_id(time_1, pk_2, ip_addr_1, port_1);
        let ping_id_4 = onion_announce.ping_id(time_1, pk_1.clone(), ip_addr_2, port_1);
        let ping_id_5 = onion_announce.ping_id(time_1, pk_1, ip_addr_1, port_2);

        assert_eq!(ping_id, ping_id_1);
        assert_ne!(ping_id, ping_id_2);
        assert_ne!(ping_id, ping_id_3);
        assert_ne!(ping_id, ping_id_4);
        assert_ne!(ping_id, ping_id_5);
    }

    fn create_random_entry(saddr: SocketAddr) -> OnionAnnounceEntry {
        let mut rng = thread_rng();
        OnionAnnounceEntry::new(
            SecretKey::generate(&mut rng).public_key(),
            saddr.ip(),
            saddr.port(),
            OnionReturn {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; 42]
            },
            SecretKey::generate(&mut rng).public_key()
        )
    }

    #[tokio::test]
    async fn expired_entry_not_in_entries() {
        let mut rng = thread_rng();
        let dht_pk = SecretKey::generate(&mut rng).public_key();
        let mut onion_announce = OnionAnnounce::new(&mut rng, dht_pk);

        let entry = create_random_entry("1.2.3.4:12345".parse().unwrap());
        let entry_pk = entry.pk.clone();
        let entry_time = entry.time;

        onion_announce.entries.push(entry);

        tokio::time::pause();

        let now = clock_now();
        let time = entry_time + ONION_ANNOUNCE_TIMEOUT + Duration::from_secs(1);
        tokio::time::advance(time - now).await;

        assert!(onion_announce.find_in_entries(entry_pk).is_none());
    }

    ////////////////////////////////////////////////////////////////////////////////////////
    // Tests for OnionAnnounce::add_to_entries
    #[test]
    fn add_to_entries_when_limit_is_not_reached() {
        let mut rng = thread_rng();
        let dht_pk = SecretKey::generate(&mut rng).public_key();
        let mut onion_announce = OnionAnnounce::new(&mut rng, dht_pk);

        let mut pks = Vec::new();

        for i in 0..ONION_ANNOUNCE_MAX_ENTRIES {
            let saddr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + i as u16);
            let entry = create_random_entry(saddr);
            pks.push(entry.pk.clone());
            assert!(onion_announce.add_to_entries(entry).is_some());
        }

        // check that announce list contains all added entries
        for pk in pks {
            assert!(onion_announce.find_in_entries(pk).is_some());
        }

        assert_eq!(onion_announce.entries.len(), ONION_ANNOUNCE_MAX_ENTRIES);
    }

    #[tokio::test]
    async fn add_to_entries_should_update_existent_entry() {
        let mut rng = thread_rng();
        let dht_pk = SecretKey::generate(&mut rng).public_key();
        let mut onion_announce = OnionAnnounce::new(&mut rng, dht_pk);

        let mut pks = Vec::new();

        for i in 0..ONION_ANNOUNCE_MAX_ENTRIES {
            let saddr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + i as u16);
            let entry = create_random_entry(saddr);
            pks.push(entry.pk.clone());
            assert!(onion_announce.add_to_entries(entry).is_some());
        }

        // choose one of entries to update
        let mut entry_to_update = onion_announce.entries[ONION_ANNOUNCE_MAX_ENTRIES / 2].clone();

        entry_to_update.time += Duration::from_secs(7);
        entry_to_update.ip_addr = "1.2.3.4".parse().unwrap();
        entry_to_update.port = 12345;

        tokio::time::pause();

        let now = clock_now();
        let time = entry_to_update.time;
        tokio::time::advance(time - now).await;

        // update entry
        assert!(onion_announce.add_to_entries(entry_to_update.clone()).is_some());

        assert_eq!(onion_announce.find_in_entries(entry_to_update.pk.clone()), Some(&entry_to_update));

        // check that announce list contains all added entries
        for pk in pks {
            assert!(onion_announce.find_in_entries(pk).is_some());
        }

        assert_eq!(onion_announce.entries.len(), ONION_ANNOUNCE_MAX_ENTRIES);
    }

    #[tokio::test]
    async fn add_to_entries_should_replace_timed_out_entries() {
        let mut rng = thread_rng();
        let dht_pk = SecretKey::generate(&mut rng).public_key();
        let mut onion_announce = OnionAnnounce::new(&mut rng, dht_pk);

        let mut pks = Vec::new();

        tokio::time::pause();
        let now = clock_now();

        // time when all entries except one will be creat
        tokio::time::advance(ONION_ANNOUNCE_TIMEOUT).await;

        for i in 0..ONION_ANNOUNCE_MAX_ENTRIES {
            let saddr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + i as u16);
            let entry = create_random_entry(saddr);
            pks.push(entry.pk.clone());
            assert!(onion_announce.add_to_entries(entry).is_some());
        }

        // make one of entries timed out
        let timed_out_pk = onion_announce.entries[ONION_ANNOUNCE_MAX_ENTRIES / 2].pk.clone();
        onion_announce.entries[ONION_ANNOUNCE_MAX_ENTRIES / 2].time = now;

        // time when one entry will be timed out
        tokio::time::advance(Duration::from_secs(1)).await;

        let entry = create_random_entry("1.2.3.5:12345".parse().unwrap());
        let entry_pk = entry.pk.clone();
        assert!(onion_announce.add_to_entries(entry).is_some());

        // check that announce list contains new entry
        assert!(onion_announce.find_in_entries(entry_pk).is_some());

        // check that announce list contains all old entries except timed out
        for pk in pks.into_iter().filter(|pk| pk != &timed_out_pk) {
            assert!(onion_announce.find_in_entries(pk).is_some());
        }

        assert_eq!(onion_announce.entries.len(), ONION_ANNOUNCE_MAX_ENTRIES);
    }

    #[test]
    fn add_to_entries_should_replace_the_farthest_entry() {
        let dht_pk = PublicKey::from([0; 32]);
        let mut onion_announce = OnionAnnounce::new(&mut thread_rng(), dht_pk);

        // add one entry with farthest pk
        let mut entry = create_random_entry("1.2.3.4:12345".parse().unwrap());
        entry.pk = PublicKey::from([255; 32]);
        assert!(onion_announce.add_to_entries(entry).is_some());

        let mut pks = Vec::new();

        for i in 0..ONION_ANNOUNCE_MAX_ENTRIES - 1 {
            let saddr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12346 + i as u16);
            let entry = create_random_entry(saddr);
            pks.push(entry.pk.clone());
            assert!(onion_announce.add_to_entries(entry).is_some());
        }

        // add new entry that should replace the farthest one
        let entry = create_random_entry("1.2.3.5:12345".parse().unwrap());
        let entry_pk = entry.pk.clone();
        assert!(onion_announce.add_to_entries(entry).is_some());

        // check that announce list contains new entry
        assert!(onion_announce.find_in_entries(entry_pk).is_some());

        // check that announce list contains all old entries except farthest
        for pk in pks {
            assert!(onion_announce.find_in_entries(pk).is_some());
        }

        assert_eq!(onion_announce.entries.len(), ONION_ANNOUNCE_MAX_ENTRIES);
    }

    #[test]
    fn add_to_entries_should_should_not_add_the_farthest_entry() {
        let dht_pk = PublicKey::from([0; 32]);
        let mut onion_announce = OnionAnnounce::new(&mut thread_rng(), dht_pk);

        let mut pks = Vec::new();

        for i in 0..ONION_ANNOUNCE_MAX_ENTRIES {
            let saddr = SocketAddr::new("1.2.3.4".parse().unwrap(), 12345 + i as u16);
            let entry = create_random_entry(saddr);
            pks.push(entry.pk.clone());
            assert!(onion_announce.add_to_entries(entry).is_some());
        }

        // try to add new farthest entry
        let mut entry = create_random_entry("1.2.3.5:12345".parse().unwrap());
        let entry_pk = PublicKey::from([255; 32]);
        entry.pk = entry_pk.clone();
        assert!(onion_announce.add_to_entries(entry).is_none());

        // check that announce list does not contain new entry
        assert!(onion_announce.find_in_entries(entry_pk).is_none());

        // check that announce list contains all old entries
        for pk in pks {
            assert!(onion_announce.find_in_entries(pk).is_some());
        }

        assert_eq!(onion_announce.entries.len(), ONION_ANNOUNCE_MAX_ENTRIES);
    }

    ////////////////////////////////////////////////////////////////////////////////////////
    // Tests for OnionAnnounce::handle_onion_announce_request
    #[test]
    fn handle_announce_failed_to_find_node() {
        let mut rng = thread_rng();
        let dht_pk = SecretKey::generate(&mut rng).public_key();
        let search_pk = SecretKey::generate(&mut rng).public_key();
        let data_pk = SecretKey::generate(&mut rng).public_key();
        let packet_pk = SecretKey::generate(&mut rng).public_key();

        let mut onion_announce = OnionAnnounce::new(&mut rng, dht_pk);

        // insert random entry
        let entry = create_random_entry("1.2.3.4:12345".parse().unwrap());
        assert!(onion_announce.add_to_entries(entry).is_some());

        // create request packet
        let payload = OnionAnnounceRequestPayload {
            ping_id: INITIAL_PING_ID,
            search_pk,
            data_pk,
            sendback_data: 42
        };
        let onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
        };

        let addr = "127.0.0.1:12345".parse().unwrap();

        let (announce_status, _ping_id_or_pk) = onion_announce.handle_onion_announce_request(
            &payload,
            packet_pk,
            onion_return,
            addr
        );

        assert_eq!(announce_status, AnnounceStatus::Failed);
    }

    #[test]
    fn handle_announce_node_is_found() {
        let mut rng = thread_rng();
        let dht_pk = SecretKey::generate(&mut rng).public_key();
        let data_pk = SecretKey::generate(&mut rng).public_key();
        let packet_pk = SecretKey::generate(&mut rng).public_key();

        let mut onion_announce = OnionAnnounce::new(&mut rng, dht_pk);

        // insert random entry
        let entry = create_random_entry("1.2.3.4:12345".parse().unwrap());
        let search_pk = entry.pk.clone();
        let entry_data_pk = entry.data_pk.clone();
        assert!(onion_announce.add_to_entries(entry).is_some());

        // create request packet
        let payload = OnionAnnounceRequestPayload {
            ping_id: INITIAL_PING_ID,
            search_pk,
            data_pk,
            sendback_data: 42
        };
        let onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
        };

        let addr = "127.0.0.1:12345".parse().unwrap();

        let (announce_status, ping_id_or_pk) = onion_announce.handle_onion_announce_request(
            &payload,
            packet_pk,
            onion_return,
            addr
        );

        assert_eq!(announce_status, AnnounceStatus::Found);
        assert_eq!(ping_id_or_pk, *entry_data_pk.as_bytes());
    }

    #[test]
    fn handle_announce_successfully_announced() {
        let mut rng = thread_rng();
        let dht_pk = SecretKey::generate(&mut rng).public_key();
        let search_pk = SecretKey::generate(&mut rng).public_key();
        let data_pk = SecretKey::generate(&mut rng).public_key();
        let packet_pk = SecretKey::generate(&mut rng).public_key();

        let mut onion_announce = OnionAnnounce::new(&mut rng, dht_pk);

        // insert random entry
        let entry = create_random_entry("1.2.3.4:12345".parse().unwrap());
        assert!(onion_announce.add_to_entries(entry).is_some());

        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let time = SystemTime::now();
        let ping_id = onion_announce.ping_id(time, packet_pk.clone(), addr.ip(), addr.port());

        // create request packet
        let payload = OnionAnnounceRequestPayload {
            ping_id,
            search_pk,
            data_pk,
            sendback_data: 42
        };
        let onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
        };

        let (announce_status, _ping_id_or_pk) = onion_announce.handle_onion_announce_request(
            &payload,
            packet_pk.clone(),
            onion_return,
            addr
        );

        assert_eq!(announce_status, AnnounceStatus::Announced);
        assert!(onion_announce.find_in_entries(packet_pk).is_some());
    }

    #[test]
    fn handle_announce_failed_to_find_ourselves_with_different_data_pk() { // weird case, should we remove it?
        let mut rng = thread_rng();
        let dht_pk = SecretKey::generate(&mut rng).public_key();
        let data_pk = SecretKey::generate(&mut rng).public_key();
        let packet_pk = SecretKey::generate(&mut rng).public_key();

        let mut onion_announce = OnionAnnounce::new(&mut rng, dht_pk);

        // insert ourselves
        let mut entry = create_random_entry("1.2.3.4:12345".parse().unwrap());
        entry.pk = packet_pk.clone();
        assert!(onion_announce.add_to_entries(entry).is_some());

        // create request packet
        let sendback_data = 42;
        let payload = OnionAnnounceRequestPayload {
            ping_id: INITIAL_PING_ID,
            search_pk: packet_pk.clone(),
            data_pk,
            sendback_data
        };
        let onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
        };

        let addr = "127.0.0.1:12345".parse().unwrap();

        let (announce_status, _ping_id_or_pk) = onion_announce.handle_onion_announce_request(
            &payload,
            packet_pk,
            onion_return,
            addr
        );

        assert_eq!(announce_status, AnnounceStatus::Failed);
    }

    ////////////////////////////////////////////////////////////////////////////////////////
    // Tests for OnionAnnounce::handle_onion_announce_request
    #[test]
    fn handle_data_request() {
        let mut rng = thread_rng();
        let dht_pk = SecretKey::generate(&mut rng).public_key();

        let mut onion_announce = OnionAnnounce::new(&mut rng, dht_pk);

        // insert random entry
        let entry = create_random_entry("1.2.3.4:12345".parse().unwrap());
        let entry_pk = entry.pk.clone();
        let entry_addr = entry.ip_addr;
        let entry_port = entry.port;
        let entry_onion_return = entry.onion_return.clone();
        assert!(onion_announce.add_to_entries(entry).is_some());

        let nonce = [42; <SalsaBox as AeadCore>::NonceSize::USIZE];
        let temporary_pk = SecretKey::generate(&mut rng).public_key();
        let payload = vec![42; 123];
        let onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
        };
        let inner = InnerOnionDataRequest {
            destination_pk: entry_pk,
            nonce,
            temporary_pk: temporary_pk.clone(),
            payload: payload.clone()
        };
        let request = OnionDataRequest {
            inner,
            onion_return
        };

        let (response, saddr) = onion_announce.handle_data_request(request).unwrap();

        assert_eq!(saddr.ip(), entry_addr);
        assert_eq!(saddr.port(), entry_port);
        assert_eq!(response.onion_return, entry_onion_return);
        assert_eq!(response.payload, InnerOnionResponse::OnionDataResponse(OnionDataResponse {
            nonce,
            temporary_pk,
            payload
        }));
    }

    #[test]
    fn handle_data_request_unknown_destination() {
        let mut rng = thread_rng();
        let dht_pk = SecretKey::generate(&mut rng).public_key();

        let onion_announce = OnionAnnounce::new(&mut rng, dht_pk);

        let onion_return = OnionReturn {
            nonce: [42; xsalsa20poly1305::NONCE_SIZE],
            payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
        };
        let inner = InnerOnionDataRequest {
            destination_pk: SecretKey::generate(&mut rng).public_key(),
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            temporary_pk: SecretKey::generate(&mut rng).public_key(),
            payload: vec![42; 123]
        };
        let request = OnionDataRequest {
            inner,
            onion_return
        };

        assert!(onion_announce.handle_data_request(request).is_err());
    }
}
