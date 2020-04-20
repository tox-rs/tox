//! Managing requests IDs and timeouts.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::time::{Duration, Instant};

use crate::utils::gen_ping_id;
use crate::time::*;

/// Struct that stores and manages requests IDs and timeouts. Every request ID
/// stores generic companion data.
#[derive(Clone, Debug)]
pub struct RequestQueue<T> {
    /// Map that stores requests IDs with time when they were generated and some
    /// generic request data.
    ping_map: HashMap<u64, (Instant, T)>,
    /// Timeout when requests IDs are considered invalid.
    timeout: Duration,
}

impl<T> RequestQueue<T> {
    /// Create new `RequestQueue`.
    pub fn new(timeout: Duration) -> Self {
        RequestQueue {
            ping_map: HashMap::new(),
            timeout,
        }
    }

    /// Generate unique non zero request ID.
    fn generate_ping_id(&self) -> u64 {
        loop {
            let ping_id = gen_ping_id();
            if !self.ping_map.contains_key(&ping_id) {
                return ping_id;
            }
        }
    }

    /// Generate and store unique non zero request ID. Later this request ID can
    /// be verified with `check_ping_id` function.
    pub fn new_ping_id(&mut self, data: T) -> u64 {
        let ping_id = self.generate_ping_id();
        self.ping_map.insert(ping_id, (clock_now(), data));
        ping_id
    }

    /// Check whether request ID is correct and not timed out. When data
    /// satisfies passed condition this function removes received request ID and
    /// returns stored data. So a request ID can be verified only once.
    pub fn check_ping_id<F: FnOnce(&T) -> bool>(&mut self, ping_id: u64, cond: F) -> Option<T> {
        if ping_id == 0 {
            return None;
        }

        if let Entry::Occupied(entry) = self.ping_map.entry(ping_id) {
            let (time, data) = entry.get();
            if clock_elapsed(*time) <= self.timeout && cond(data) {
                let (_ping_id, (_time, data)) = entry.remove_entry();
                Some(data)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Remove timed out request IDs.
    pub fn clear_timed_out(&mut self) {
        let timeout = self.timeout;
        self.ping_map.retain(|&_, &mut (time, _)|
            clock_elapsed(time) <= timeout
        );
    }

    /// Get not timed out requests stored in this `RequestQueue`.
    pub fn get_values(&self) -> impl Iterator<Item = (Instant, &T)> {
        self.ping_map
            .values()
            .filter(move |(time, _)| clock_elapsed(*time) <= self.timeout)
            .map(|(time, data)| (*time, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tox_crypto::*;

    #[test]
    fn insert_new_ping_id() {
        crypto_init().unwrap();

        let mut queue = RequestQueue::new(Duration::from_secs(42));

        let ping_id = queue.new_ping_id(7);

        assert_eq!(queue.ping_map[&ping_id].1, 7);
    }

    #[test]
    fn check_ping_id() {
        crypto_init().unwrap();

        let mut queue = RequestQueue::new(Duration::from_secs(42));

        let ping_id = queue.new_ping_id(7);
        assert_eq!(queue.check_ping_id(ping_id, |&data| data == 6), None);
        assert_eq!(queue.check_ping_id(ping_id, |&data| data == 7), Some(7));
        assert_eq!(queue.check_ping_id(ping_id, |&data| data == 7), None);
    }

    #[test]
    fn check_ping_id_zero() {
        let mut queue = RequestQueue::<()>::new(Duration::from_secs(42));

        assert_eq!(queue.check_ping_id(0, |_| true), None);
    }

    #[test]
    fn check_ping_id_nonexistent() {
        crypto_init().unwrap();

        let mut queue = RequestQueue::new(Duration::from_secs(42));

        let ping_id = queue.new_ping_id(());
        assert_eq!(queue.check_ping_id(ping_id.overflowing_add(1).0, |_| true), None);
        assert_eq!(queue.check_ping_id(ping_id.overflowing_sub(1).0, |_| true), None);
    }

    #[tokio::test]
    async fn check_ping_id_timed_out() {
        crypto_init().unwrap();

        let mut queue = RequestQueue::new(Duration::from_secs(42));
        let ping_id = queue.new_ping_id(());

        tokio::time::pause();

        let now = clock_now();
        let time = queue.ping_map[&ping_id].0 + Duration::from_secs(43);
        tokio::time::advance(time - now).await;

        assert_eq!(queue.check_ping_id(ping_id, |_| true), None);
    }

    #[tokio::test]
    async fn clear_timed_out() {
        crypto_init().unwrap();

        let mut queue = RequestQueue::new(Duration::from_secs(42));
        let ping_id_1 = queue.new_ping_id(());

        tokio::time::pause();

        let now = clock_now();
        let time = queue.ping_map[&ping_id_1].0;

        tokio::time::advance((time + Duration::from_secs(21)) - now).await;
        let ping_id_2 = queue.new_ping_id(());

        tokio::time::advance(Duration::from_secs(43 - 21)).await;
        queue.clear_timed_out();

        // ping_id_1 is timed out while ping_id_2 is not
        assert!(!queue.ping_map.contains_key(&ping_id_1));
        assert!(queue.ping_map.contains_key(&ping_id_2));
    }

    #[test]
    fn get_values() {
        crypto_init().unwrap();

        let mut queue = RequestQueue::new(Duration::from_secs(42));

        let _ping_id_1 = queue.new_ping_id(1);
        let _ping_id_2 = queue.new_ping_id(2);
        let _ping_id_3 = queue.new_ping_id(3);

        let values = queue.get_values().map(|(_, &data)| data).collect::<Vec<_>>();

        assert!(values.contains(&1));
        assert!(values.contains(&2));
        assert!(values.contains(&3));
        assert!(!values.contains(&4));
    }
}
