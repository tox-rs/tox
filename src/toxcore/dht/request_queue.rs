//! Managing requests IDs and timeouts.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::toxcore::crypto_core::*;
use crate::toxcore::time::*;

/** Struct that stores and manages requests IDs and timeouts.

Request ID is tied to `PublicKey` of node to which a request is supposed to be
made.
*/
#[derive(Clone, Debug)]
pub struct RequestQueue {
    /// Map that stores requests IDs with time when they were generated.
    ping_map: HashMap<(PublicKey, u64), Instant>,
    /// Timeout when requests IDs are considered invalid.
    timeout: Duration,
}

impl RequestQueue {
    /// Create new `RequestQueue`.
    pub fn new(timeout: Duration) -> RequestQueue {
        RequestQueue {
            ping_map: HashMap::new(),
            timeout,
        }
    }

    /// Generate unique non zero request ID.
    fn generate_ping_id(&self, pk: PublicKey) -> u64 {
        loop {
            let ping_id = random_u64();
            if ping_id != 0 && !self.ping_map.contains_key(&(pk, ping_id)) {
                return ping_id;
            }
        }
    }

    /// Generate and store unique non zero request ID. Later this request ID can
    /// be verified with `check_ping_id` function.
    pub fn new_ping_id(&mut self, pk: PublicKey) -> u64 {
        let ping_id = self.generate_ping_id(pk);
        self.ping_map.insert((pk, ping_id), clock_now());
        ping_id
    }

    /// Check whether request ID is correct and not timed out. This function
    /// removes received request ID so that it can be verified only once.
    pub fn check_ping_id(&mut self, pk: PublicKey, ping_id: u64) -> bool {
        if ping_id == 0 {
            return false
        }

        match self.ping_map.remove(&(pk, ping_id)) {
            Some(time) if clock_elapsed(time) <= self.timeout => true,
            _ => false,
        }
    }

    /// Remove timed out request IDs.
    pub fn clear_timed_out(&mut self) {
        let timeout = self.timeout;
        self.ping_map.retain(|&_, &mut time|
            clock_elapsed(time) <= timeout
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio_executor;
    use tokio_timer::clock::*;

    use crate::toxcore::time::ConstNow;

    #[test]
    fn clone() {
        let queue = RequestQueue::new(Duration::from_secs(42));
        let _ = queue.clone();
    }

    #[test]
    fn insert_new_ping_id() {
        crypto_init().unwrap();
        let mut queue = RequestQueue::new(Duration::from_secs(42));
        let (pk, _sk) = gen_keypair();

        let ping_id = queue.new_ping_id(pk);

        assert!(queue.ping_map.contains_key(&(pk, ping_id)));
    }

    #[test]
    fn check_ping_id() {
        crypto_init().unwrap();
        let mut queue = RequestQueue::new(Duration::from_secs(42));
        let (pk, _sk) = gen_keypair();

        let ping_id = queue.new_ping_id(pk);
        assert!(queue.check_ping_id(pk, ping_id));
        assert!(!queue.check_ping_id(pk, ping_id));
    }

    #[test]
    fn check_ping_id_zero() {
        crypto_init().unwrap();
        let mut queue = RequestQueue::new(Duration::from_secs(42));
        let (pk, _sk) = gen_keypair();

        assert!(!queue.check_ping_id(pk, 0));
    }

    #[test]
    fn check_ping_id_nonexistent() {
        crypto_init().unwrap();
        let mut queue = RequestQueue::new(Duration::from_secs(42));
        let (pk, _sk) = gen_keypair();

        let ping_id = queue.new_ping_id(pk);
        assert!(!queue.check_ping_id(pk, ping_id.overflowing_add(1).0));
        assert!(!queue.check_ping_id(pk, ping_id.overflowing_sub(1).0));
    }

    #[test]
    fn check_ping_id_timed_out() {
        crypto_init().unwrap();
        let mut queue = RequestQueue::new(Duration::from_secs(42));
        let (pk, _sk) = gen_keypair();

        let ping_id = queue.new_ping_id(pk);

        let time = queue.ping_map[&(pk, ping_id)];
        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(
            time + Duration::from_secs(43)
        ));

        with_default(&clock, &mut enter, |_| {
            assert!(!queue.check_ping_id(pk, ping_id));
        });
    }

    #[test]
    fn clear_timed_out_pings() {
        crypto_init().unwrap();
        let mut queue = RequestQueue::new(Duration::from_secs(42));
        let (pk, _sk) = gen_keypair();

        let ping_id_1 = queue.new_ping_id(pk);

        let time = queue.ping_map[&(pk, ping_id_1)];
        let mut enter = tokio_executor::enter().unwrap();
        let clock_1 = Clock::new_with_now(ConstNow(
            time + Duration::from_secs(21)
        ));
        let clock_2 = Clock::new_with_now(ConstNow(
            time + Duration::from_secs(43)
        ));

        let ping_id_2 = with_default(&clock_1, &mut enter, |_| {
            queue.new_ping_id(pk)
        });

        with_default(&clock_2, &mut enter, |_| {
            queue.clear_timed_out();

            // ping_id_1 is timed out while ping_id_2 is not
            assert!(!queue.ping_map.contains_key(&(pk, ping_id_1)));
            assert!(queue.ping_map.contains_key(&(pk, ping_id_2)));
        });
    }
}
