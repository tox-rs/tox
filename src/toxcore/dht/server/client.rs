/*!
Manage ping_id.
Generate ping_id on request packet, check ping_id on response packet.
*/

use std::collections::HashMap;
use std::time::{Duration, Instant};

use toxcore::crypto_core::*;
use toxcore::time::*;

/// Ping timeout in seconds
pub const PING_TIMEOUT: u64 = 5;

/// peer info.
#[derive(Clone, Debug)]
pub struct PingData {
    /// hash of ping_ids to check PingResponse is correct
    ping_hash: HashMap<u64, Instant>,
    /// last received ping/nodes-response time
    pub last_resp_time: Instant,
    /// last sent ping-req time
    pub last_ping_req_time: Option<Instant>,
}

impl PingData {
    /// create PingData object
    pub fn new() -> PingData {
        PingData {
            ping_hash: HashMap::new(),
            last_resp_time: clock_now(),
            last_ping_req_time: None,
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
    pub fn clear_timedout_pings(&mut self) {
        self.ping_hash.retain(|&_ping_id, &mut time|
            clock_elapsed(time) <= Duration::from_secs(PING_TIMEOUT)
        );
    }

    /// Add a Ping Hash Entry and return a new ping_id.
    pub fn insert_new_ping_id(&mut self) -> u64 {
        let ping_id = self.generate_ping_id();
        self.ping_hash.insert(ping_id, clock_now());

        ping_id
    }

    /// Check if ping_id is valid and not timed out.
    pub fn check_ping_id(&mut self, ping_id: u64) -> bool {
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

        if clock_elapsed(time_ping_sent) > Duration::from_secs(PING_TIMEOUT) {
            debug!("Given ping_id is timed out");
            return false
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio_executor;
    use tokio_timer::clock::*;

    use toxcore::time::ConstNow;

    #[test]
    fn clone() {
        let ping_data = PingData::new();
        let _ = ping_data.clone();
    }

    #[test]
    fn insert_new_ping_id() {
        let mut ping_data = PingData::new();

        let ping_id = ping_data.insert_new_ping_id();

        assert!(ping_data.ping_hash.contains_key(&ping_id));
    }

    #[test]
    fn check_ping_id() {
        let mut ping_data = PingData::new();

        let ping_id = ping_data.insert_new_ping_id();
        assert!(ping_data.check_ping_id(ping_id));
        assert!(!ping_data.check_ping_id(ping_id));
    }

    #[test]
    fn check_ping_id_zero() {
        let mut ping_data = PingData::new();

        assert!(!ping_data.check_ping_id(0));
    }

    #[test]
    fn check_ping_id_nonexistent() {
        let mut ping_data = PingData::new();

        let ping_id = ping_data.insert_new_ping_id();
        assert!(!ping_data.check_ping_id(ping_id.overflowing_add(1).0));
        assert!(!ping_data.check_ping_id(ping_id.overflowing_sub(1).0));
    }

    #[test]
    fn check_ping_id_timed_out() {
        let mut ping_data = PingData::new();

        let ping_id = ping_data.insert_new_ping_id();

        let time = *ping_data.ping_hash.get(&ping_id).unwrap();
        let mut enter = tokio_executor::enter().unwrap();
        let clock = Clock::new_with_now(ConstNow(
            time + Duration::from_secs(PING_TIMEOUT + 1)
        ));

        with_default(&clock, &mut enter, |_| {
            assert!(!ping_data.check_ping_id(ping_id));
        });
    }

    #[test]
    fn clear_timed_out_pings() {
        let mut ping_data = PingData::new();

        let ping_id_1 = ping_data.insert_new_ping_id();

        let time = *ping_data.ping_hash.get(&ping_id_1).unwrap();
        let mut enter = tokio_executor::enter().unwrap();
        let clock_1 = Clock::new_with_now(ConstNow(
            time + Duration::from_secs(PING_TIMEOUT / 2)
        ));
        let clock_2 = Clock::new_with_now(ConstNow(
            time + Duration::from_secs(PING_TIMEOUT + 1)
        ));

        let ping_id_2 = with_default(&clock_1, &mut enter, |_| {
            ping_data.insert_new_ping_id()
        });

        with_default(&clock_2, &mut enter, |_| {
            ping_data.clear_timedout_pings();

            // ping_id_1 is timed out while ping_id_2 is not
            assert!(!ping_data.ping_hash.contains_key(&ping_id_1));
            assert!(ping_data.ping_hash.contains_key(&ping_id_2));
        });
    }
}
