use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::toxcore::crypto_core::*;
use crate::toxcore::time::*;

#[derive(Clone, Debug)]
pub struct RequestQueue<T> {
    ping_map: HashMap<u64, (Instant, T)>,
    timeout: Duration,
}

impl<T> RequestQueue<T> { // TODO: unify with DHT?
    pub fn new(timeout: Duration) -> Self {
        RequestQueue {
            ping_map: HashMap::new(),
            timeout,
        }
    }

    fn generate_ping_id(&self) -> u64 {
        loop {
            let ping_id = random_u64();
            if ping_id != 0 && !self.ping_map.contains_key(&ping_id) {
                return ping_id;
            }
        }
    }

    pub fn new_ping_id(&mut self, data: T) -> u64 {
        let ping_id = self.generate_ping_id();
        self.ping_map.insert(ping_id, (clock_now(), data));
        ping_id
    }

    pub fn check_ping_id(&mut self, ping_id: u64) -> Option<T> {
        if ping_id == 0 {
            return None
        }

        self.ping_map
            .remove(&ping_id)
            .filter(|&(time, _)| clock_elapsed(time) <= self.timeout)
            .map(|(_, data)| data)
    }

    pub fn clear_timed_out(&mut self) {
        let timeout = self.timeout;
        self.ping_map.retain(|&_, &mut (time, _)|
            clock_elapsed(time) <= timeout
        );
    }
}
