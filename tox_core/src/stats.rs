/*!
Statistics of incoming/outgoing packets
This is used by both Udp codec and Tcp codec.
*/

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Struct for various counters
#[derive(Clone, Default)]
pub struct Stats {
    /// incoming/outgoing counters
    pub counters: Arc<Counters>
}

impl Stats {
    /// New Stats object
    pub fn new() -> Self {
        Default::default()
    }
}

#[derive(Default)]
/// A struct for counting incoming and outgoing packets.
pub struct Counters {
    /// Incoming packets count for Udp/Tcp
    incoming: AtomicU64,
    /// Outgoing packets count for Udp/Tcp
    outgoing: AtomicU64,
}

impl Counters {
    /// Add 1 to incoming counter
    pub fn increase_incoming(&self) {
        self.incoming.fetch_add(1, Ordering::Relaxed);
    }

    /// Add 1 to outgoing counter
    pub fn increase_outgoing(&self) {
        self.outgoing.fetch_add(1, Ordering::Relaxed);
    }

    /// Get incoming counter
    pub fn incoming(&self) -> u64 {
        self.incoming.load(Ordering::Relaxed)
    }

    /// Get outgoing counter
    pub fn outgoing(&self) -> u64 {
        self.outgoing.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incoming() {
        let stats = Stats::new();
        assert_eq!(0, stats.counters.incoming());
        stats.counters.increase_incoming();
        assert_eq!(1, stats.counters.incoming());
    }

    #[test]
    fn outgoing() {
        let stats = Stats::new();
        assert_eq!(0, stats.counters.outgoing());
        stats.counters.increase_outgoing();
        stats.counters.increase_outgoing();
        assert_eq!(2, stats.counters.outgoing());
    }
}
