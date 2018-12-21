/*!
Statistics of incoming/outgoing packets
This is used by both Udp codec and Tcp codec.
*/

use std::sync::Arc;
#[cfg(target_pointer_width = "64")]
use std::sync::atomic::*;
#[cfg(not(target_pointer_width = "64"))]
use std::sync::Mutex;

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

#[cfg(target_pointer_width = "64")]
#[derive(Default)]
/// Struct for counting packets on x64 CPU.
pub struct Counters {
    /// Incoming packets count for Udp/Tcp
    incoming: AtomicUsize,
    /// Outgoing packets count for Udp/Tcp
    outgoing: AtomicUsize,
}

#[cfg(not(target_pointer_width = "64"))]
#[derive(Default)]
/// Struct for counting packets on non-x64 CPU.
pub struct Counters {
    /// Incoming packets count for Udp/Tcp
    incoming: Mutex<u64>,
    /// Outgoing packets count for Udp/Tcp
    outgoing: Mutex<u64>,
}

impl Counters {
    /// Add 1 to incoming counter
    #[cfg(target_pointer_width = "64")]
    pub fn increase_incoming(&self) {
        self.incoming.fetch_add(1, Ordering::Relaxed);
    }

    /// Add 1 to incoming counter
    #[cfg(not(target_pointer_width = "64"))]
    pub fn increase_incoming(&self) {
        *self.incoming.lock().expect("Can't lock mutex") += 1;
    }

    /// Add 1 to outgoing counter
    #[cfg(target_pointer_width = "64")]
    pub fn increase_outgoing(&self) {
        self.outgoing.fetch_add(1, Ordering::Relaxed);
    }

    /// Add 1 to outgoing counter
    #[cfg(not(target_pointer_width = "64"))]
    pub fn increase_outgoing(&self) {
        *self.outgoing.lock().expect("Can't lock mutex") += 1;
    }

    /// Get incoming counter
    #[cfg(target_pointer_width = "64")]
    pub fn incoming(&self) -> u64 {
        self.incoming.load(Ordering::Relaxed) as u64
    }

    /// Get incoming counter
    #[cfg(not(target_pointer_width = "64"))]
    pub fn incoming(&self) -> u64 {
        *self.incoming.lock().expect("Can't lock mutex")
    }

    /// Get outgoing counter
    #[cfg(target_pointer_width = "64")]
    pub fn outgoing(&self) -> u64 {
        self.outgoing.load(Ordering::Relaxed) as u64
    }

    /// Get outgoing counter
    #[cfg(not(target_pointer_width = "64"))]
    pub fn outgoing(&self) -> u64 {
        *self.outgoing.lock().expect("Can't lock mutex")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clonable() {
        let stats = Stats::new();
        let _stats_c = stats.clone();
    }

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
