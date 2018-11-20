/*! Common utility functions
*/

use toxcore::crypto_core::*;

/// Generate non-zero ping_id
pub fn gen_ping_id() -> u64 {
    let mut ping_id = 0;
    while ping_id == 0 {
        ping_id = random_u64();
    }
    ping_id
}

/// Statistics of incoming/outgoing packets
/// This is used by both Udp codec and Tcp codec.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Stats {
    /// Incoming packets count for Udp/Tcp
    pub incoming: u64,
    /// Outgoing packets count for Udp/Tcp
    pub outgoing: u64,
}

impl Stats {
    /// New Stats object
    pub fn new() -> Self {
        Default::default()
    }
}
