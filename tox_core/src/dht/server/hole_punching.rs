/*!
Module for hole-punching.

https://zetok.github.io/tox-spec/#hole-punching
*/

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use std::collections::HashMap;

use crate::dht::dht_friend::*;
use crate::dht::server::*;
use crate::utils::*;

/// Interval of time for sending `NatPingRequest` packet and doing hole
/// punching.
pub const PUNCH_INTERVAL: Duration = Duration::from_secs(3);
/// Interval of time to reset counter of hole punching attempts.
pub const RESET_PUNCH_INTERVAL: Duration = Duration::from_secs(40);
/// Maximum number of ports to use for every round of hole punching. Note that
/// we have 2 different guessing algorithms so each one of them will use this
/// number of ports.
const MAX_PORTS_TO_PUNCH: u32 = 48;
/// After this number of hole punching attempts we will use advanced port
/// guessing algorithm besides simple algorithm.
const MAX_NORMAL_PUNCHING_TRIES: u32 = 5;

/// Struct for hole punching.
#[derive(Clone, Debug)]
pub struct HolePunching {
    /// Flag shows if the hole punching is done or not. This value is a bit
    /// tricky. Every hole punching round we set it to `true` regardless of
    /// whether it succeed or not. But when we are not directly connected to a
    /// friend we send `NatPingRequest` packet periodically and when we receive
    /// `NatPingRequest` we reset this value back to `false` which means we
    /// should run next round of hole punching.
    pub is_punching_done: bool,
    /// Number of hole punching attempts. If this value exceeds
    /// `MAX_NORMAL_PUNCHING_TRIES` we will try advanced port guessing
    /// algorithm. We reset this value every `RESET_PUNCH_INTERVAL`.
    pub num_punch_tries: u32,
    /// Time when the last `NatPingRequest` packet was received from a friend.
    pub last_recv_ping_time: Instant,
    /// Time when the last `NatPingRequest` packet was sent.
    pub last_send_ping_time: Option<Instant>,
    /// Time when the last attempt to punch holes was made. It is used to send
    /// `NatPingRequest` packet every 3 seconds.
    pub last_punching_time: Option<Instant>,
    /// Factor variable for guessing NAT port.
    pub first_punching_index: u32,
    /// Another factor variable for guessing NAT port.
    pub last_punching_index: u32,
    /// Ping id that is used to send `NatPingRequest` packets. It's refreshed
    /// every time we receive valid `NatPingResponse` packet.
    pub ping_id: u64,
}

impl Default for HolePunching {
    fn default() -> Self {
        HolePunching::new()
    }
}

impl HolePunching {
    /// Create new `HolePunching` object.
    pub fn new() -> Self {
        HolePunching {
            is_punching_done: true,
            num_punch_tries: 0,
            last_recv_ping_time: Instant::now(),
            last_send_ping_time: None,
            last_punching_time: None,
            first_punching_index: 0,
            last_punching_index: 0,
            ping_id: gen_ping_id(),
        }
    }

    /// Run next round of hole punching if necessary, i.e. if:
    /// - hole punching is not done
    /// - `PUNCH_INTERVAL` elapsed since last hole punching round
    /// - friend successfully responded to `NatPingRequest` (defined by `is_punching_done`)
    /// - friend successfully send `NatPingRequest` to us
    ///
    /// This function returns list of addresses to which we should send
    ///`PingRequest` packet.
    pub fn next_punch_addrs(&mut self, addrs: &[SocketAddr]) -> Vec<SocketAddr> {
        if !self.is_punching_done &&
            self.last_punching_time.map_or(true, |time| time.elapsed() >= PUNCH_INTERVAL) &&
            self.last_recv_ping_time.elapsed() <= PUNCH_INTERVAL * 2 {
                let ip = match HolePunching::get_common_ip(addrs, u32::from(FRIEND_CLOSE_NODES_COUNT) / 2) {
                    // A friend can have maximum 8 close node. If 4 or more close nodes returned
                    // the same friend's IP address but with different port we consider that friend
                    // is behind NAT. Otherwise we do nothing.
                    None => return Vec::new(),
                    Some(ip) => ip,
                };

                if self.last_punching_time.map_or(true, |time| time.elapsed() > RESET_PUNCH_INTERVAL) {
                    self.num_punch_tries = 0;
                    self.first_punching_index = 0;
                    self.last_punching_index = 0;
                }

                let ports_to_try = HolePunching::get_nat_ports(&addrs, ip);

                let res = self.punch_addrs(&ports_to_try, ip);

                self.last_punching_time = Some(clock_now());
                self.is_punching_done = true;

                res
        } else {
            Vec::new()
        }
    }

    /// Calculate the most common IP i.e. a overlapping IP of a friend returned
    /// by his close nodes. If number of occurrences of the most common IP
    /// exceeds `need_num` number return it. `need_num` is normally 4 which is
    /// half of maximum close nodes per friend. When half of friend's close
    /// nodes return same IP with different port we consider that friend is
    /// behind NAT.
    fn get_common_ip(addrs: &[SocketAddr], need_num: u32) -> Option<IpAddr> {
        let mut occurrences = HashMap::new();

        for addr in addrs {
            *occurrences.entry(addr.ip()).or_insert(0) += 1;
        }

        occurrences.into_iter().max_by_key(|&(_, count)| count)
            .and_then(|(common_ip, count)|
                if count > need_num {
                    Some(common_ip)
                } else {
                    None
                }
            )
    }

    /// Get ports list of given IP address.
    fn get_nat_ports(addrs: &[SocketAddr], ip: IpAddr) -> Vec<u16> {
        addrs.iter()
            .filter(|addr| addr.ip() == ip)
            .map(|addr| addr.port())
            .collect::<Vec<u16>>()
    }

    /// Simple port guessing algorithm. It uses only ports (with some
    /// neighborhood) returned by close nodes of a friend.
    fn first_hole_punching(&self, ports: &[u16], ip: IpAddr) -> Vec<SocketAddr> {
        let num_ports = ports.len();
        (0..MAX_PORTS_TO_PUNCH).map(|i| {
            // algorithm designed by irungentoo
            // https://zetok.github.io/tox-spec/#symmetric-nat
            let it = i + self.first_punching_index;
            let sign: i16 = if it % 2 == 1 { -1 } else { 1 };
            let delta = sign * (it / (2 * num_ports as u32)) as i16;
            let index = (it as usize / 2) % num_ports;
            let port = (ports[index] as i16 + delta) as u16;

            SocketAddr::new(ip, port)
        }).collect()
    }

    /// Advanced port guessing algorithm. It uses all ports sequentially
    /// starting from 1024.
    fn last_hole_punching(&self, ip: IpAddr) -> Vec<SocketAddr> {
        let port: u32 = 1024;

        (0..MAX_PORTS_TO_PUNCH).map(|i| {
            // algorithm designed by irungentoo
            // https://zetok.github.io/tox-spec/#symmetric-nat
            let it = i + self.last_punching_index;
            let port = port + it;

            SocketAddr::new(ip, port as u16)
        }).collect()
    }

    /// Get addresses for hole punching using different port guessing
    /// algorithms.
    ///
    /// This function returns list of addresses to which we should send
    ///`PingRequest` packet.
    fn punch_addrs(&mut self, ports: &[u16], ip: IpAddr) -> Vec<SocketAddr> {
        if ports.is_empty() {
            return Vec::new()
        }

        let first_port = ports[0];
        let num_ports = ports.len();
        let num_same_port = ports.iter().filter(|port| **port == first_port).count();

        let mut addrs = if num_same_port == num_ports {
            vec![SocketAddr::new(ip, first_port)]
        } else {
            let addrs = self.first_hole_punching(ports, ip);
            self.first_punching_index += MAX_PORTS_TO_PUNCH;
            addrs
        };

        if self.num_punch_tries > MAX_NORMAL_PUNCHING_TRIES {
            addrs.append(&mut self.last_hole_punching(ip));
            self.last_punching_index += MAX_PORTS_TO_PUNCH - (MAX_PORTS_TO_PUNCH / 2);
        };

        addrs.dedup();

        self.num_punch_tries = self.num_punch_tries.saturating_add(1);

        addrs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hole_punch_new() {
        let hole_punch = HolePunching::new();
        assert!(hole_punch.is_punching_done);
        assert_eq!(hole_punch.num_punch_tries, 0);
        assert!(hole_punch.last_send_ping_time.is_none());
        assert!(hole_punch.last_punching_time.is_none());
        assert_eq!(hole_punch.first_punching_index, 0);
        assert_eq!(hole_punch.last_punching_index, 0);
    }

    #[test]
    fn hole_punch_default() {
        let hole_punch = HolePunching::default();
        assert!(hole_punch.is_punching_done);
        assert_eq!(hole_punch.num_punch_tries, 0);
        assert!(hole_punch.last_send_ping_time.is_none());
        assert!(hole_punch.last_punching_time.is_none());
        assert_eq!(hole_punch.first_punching_index, 0);
        assert_eq!(hole_punch.last_punching_index, 0);
    }

    #[test]
    fn hole_punch_get_common_ip_with_null_addrs() {
        let addrs = vec![];

        let mut hole_punch = HolePunching::new();
        hole_punch.is_punching_done = false;

        assert!(hole_punch.next_punch_addrs(&addrs).is_empty());
    }

    #[test]
    fn hole_punch_get_common_ip_with_under_half_addrs() {
        let addrs = vec![
            "127.0.0.1:11111".parse().unwrap(),
            "127.0.0.1:22222".parse().unwrap(),
            "127.0.0.2:33333".parse().unwrap(),
        ];

        let mut hole_punch = HolePunching::new();
        hole_punch.is_punching_done = false;

        assert!(hole_punch.next_punch_addrs(&addrs).is_empty());
    }

    #[test]
    fn hole_punch_get_common_ip_with_enough_addrs() {
        let addrs = vec![
            "127.0.0.1:11111".parse().unwrap(),
            "127.0.0.1:22222".parse().unwrap(),
            "127.0.0.2:33333".parse().unwrap(),
            "127.0.0.1:44444".parse().unwrap(),
            "127.0.0.1:55555".parse().unwrap(),
            "127.0.0.1:55556".parse().unwrap(),
            "127.0.0.1:55557".parse().unwrap(),
            "127.0.0.1:55558".parse().unwrap(),
            "127.0.0.2:55559".parse().unwrap(),
        ];

        let mut hole_punch = HolePunching::new();
        hole_punch.is_punching_done = false;

        assert!(!hole_punch.next_punch_addrs(&addrs).is_empty());
    }

    #[test]
    fn hole_punch_lash_punch() {
        let addrs = vec![
            "127.0.0.1:11111".parse().unwrap(),
            "127.0.0.1:22222".parse().unwrap(),
            "127.0.0.2:33333".parse().unwrap(),
            "127.0.0.1:44444".parse().unwrap(),
            "127.0.0.1:55555".parse().unwrap(),
            "127.0.0.1:55556".parse().unwrap(),
            "127.0.0.1:55557".parse().unwrap(),
            "127.0.0.1:55558".parse().unwrap(),
            "127.0.0.2:55559".parse().unwrap(),
        ];

        let mut hole_punch = HolePunching::new();
        hole_punch.is_punching_done = false;
        hole_punch.num_punch_tries = MAX_NORMAL_PUNCHING_TRIES + 1;

        assert!(!hole_punch.next_punch_addrs(&addrs).is_empty());
    }
}
