/*
    Copyright © 2016 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2018 Namsoo CHO <nscho66@gmail.com>

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


/*!
Module for hole-punching.

https://zetok.github.io/tox-spec/#hole-punching
*/

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use futures::{future, stream, Stream};

use toxcore::crypto_core::*;
use toxcore::dht::server::*;
use toxcore::dht::packed_node::*;
use toxcore::io_tokio::IoFuture;

/// Interval in seconds for sending NatPingRequest
pub const NAT_PING_PUNCHING_INTERVAL: u64 = 3;
/// Interval in seconds to reset trying count of hole-punch,
/// if connecttion to friends is not done for over 40 seconds
/// retry to connect to friends using NatPingRequest
pub const RESET_PUNCH_INTERVAL: u64 = 40;
// Maximum number of ports to punch hole
const MAX_PORTS_TO_PUNCH: u32 = 48;
// Maximum trying count for hole punch
// after RESET_PUNCH_INTERVAL seconds it is reset if connection is not done.
const MAX_NORMAL_PUNCHING_TRIES: u32 = 5;
/// Maximum clients number per friend
pub const MAX_CLIENTS_PER_FRIEND: u32 = 8;

/// Structure for hole punch
pub struct HolePunching {
    /// flag for hole punching is done or not.
    pub is_punching_done: bool,
    /// number of punching tries
    pub num_punch_tries: u32,
    /// last timestamp of receiving NatPingResponse packet
    pub last_recv_ping_time: Instant,
    /// last timestamp of sending NatPingRequest packet
    pub last_send_ping_time: Instant,
    /// last timestamp of trying hole punch
    /// it is used to send NatPingRequest every 3 seconds
    pub last_punching_time: Instant,
    /// factor variable for guessing NAT port
    pub first_punching_index: u32,
    /// another factor variable for guessing NAT port
    pub last_punching_index: u32,
    /// holds ping_id used in NatPingRequest
    /// multi NatPingRequest has this same ping_id
    /// because every NatPingRequest receives NatPingResponse.
    pub ping_id: u64,
}

impl HolePunching {
    /// new object of HolePunching
    pub fn new() -> Self {
        HolePunching {
            is_punching_done: true,
            num_punch_tries: 0,
            last_recv_ping_time: Instant::now(),
            last_send_ping_time: Instant::now(),
            last_punching_time: Instant::now(),
            first_punching_index: 0,
            last_punching_index: 0,
            ping_id: HolePunching::new_ping_id(),
        }
    }

    // get new ping id for NatPingRequest packet
    fn new_ping_id() -> u64 {
        loop {
            let ping_id = random_u64();
            if ping_id != 0 {
                return ping_id;
            }
        }
    }

    /// send NatPingRequest and if condition is true, do hole punch
    pub fn try_nat_punch(&mut self, server: &Server, friend_pk: PublicKey, addrs: Vec<SocketAddr>,
                         nat_ping_req_interval: Duration) -> IoFuture<()> {
        if !self.is_punching_done &&
            self.last_punching_time.elapsed() >= nat_ping_req_interval &&
            self.last_recv_ping_time.elapsed() <= nat_ping_req_interval * 2 {
                let ip = match HolePunching::get_major_ip(&addrs, MAX_CLIENTS_PER_FRIEND / 2) {
                    None => return Box::new(future::ok(())),
                    Some(ip) => ip,
                };

                if self.last_punching_time.elapsed() > Duration::from_secs(RESET_PUNCH_INTERVAL) {
                    self.num_punch_tries = 0;
                    self.first_punching_index = 0;
                    self.last_punching_index = 0;
                }

                let ports_to_try = HolePunching::get_nat_ports(&addrs, ip);

                let res = self.punch(ports_to_try, ip, server, friend_pk);

                self.last_punching_time = Instant::now();
                self.is_punching_done = true;

                res
        } else {
            // NatPingResponse is not responded, or hole punching was already done,
            // or the elapsed time is too long since we received NatPingResponse,
            // then we do nothing.
            Box::new(future::ok(()))
        }
    }

    // Calc most common IP and if number of most common IP exceeds need_num, return it.
    // need_num is normally 4, 4 is half of maximum close nodes per friend.
    // When half of clients have same IP with different port, we consider it as
    // friend is behind NAT.
    fn get_major_ip(addrs: &[SocketAddr], need_num: u32) -> Option<IpAddr> {
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

    // Get ports list of given IP
    fn get_nat_ports(addrs: &[SocketAddr], ip: IpAddr) -> Vec<u16> {
        addrs.iter()
            .filter(|addr| addr.ip() == ip)
            .map(|addr| addr.port())
            .collect::<Vec<u16>>()
    }

    // punch using first_punching_index
    fn first_hole_punching(&mut self, ports: Vec<u16>, ip: IpAddr, server: &Server, friend_pk: PublicKey) -> IoFuture<()> {
        let num_ports = ports.len();
        let first_punching_index = self.first_punching_index;
        let ping_sender = (0..MAX_PORTS_TO_PUNCH)
            .map(|i| {
                let it = i + first_punching_index;
                let sign: i16 = if it % 2 == 1 { -1 } else { 1 };
                let delta = sign * (it / (2 * num_ports as u32)) as i16;
                let index = (it as usize / 2) % num_ports;
                let port = (ports[index] as i16 + delta) as u16;

                server.send_ping_req(
                    &PackedNode::new(false, SocketAddr::new(ip, port), &friend_pk)
                )
            });

        let ping_stream = stream::futures_unordered(ping_sender).then(|_| Ok(()));

        Box::new(ping_stream.for_each(|()| Ok(())))
    }

    // do punch using last_punching_index
    fn last_hole_punching(&mut self, ip: IpAddr, server: &Server, friend_pk: PublicKey) -> IoFuture<()> {
        let port: u32 = 1024;

        let last_punching_index = self.last_punching_index;
        let ping_sender = (0..MAX_PORTS_TO_PUNCH)
            .map(|i| {
                let it = i + last_punching_index;
                let port = port + it;
                server.send_ping_req(
                    &PackedNode::new(false, SocketAddr::new(ip, port as u16), &friend_pk)
                )
            });

        let ping_stream = stream::futures_unordered(ping_sender).then(|_| Ok(()));

        Box::new(ping_stream.for_each(|()| Ok(())))
    }

    // do hole punch using port guessing algorithm designed by irungentoo
    fn punch(&mut self, ports: Vec<u16>, ip: IpAddr, server: &Server, friend_pk: PublicKey) ->IoFuture<()> {
        if ports.is_empty() {
            return Box::new(future::ok(()))
        }

        // algorithm from irungentoo
        let first_port = ports[0];
        let num_ports = ports.len();
        let num_same_port = ports.iter().filter(|port| **port == first_port).count();

        let first_hole_punching = if num_same_port == num_ports {
            server.send_ping_req(
                &PackedNode::new(false, SocketAddr::new(ip, first_port), &friend_pk)
            )
        } else {
            let res = self.first_hole_punching(ports, ip, server, friend_pk);

            self.first_punching_index += MAX_PORTS_TO_PUNCH;

            res
        };

        let last_hole_punching = if self.num_punch_tries > MAX_NORMAL_PUNCHING_TRIES {
            let res = self.last_hole_punching(ip, server, friend_pk);
            self.last_punching_index += MAX_PORTS_TO_PUNCH - (MAX_PORTS_TO_PUNCH / 2);

            res
        } else {
            Box::new(future::ok(()))
        };

        self.num_punch_tries += 1;

        Box::new(first_hole_punching.join(last_hole_punching)
            .map(|_| ())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use toxcore::dht::packet::*;
    use futures::sync::mpsc;
    use std::thread;

    macro_rules! unpack {
        ($variable:expr, $variant:path) => (
            match $variable {
                $variant(inner) => inner,
                other => panic!("Expected {} but got {:?}", stringify!($variant), other),
            }
        )
    }

    #[test]
    fn hole_punch_new_test() {
        let hole_punch = HolePunching::new();

        assert!(hole_punch.ping_id != 0);
    }

    #[test]
    fn hole_punch_get_major_ip_with_null_addrs_test() {
        let (pk, sk) = gen_keypair();
        let (friend_pk, _friend_sk) = gen_keypair();
        let (tx, _rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
        let alice = Server::new(tx, pk, sk);

        let addrs = vec![];

        let mut hole_punch = HolePunching::new();
        hole_punch.is_punching_done = false;
        thread::sleep(Duration::from_millis(1));

        assert!(hole_punch.try_nat_punch(&alice, friend_pk, addrs, Duration::from_millis(1)).wait().is_ok());
    }

    #[test]
    fn hole_punch_get_major_ip_with_under_half_addrs_test() {
        let (pk, sk) = gen_keypair();
        let (friend_pk, _friend_sk) = gen_keypair();
        let (tx, _rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
        let alice = Server::new(tx, pk, sk);

        let addrs = vec![
            "127.0.0.1:11111".parse().unwrap(),
            "127.0.0.1:22222".parse().unwrap(),
            "127.0.0.2:33333".parse().unwrap(),
        ];

        let mut hole_punch = HolePunching::new();
        hole_punch.is_punching_done = false;
        thread::sleep(Duration::from_millis(1));

        assert!(hole_punch.try_nat_punch(&alice, friend_pk, addrs, Duration::from_millis(1)).wait().is_ok());
    }

    #[test]
    fn hole_punch_get_major_ip_with_enough_addrs_test() {
        let (pk, sk) = gen_keypair();
        let (friend_pk, _friend_sk) = gen_keypair();
        let (tx, _rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
        let alice = Server::new(tx, pk, sk);

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
        thread::sleep(Duration::from_millis(1));

        assert!(hole_punch.try_nat_punch(&alice, friend_pk, addrs, Duration::from_millis(1)).wait().is_ok());
    }

    #[test]
    fn hole_punch_get_nat_ports_test() {
        let (pk, sk) = gen_keypair();
        let (friend_pk, _friend_sk) = gen_keypair();
        let (tx, _rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
        let alice = Server::new(tx, pk, sk);
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
        thread::sleep(Duration::from_millis(1));

        assert!(hole_punch.try_nat_punch(&alice, friend_pk, addrs, Duration::from_millis(1)).wait().is_ok());
    }

    #[test]
    fn hole_punch_punch_test() {
        let (pk, sk) = gen_keypair();
        let (friend_pk, friend_sk) = gen_keypair();
        let (tx, rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
        let alice = Server::new(tx, pk, sk);
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
        thread::sleep(Duration::from_millis(150));

        hole_punch.try_nat_punch(&alice, friend_pk, addrs, Duration::from_millis(150)).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, _addr_to_send) = received.unwrap();

        let ping_req = unpack!(packet, DhtPacket::PingRequest);

        let ping_req_payload = ping_req.get_payload(&friend_sk).unwrap();

        let peers_cache = alice.get_peers_cache();
        let mut peers_cache = peers_cache.write();

        let client = peers_cache.get_mut(&friend_pk).unwrap();
        let dur = Duration::from_secs(PING_TIMEOUT);

        assert!(client.check_ping_id(ping_req_payload.id, dur));
    }

    #[test]
    fn hole_punch_lash_punch_test() {
        let (pk, sk) = gen_keypair();
        let (friend_pk, friend_sk) = gen_keypair();
        let (tx, rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
        let alice = Server::new(tx, pk, sk);
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
        thread::sleep(Duration::from_millis(150));

        hole_punch.try_nat_punch(&alice, friend_pk, addrs, Duration::from_millis(150)).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, _addr_to_send) = received.unwrap();

        let ping_req = unpack!(packet, DhtPacket::PingRequest);

        let ping_req_payload = ping_req.get_payload(&friend_sk).unwrap();

        let peers_cache = alice.get_peers_cache();
        let mut peers_cache = peers_cache.write();

        let client = peers_cache.get_mut(&friend_pk).unwrap();
        let dur = Duration::from_secs(PING_TIMEOUT);

        assert!(client.check_ping_id(ping_req_payload.id, dur));
    }
}
