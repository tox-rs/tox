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
#[derive(Clone, Debug)]
pub struct HolePunching {
    /// flag for hole punching is done or not.
    pub is_punching_done: bool,
    /// number of punching tries
    pub num_punch_tries: u32,
    /// last timestamp of receiving NatPingResponse packet
    pub last_recv_ping_time: Instant,
    /// last timestamp of sending NatPingRequest packet
    pub last_send_ping_time: Option<Instant>,
    /// last timestamp of trying hole punch
    /// it is used to send NatPingRequest every 3 seconds
    pub last_punching_time: Option<Instant>,
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
            last_send_ping_time: None,
            last_punching_time: None,
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
    pub fn try_nat_punch(&mut self, server: &Server, friend_pk: PublicKey, addrs: Vec<SocketAddr>) -> IoFuture<()> {
        if !self.is_punching_done &&
            self.last_punching_time.map_or(true, |time| time.elapsed() >= Duration::from_secs(NAT_PING_PUNCHING_INTERVAL)) &&
            self.last_recv_ping_time.elapsed() <= Duration::from_secs(NAT_PING_PUNCHING_INTERVAL) * 2 {
                let ip = match HolePunching::get_common_ip(&addrs, MAX_CLIENTS_PER_FRIEND / 2) {
                    // A friend can have maximum 8 close node.
                    // If 4 or more close nodes have same IP(with different ports), we consider friend is behind NAT.
                    // Otherwise we do nothing.
                    None => return Box::new(future::ok(())),
                    Some(ip) => ip,
                };

                if self.last_punching_time.map_or(true, |time| time.elapsed() > Duration::from_secs(RESET_PUNCH_INTERVAL)) {
                    self.num_punch_tries = 0;
                    self.first_punching_index = 0;
                    self.last_punching_index = 0;
                }

                let ports_to_try = HolePunching::get_nat_ports(&addrs, ip);

                let res = self.punch(ports_to_try, ip, server, friend_pk);

                self.last_punching_time = Some(Instant::now());
                self.is_punching_done = true;

                res
        } else {
            // NatPingResponse is not responded, or hole punching was already done,
            // or the elapsed time is too long since we received NatPingResponse,
            // then we do nothing.
            Box::new(future::ok(()))
        }
    }

    // Calc most common IP. "most common IP" is a overlapping IP of close nodes of a friend.
    // if number of most common IP exceeds need_num, return it.
    // need_num is normally 4, 4 is half of maximum close nodes per friend.
    // When half of clients have same IP with different port, we consider it as
    // friend is behind NAT.
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

    // Get ports list of given IP
    fn get_nat_ports(addrs: &[SocketAddr], ip: IpAddr) -> Vec<u16> {
        addrs.iter()
            .filter(|addr| addr.ip() == ip)
            .map(|addr| addr.port())
            .collect::<Vec<u16>>()
    }

    // punch using first_punching_index
    // do hole punching for typical NAT, but last_hole_punching do hole punching on more precise ports
    fn first_hole_punching(&mut self, ports: Vec<u16>, ip: IpAddr, server: &Server, friend_pk: PublicKey) -> IoFuture<()> {
        let num_ports = ports.len();
        let first_punching_index = self.first_punching_index;
        let ping_sender = (0..MAX_PORTS_TO_PUNCH)
            .map(|i| {
                // algorithm from irungentoo
                // https://zetok.github.io/tox-spec/#symmetric-nat
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
    // do hole punchng on more precise ports.
    fn last_hole_punching(&mut self, ip: IpAddr, server: &Server, friend_pk: PublicKey) -> IoFuture<()> {
        let port: u32 = 1024;

        let last_punching_index = self.last_punching_index;
        let ping_sender = (0..MAX_PORTS_TO_PUNCH)
            .map(|i| {
                // algorithm from irungentoo
                // https://zetok.github.io/tox-spec/#symmetric-nat
                let it = i + last_punching_index;
                let port = port + it;
                server.send_ping_req(
                    &PackedNode {
                        pk: friend_pk,
                        saddr: SocketAddr::new(ip, port as u16),
                    }
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

    #[test]
    fn hole_punch_new_test() {
        let hole_punch = HolePunching::new();

        assert!(hole_punch.ping_id != 0);
    }

    #[test]
    fn hole_punch_get_common_ip_with_null_addrs_test() {
        let (pk, sk) = gen_keypair();
        let (friend_pk, _friend_sk) = gen_keypair();
        let (tx, _rx) = mpsc::unbounded::<(DhtPacket, SocketAddr)>();
        let alice = Server::new(tx, pk, sk);

        let addrs = vec![];

        let mut hole_punch = HolePunching::new();
        hole_punch.is_punching_done = false;

        assert!(hole_punch.try_nat_punch(&alice, friend_pk, addrs).wait().is_ok());
    }

    #[test]
    fn hole_punch_get_common_ip_with_under_half_addrs_test() {
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

        assert!(hole_punch.try_nat_punch(&alice, friend_pk, addrs).wait().is_ok());
    }

    #[test]
    fn hole_punch_get_common_ip_with_enough_addrs_test() {
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

        assert!(hole_punch.try_nat_punch(&alice, friend_pk, addrs).wait().is_ok());
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

        assert!(hole_punch.try_nat_punch(&alice, friend_pk, addrs).wait().is_ok());
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

        hole_punch.try_nat_punch(&alice, friend_pk, addrs).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, _addr_to_send) = received.unwrap();

        let ping_req = unpack!(packet, DhtPacket::PingRequest);

        let ping_req_payload = ping_req.get_payload(&friend_sk).unwrap();

        let ping_map = alice.get_ping_map();
        let mut ping_map = ping_map.write();

        let client = ping_map.get_mut(&friend_pk).unwrap();

        assert!(client.check_ping_id(ping_req_payload.id));
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

        hole_punch.try_nat_punch(&alice, friend_pk, addrs).wait().unwrap();

        let (received, _rx) = rx.into_future().wait().unwrap();
        let (packet, _addr_to_send) = received.unwrap();

        let ping_req = unpack!(packet, DhtPacket::PingRequest);

        let ping_req_payload = ping_req.get_payload(&friend_sk).unwrap();

        let ping_map = alice.get_ping_map();
        let mut ping_map = ping_map.write();

        let client = ping_map.get_mut(&friend_pk).unwrap();

        assert!(client.check_ping_id(ping_req_payload.id));
    }
}
