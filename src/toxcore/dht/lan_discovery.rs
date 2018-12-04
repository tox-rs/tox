//! Module for LAN discovery.

use std::iter;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use futures::{stream, Stream};
use futures::sync::mpsc;
use get_if_addrs;
use get_if_addrs::IfAddr;
use tokio::timer::Interval;

use toxcore::crypto_core::*;
use toxcore::io_tokio::*;
use toxcore::dht::packet::*;

/// How many ports should be used on every iteration.
pub const PORTS_PER_DISCOVERY: u16 = 10;

/// To this port `LanDiscovery` packet will be sent every iteration. This port
/// shouldn't be included in `START_PORT` .. `END_PORT` range.
pub const DEFAULT_PORT: u16 = 33445;

/// Start port for sending `LanDiscovery` packets.
pub const START_PORT: u16 = 33446;

/// End port for sending `LanDiscovery` packets.
pub const END_PORT: u16 = 33546;

/// Interval in seconds between `LanDiscovery` packet sending.
pub const LAN_DISCOVERY_INTERVAL: u64 = 10;

/// Timeout in seconds for packet sending
pub const LAN_DISCOVERY_SEND_TIMEOUT: u64 = 1;

/// Shorthand for the transmit half of the message channel.
type Tx = mpsc::Sender<(Packet, SocketAddr)>;

/// LAN discovery struct
pub struct LanDiscoverySender {
    /// Sink to send packet to UDP socket
    tx: Tx,
    /// Our DHT `PublicKey`
    dht_pk: PublicKey,
    /// Whether our UDP socket is IPv6
    ipv6: bool,
    /// Start port for the next iteration of `LanDiscovery` packets sending
    next_port: u16,
}

impl LanDiscoverySender {
    /// Create new `LanDiscovery`.
    pub fn new(tx: Tx, dht_pk: PublicKey, ipv6: bool) -> LanDiscoverySender {
        LanDiscoverySender {
            tx,
            dht_pk,
            ipv6,
            next_port: START_PORT,
        }
    }

    /// Get broadcast addresses for host's network interfaces.
    fn get_ipv4_broadcast_addrs() -> Vec<IpAddr> {
        let ifs = get_if_addrs::get_if_addrs().expect("no network interface");
        ifs
            .iter()
            .filter_map(|interface|
                match interface.addr {
                    IfAddr::V4(ref addr) => addr.broadcast,
                    _ => None,
                }
            )
            .map(Into::into)
            .collect()
    }

    /// Get broadcast addresses depending on IP version.
    fn get_broadcast_addrs(&self) -> Vec<IpAddr> {
        let mut ip_addrs = LanDiscoverySender::get_ipv4_broadcast_addrs();
        if self.ipv6 {
            // IPv6 broadcast address
            ip_addrs.push("FF02::1".parse().unwrap());
            // IPv4 global broadcast address
            ip_addrs.push("::ffff:255.255.255.255".parse().unwrap());
        } else {
            // IPv4 global broadcast address
            ip_addrs.push("255.255.255.255".parse().unwrap());
        }
        ip_addrs
    }

    /// Get broadcast addresses to send `LanDiscovery` packet.
    ///
    /// This function returns Cartesian product of addresses from
    /// `get_broadcast_addrs` function with ports list of current iteration.
    fn get_broadcast_socket_addrs(&mut self) -> Vec<SocketAddr> {
        fn cycle(port: u16) -> u16 {
            (port - START_PORT) % (END_PORT - START_PORT) + START_PORT
        }
        let ip_addrs = self.get_broadcast_addrs();
        // range of ports to send discovery packet to
        let ports_range = (self.next_port .. self.next_port + PORTS_PER_DISCOVERY).map(cycle);
        // always send discovery packet to default port
        let ports_range = iter::once(DEFAULT_PORT).chain(ports_range);
        // add ports to ip addrs
        let socket_addrs = ip_addrs.into_iter().flat_map(move |ip_addr| {
            ports_range.clone().map(move |port| SocketAddr::new(ip_addr, port))
        }).collect();
        // update port for next iteration
        self.next_port = cycle(self.next_port + PORTS_PER_DISCOVERY);
        socket_addrs
    }

    /// Send `LanDiscovery` packets.
    fn send(&mut self) -> IoFuture<()> {
        let addrs = self.get_broadcast_socket_addrs();
        let lan_packet = Packet::LanDiscovery(LanDiscovery {
            pk: self.dht_pk,
        });

        let stream = stream::iter_ok(
            addrs.into_iter().map(move |addr| (lan_packet.clone(), addr))
        );

        send_all_to_bounded(&self.tx, stream, Duration::from_secs(LAN_DISCOVERY_SEND_TIMEOUT))
    }

    /// Run LAN discovery periodically. Result future will never be completed
    /// successfully.
    pub fn run(mut self) -> IoFuture<()> {
        let interval = Duration::from_secs(LAN_DISCOVERY_INTERVAL);
        let wakeups = Interval::new(Instant::now(), interval);
        let future = wakeups
            .map_err(|e| Error::new(ErrorKind::Other, format!("LanDiscovery timer error: {:?}", e)))
            .for_each(move |_instant| {
                trace!("LAN discovery sender wake up");
                self.send()
            });
        Box::new(future)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::{Future, Stream};

    fn broadcast_addrs_count() -> usize {
        get_if_addrs::get_if_addrs().expect("no network interface").iter().filter_map(|interface|
            match interface.addr {
                IfAddr::V4(ref addr) => addr.broadcast,
                _ => None,
            }
        ).map(|ipv4|
            SocketAddr::new(IpAddr::V4(ipv4), 33445)
        ).count()
    }

    #[test]
    fn send_ipv4() {
        // `+1` for 255.255.255.255
        let packets_count = (broadcast_addrs_count() + 1) * (PORTS_PER_DISCOVERY + 1) as usize;

        let (tx, mut rx) = mpsc::channel(packets_count);
        let (dht_pk, _dht_sk) = gen_keypair();
        let mut lan_discovery = LanDiscoverySender::new(tx, dht_pk, /* ipv6 */ false);

        assert!(lan_discovery.send().wait().is_ok());

        assert_eq!(lan_discovery.next_port, START_PORT + PORTS_PER_DISCOVERY);

        for _i in 0 .. packets_count {
            let (received, rx1) = rx.into_future().wait().unwrap();
            let (packet, _addr) = received.unwrap();

            let lan_discovery = unpack!(packet, Packet::LanDiscovery);

            assert_eq!(lan_discovery.pk, dht_pk);

            rx = rx1;
        }
    }

    #[test]
    fn send_ipv6() {
        // `+2` for ::1 and ::ffff:255.255.255.255
        let packets_count = (broadcast_addrs_count() + 2) * (PORTS_PER_DISCOVERY + 1) as usize;

        let (tx, mut rx) = mpsc::channel(packets_count);
        let (dht_pk, _dht_sk) = gen_keypair();
        let mut lan_discovery = LanDiscoverySender::new(tx, dht_pk, /* ipv6 */ true);

        assert!(lan_discovery.send().wait().is_ok());

        assert_eq!(lan_discovery.next_port, START_PORT + PORTS_PER_DISCOVERY);

        for _i in 0 .. packets_count {
            let (received, rx1) = rx.into_future().wait().unwrap();
            let (packet, _addr) = received.unwrap();

            let lan_discovery = unpack!(packet, Packet::LanDiscovery);

            assert_eq!(lan_discovery.pk, dht_pk);

            rx = rx1;
        }
    }

    #[test]
    fn cycle_around_ports() {
        // `+1` for 255.255.255.255
        let packets_count = (broadcast_addrs_count() + 1) * (PORTS_PER_DISCOVERY + 1) as usize;

        let (tx, mut rx) = mpsc::channel(packets_count);
        let (dht_pk, _dht_sk) = gen_keypair();
        let mut lan_discovery = LanDiscoverySender::new(tx, dht_pk, /* ipv6 */ false);

        lan_discovery.next_port = END_PORT - 1;

        assert!(lan_discovery.send().wait().is_ok());

        assert_eq!(lan_discovery.next_port, START_PORT + PORTS_PER_DISCOVERY - 1);

        for _i in 0 .. packets_count {
            let (received, rx1) = rx.into_future().wait().unwrap();
            let (packet, _addr) = received.unwrap();

            let lan_discovery = unpack!(packet, Packet::LanDiscovery);

            assert_eq!(lan_discovery.pk, dht_pk);

            rx = rx1;
        }
    }
}
