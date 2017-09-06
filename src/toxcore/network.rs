/*
    Copyright © 2016-2017 Zetok Zalbavar <zexavexxe@gmail.com>

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


// ↓ FIXME expand doc
//! Networking part of the toxcore.

// TODO: separate stuff managing DHT from network
//       proper implementation of DHT should expose an interface that network
//       implements

use std::any::Any;
use std::rc::Rc;
use std::cell::RefCell;
use std::io::{ self, ErrorKind };
use std::ops::{ Range, RangeFrom, RangeTo, RangeFull };
use std::net::{ IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs };
use std::collections::HashMap;

use tokio_core::net::UdpSocket;
use tokio_core::reactor::Handle;

use super::crypto_core::crypto_init;


/// Minimum default port which Tox will try to bind to.
pub const PORT_MIN: u16 = 33445;
/// Maximum default port which Tox will try to bind to.
pub const PORT_MAX: u16 = 33545;
/// Maximum size of a UDP packet that tox will handle.
// TODO: check if it's still the biggest packet size
pub const MAX_UDP_PACKET_SIZE: usize = 2048;


/** Type for functions that handle packets.

- `addr` – sender address
- `data` – packet data
*/
// TODO: move out of `network` ?
pub type PacketHandlerCallback = fn(Rc<RefCell<Any>>, addr: SocketAddr, data: &[u8]) -> usize;

// TODO: move out of `network` ?
struct PacketHandles {
    object: Rc<RefCell<Any>>,
    function: PacketHandlerCallback
}

// TODO: move out of `network` ?
impl PacketHandles {
    #[inline]
    fn handle(&self, addr: SocketAddr, data: &[u8]) {
        (self.function)(self.object.clone(), addr, data);
    }
}

/// Networking Core.
pub struct NetworkingCore {
    packethandles: HashMap<u8, PacketHandles>,
    sock: UdpSocket
}

impl NetworkingCore {
    /** Initialize networking by binding to specified socket IP, and a port in
    supplied range.

    # Fails when

      - binding to IP address and every port in supplied range fails
      - setting broadcast on socket fails
    */
    pub fn new<R>(ip: IpAddr, port_range: R, handle: &Handle) -> io::Result<NetworkingCore>
        where R: Into<PortRange<u16>>
    {
        let PortRange(port_range) = port_range.into();

        // TODO: network shouldn't fail due to crypto, remove this from network
        //       and put in more fitting place
        if !crypto_init() {
            return Err(io::Error::new(ErrorKind::Other,
                        "Crypto initialization failed."));
        }

        let sock = try!(
            bind_udp(ip, port_range, handle)
                .ok_or_else(|| io::Error::new(ErrorKind::AddrInUse, "Addr/Port in use."))
        );

        if let IpAddr::V6(_) = ip {
            // TODO Dual-stack: set only_v6 to false.

            let res = sock.join_multicast_v6(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x01), 0);
            match res {
                Ok(_) => debug!("Local multicast group FF02::1 joined successfully"),
                Err(err) => debug!("Failed to activate local multicast membership. {}", err)
            }
        }

        // TODO set RCVBUF/SNDBUF/SIGPIPE
        try!(sock.set_broadcast(true));

        Ok(NetworkingCore {
            packethandles: HashMap::new(),
            sock: sock
        })
    }

    /** Function to call when packet beginning with byte is received.
    */
    // FIXME: docs
    pub fn register(&mut self, byte: u8, cb: PacketHandlerCallback, object: Rc<RefCell<Any>>) {
        self.packethandles.insert(byte, PacketHandles {
            object: object,
            function: cb
        });
    }

    /// Call this several times a second.
    // TODO: polling isn't really optimal, move away from it
    pub fn poll(&self) {
        let mut data = [0; MAX_UDP_PACKET_SIZE];

        while let Ok((size, addr)) = self.receive_packet(&mut data) {
            if size < 1 { continue };

            match self.packethandles.get(&data[0]) {
                Some(handler) => handler.handle(addr, &data[..size]),
                None => warn!("[{:x}] -- Packet has no handler", data[0])
            }
        }
    }

    /// Function to send packet (`data`) to SocketAddr.
    pub fn send_packet(&self, addr: SocketAddr, data: &[u8]) -> io::Result<usize> {
        // XXX need check target ip type?
        let res = self.sock.send_to(data, &addr);

        // TODO debug
        match res {
            Ok(size) => debug!("send: [{} -> {}] {:?}", addr, size, data),
            Err(ref err) => debug!("{}", err)
        }

        res
    }

    // TODO: convert docs to block style once rust gets fixed
    /** Receive packet data into `&mut data`.

    Returns `Option<(length, addr)>` or `io::Error`.

    If successfull, `(received bytes length, sender socket addr)` are
    returned.
    */
    pub fn receive_packet(&self, data: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let res = self.sock.recv_from(data);

        // TODO debug
        // TODO: should be `trace!` instead?
        match res {
            Ok((size, addr)) => debug!("recv: [{} -> {}] {:?}", addr, size, data),
            Err(ref err) => debug!("{}", err)
        }

        res
    }
}

/** Bind to an UDP socket on `0.0.0.0` with a port in range [`PORT_MIN`]
(./constant.PORT_MIN.html):[`PORT_MAX`](./constant.PORT_MAX.html).

Returns `None` if failed to bind to port within range.
*/
pub fn bind_udp(ip: IpAddr, port_range: Range<u16>, handle: &Handle)
    -> Option<UdpSocket>
{
    for port in port_range {
        match (ip, port).to_socket_addrs().ok()
            .and_then(|mut addrs| addrs.next())
            .ok_or_else(|| io::Error::new(ErrorKind::AddrNotAvailable, "Socket Addr Not Available."))
            .and_then(|addr| UdpSocket::bind(&addr, handle))
        {
            Ok(s) => {
                debug!(target: "Port", "Bind to port {} successful.", port);
                return Some(s)
            },
            Err(e) => trace!(target: "Port", "Bind to port {} unsuccessful: {}",
                             port, e),
        }
    }
    error!(target: "Port", "Failed to bind to any port in range!");
    None  // loop ended without "early" return – failed to bind
}

/** Port Range, default is
[`PORT_MIN`](./constant.PORT_MIN.html)..[`PORT_MAX`](./constant.PORT_MAX.html).
*/
#[derive(Clone, Debug, PartialEq)]
pub struct PortRange<N>(pub Range<N>);

/** If one is 0 and the other is non-0, use the non-0 value as only port

```
# use tox::toxcore::network::PortRange;
assert_eq!(PortRange(33445..33446), (33445..).into());
```
*/
impl From<RangeFrom<u16>> for PortRange<u16> {
    fn from(range: RangeFrom<u16>) -> PortRange<u16> {
        let RangeFrom { start } = range;
        PortRange(Range { start: start, end: start + 1 })
    }
}

/** If one is 0 and the other is non-0, use the non-0 value as only port

```
# use tox::toxcore::network::PortRange;
assert_eq!(PortRange(33445..33446), (..33445).into());
```
*/
impl From<RangeTo<u16>> for PortRange<u16> {
    fn from(range: RangeTo<u16>) -> PortRange<u16> {
        let RangeTo { end } = range;
        PortRange(Range { start: end, end: end + 1 })
    }
}

/** If both from and to are 0, use default port range

```
# use tox::toxcore::network::PortRange;
assert_eq!(PortRange(33445..33546), (..).into());
```
*/
impl From<RangeFull> for PortRange<u16> {
    fn from(_: RangeFull) -> PortRange<u16> {
        PortRange(Range { start: PORT_MIN, end: PORT_MAX + 1 })
    }
}

/** If `from > to`, values are swapped.

```
# use tox::toxcore::network::PortRange;
assert_eq!(PortRange(33445..33546), (33445..33546).into());
assert_eq!(PortRange(33445..33546), (33546..33445).into());
```
*/
impl From<Range<u16>> for PortRange<u16> {
    fn from(range: Range<u16>) -> PortRange<u16> {
        let Range { start, end } = range;
        PortRange(if start > end {
            Range { start: end, end: start }
        } else {
            Range { start: start, end: end }
        })
    }
}
