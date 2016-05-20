/*
    Copyright © 2016 Zetok Zalbavar <zexavexxe@gmail.com>

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


use std::any::Any;
use std::rc::Rc;
use std::cell::RefCell;
use std::io::{ self, ErrorKind };
use std::sync::{ Once, ONCE_INIT };
use std::ops::{ Range, RangeFrom, RangeTo, RangeFull };
use std::net::{ IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs };
use std::collections::HashMap;
use mio::udp::UdpSocket;
use sodiumoxide;


/// Minimum port which Tox will try to bind to.
pub const PORT_MIN: u16 = 33445;
/// Maximum port which Tox will try to bind to.
pub const PORT_MAX: u16 = 33545;
/// Maximum size of a UDP packet that tox will handle.
pub const MAX_UDP_PACKET_SIZE: usize = 2048;

static AT_STARTUP_RAN: Once = ONCE_INIT;

fn networking_at_startup() -> bool {
    let mut output = true;
    AT_STARTUP_RAN.call_once(|| output = sodiumoxide::init());
    output
}

/** Function to receive data, ip and port of sender is put into ip_port.
    Packet data is put into data.
    Packet length is put into length.
*/
pub type PacketHandlerCallback = fn(Rc<RefCell<Any>>, SocketAddr, &[u8]) -> usize;

pub struct PacketHandles {
    object: Rc<RefCell<Any>>,
    function: PacketHandlerCallback
}

impl PacketHandles {
    #[inline]
    pub fn handle(&self, addr: SocketAddr, data: &[u8]) {
        (self.function)(self.object.clone(), addr, data);
    }
}

pub struct NetworkingCore {
    packethandles: HashMap<u8, PacketHandles>,
    sock: UdpSocket
}

impl NetworkingCore {
    /** Initialize networking.
        Added for reverse compatibility with old new_networking calls.

        ```
        use tox::toxcore::network::NetworkingCore;

        NetworkingCore::new("[::]:33445").unwrap();
        ```
    */
    pub fn new<T: ToSocketAddrs>(addr: T) -> io::Result<NetworkingCore> {
        let addr = try!(
            try!(addr.to_socket_addrs()).next()
                .ok_or(io::Error::new(ErrorKind::InvalidInput, "No Address"))
        );
        NetworkingCore::new_ex(addr.ip(), addr.port()..(addr.port() + (PORT_MAX - PORT_MIN)))
    }

    // TODO fix docs
    /** Initialize networking.
        Bind to ip and port.
        ip must be in network order EX: 127.0.0.1 = (7F000001).
        port is in host byte order (this means don't worry about it).

         return NetworkingCore object if no problems
         return NULL if there are problems.

        If error is non NULL it is set to 0 if no issues, 1 if socket related error, 2 if other.

        ```
        use tox::toxcore::network::NetworkingCore;

        NetworkingCore::new_ex("::".parse().unwrap(), 33445..33545).unwrap();
        ```
    */
    pub fn new_ex<R: Into<PortRange<u16>>>(ip: IpAddr, port_range: R) -> io::Result<NetworkingCore> {
        let PortRange(port_range) = port_range.into();

        if !networking_at_startup() {
            return Err(io::Error::new(ErrorKind::Other, "Startup error."));
        }

        let sock = try!(
            bind_udp(ip, port_range)
                .ok_or_else(|| io::Error::new(ErrorKind::AddrInUse, "Addr/Port in use."))
        );

        if let IpAddr::V6(_) = ip {
            // TODO Dual-stack: set only_v6 to false.

            let res = sock.join_multicast(&IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x01)));
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

    /**
        ```
        # use std::rc::Rc;
        # use std::any::Any;
        # use std::cell::RefCell;
        # use std::net::SocketAddr;
        # use tox::toxcore::network::NetworkingCore;
        # let mut net = NetworkingCore::new("[::]:33445").unwrap();
        fn callback(num: Rc<RefCell<Any>>, _: SocketAddr, _: &[u8]) -> usize {
            match num.borrow().downcast_ref::<usize>() {
                Some(&num) => unimplemented!(),
                None => 0
            }
        }

        net.register(99, callback, Rc::new(RefCell::new(1)) as Rc<RefCell<Any>>);

        // ..
        ```
    */
    pub fn register(&mut self, byte: u8, cb: PacketHandlerCallback, object: Rc<RefCell<Any>>) {
        self.packethandles.insert(byte, PacketHandles {
            object: object,
            function: cb
        });
    }

    pub fn poll(&self) {
        let mut data = [0; MAX_UDP_PACKET_SIZE];

        loop {
            match self.receive_packet(&mut data) {
                Ok(Some((size, addr))) => {
                    if size < 1 { continue };

                    match self.packethandles.get(&data[0]) {
                        Some(handler) => handler.handle(addr, &data[..size]),
                        None => warn!("[{:x}] -- Packet has no handler", data[0])
                    }
                },
                Ok(None) => continue,
                Err(err) => {
                    warn!("{:?}", err);
                    break
                }
            }
        }
    }

    pub fn send_packet(&self, addr: SocketAddr, data: &[u8]) -> io::Result<Option<usize>> {
        // XXX need check target ip type?
        let res = self.sock.send_to(data, &addr);

        // TODO debug
        match &res {
            &Ok(Some(size)) => debug!("send: [{} -> {}] {:?}", addr, size, data),
            &Ok(None) => debug!("send: [none] {:?}", data),
            &Err(ref err) => debug!("{}", err)
        }

        res
    }

    pub fn receive_packet(&self, data: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>> {
        let res = self.sock.recv_from(data);

        // TODO debug
        match &res {
            &Ok(Some((size, addr))) => debug!("recv: [{} -> {}] {:?}", addr, size, data),
            &Ok(None) => debug!("recv: [none] {:?}", data),
            &Err(ref err) => debug!("{}", err)
        }

        res
    }
}

/** Bind to an UDP socket on `0.0.0.0` with a port in range [`PORT_MIN`]
    (./constant.PORT_MIN.html):[`PORT_MAX`](./constant.PORT_MAX.html).

    Returns `None` if failed to bind to port within range.
*/
pub fn bind_udp(ip: IpAddr, port_range: Range<u16>) -> Option<UdpSocket> {
    for port in port_range {
        match (ip, port).to_socket_addrs().ok()
            .and_then(|mut addrs| addrs.next())
            .ok_or_else(|| io::Error::new(ErrorKind::AddrNotAvailable, "Socket Addr Not Available."))
            .and_then(|addr| UdpSocket::bound(&addr))
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

/** Correct Port Range.
    If both from and to are 0, use default port range
    If one is 0 and the other is non-0, use the non-0 value as only port
    If from > to, swap
*/
#[derive(Clone, Debug, PartialEq)]
pub struct PortRange<N>(pub Range<N>);

/// If one is 0 and the other is non-0, use the non-0 value as only port
///
/// ```
/// # use tox::toxcore::network::PortRange;
/// assert_eq!(PortRange(33445..33446), (33445..).into());
/// ```
impl From<RangeFrom<u16>> for PortRange<u16> {
    fn from(range: RangeFrom<u16>) -> PortRange<u16> {
        let RangeFrom { start } = range;
        PortRange(Range { start: start, end: start + 1 })
    }
}

/// If one is 0 and the other is non-0, use the non-0 value as only port
///
/// ```
/// # use tox::toxcore::network::PortRange;
/// assert_eq!(PortRange(33445..33446), (..33445).into());
/// ```
impl From<RangeTo<u16>> for PortRange<u16> {
    fn from(range: RangeTo<u16>) -> PortRange<u16> {
        let RangeTo { end } = range;
        PortRange(Range { start: end, end: end + 1 })
    }
}

/// If both from and to are 0, use default port range
///
/// ```
/// # use tox::toxcore::network::PortRange;
/// assert_eq!(PortRange(33445..33546), (..).into());
/// ```
impl From<RangeFull> for PortRange<u16> {
    fn from(_: RangeFull) -> PortRange<u16> {
        PortRange(Range { start: PORT_MIN, end: PORT_MAX + 1 })
    }
}

/// If from > to, swap
///
/// ```
/// # use tox::toxcore::network::PortRange;
/// assert_eq!(PortRange(33445..33546), (33445..33546).into());
/// assert_eq!(PortRange(33445..33546), (33546..33445).into());
/// ```
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
