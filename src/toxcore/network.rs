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


use std::net::UdpSocket;


/// Minimum port which Tox will try to bind to.
pub const PORT_MIN: u16 = 33445;
/// Maximum port which Tox will try to bind to.
pub const PORT_MAX: u16 = 33545;

/// Bind to an UDP socket on `0.0.0.0` with a port in range [`PORT_MIN`]
/// (./constant.PORT_MIN.html):[`PORT_MAX`](./constant.PORT_MAX.html).
///
/// Returns `None` if failed to bind to port within range.
// TODO: perhaps use closure as an argument with 2 ports provided;
//        - if no args in closure (`||`), use port range from constants
//        - if 2 args in closure, validate port range from args and try to use
//          them to do the binding
pub fn bind_udp() -> Option<UdpSocket> {
    for port in PORT_MIN..(PORT_MAX + 1) {
        // TODO: check if `[::]` always works, even on platforms with disabled
        //       IPv6
        match UdpSocket::bind(&format!("[::]:{}", port)[..]) {
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
