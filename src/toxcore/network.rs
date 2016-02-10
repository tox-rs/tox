/* network.rs

    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2016 Zetok Zalbavar

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

//! Datatypes, functions and constants for the core networking.


/// Maximum size in bytes of an UDP packet.
pub const MAX_UDP_PACKET_SIZE: usize = 2048;

/// Type of packet received/sent by `toxcore`.
#[derive(Clone, Copy, Debug)]
pub enum NetPacket {
    /// Ping request packet ID.
    PingRequest     = 0,
    /// Ping response packet ID.
    PingResponse    = 1,
    /// Get nodes request packet ID.
    GetNodes        = 2,
    ///Send nodes response packet ID for other addresses.
    SendNodesIpv6   = 4,
    /// Cookie request packet.
    CookieRequest   = 24,
    /// Cookie response packet.
    CookieResponse  = 25,
    /// Crypto handshake packet.
    CryptoHs        = 26,
    /// Crypto data packet.
    CryptoData      = 27,
    /// Encrypted data packet ID.
    ///
    /// Needed by `crypto_core`
    Crypto          = 32,
    /// LAN discovery packet ID.
    LanDiscovery    = 33,
}

// Functionality needed by this module is going to be stabilized in Rust 1.7:
// https://github.com/rust-lang/rust/issues/27709
