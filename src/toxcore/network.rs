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


pub const MAX_UDP_PACKET_SIZE: usize = 2048;

// those are needed by:
//  - crypto_core
#[derive(Clone, Copy, Debug)]
pub enum NetPacket {
    PingRequest     = 0,  // Ping request packet ID.
    PingResponse    = 1,  // Ping response packet ID.
    GetNodes        = 2,  // Get nodes request packet ID.
    SendNodesIpv6   = 4,  // Send nodes response packet ID for other addresses.
    CookieRequest   = 24, // Cookie request packet.
    CookieResponse  = 25, // Cookie response packet.
    CryptoHs        = 26, // Crypto handshake packet.
    CryptoData      = 27, // Crypto data packet.
    Crypto          = 32, // Encrypted data packet ID.
    LanDiscovery    = 33, // LAN discovery packet ID.
}
