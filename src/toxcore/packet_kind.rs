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

/*! Data associated with the `PacketKind`. Used by most of other `toxcore`
    modules.

    Used by:

    * [`dht`](../dht/index.html)
*/

use nom::le_u8;

use toxcore::binary_io::*;


/** Top-level packet kind names and their associated numbers.

    According to https://zetok.github.io/tox-spec.html#packet-kind.
*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketKind {
    /// [`Ping`](./struct.Ping.html) request number.
    PingReq       = 0,
    /// [`Ping`](./struct.Ping.html) response number.
    PingResp      = 1,
    /// [`GetNodes`](./struct.GetNodes.html) packet number.
    GetN          = 2,
    /// [`SendNodes`](./struct.SendNodes.html) packet number.
    SendN         = 4,
    /// Cookie Request.
    CookieReq     = 24,
    /// Cookie Response.
    CookieResp    = 25,
    /// Crypto Handshake.
    CryptoHs      = 26,
    /// Crypto Data (general purpose packet for transporting encrypted data).
    CryptoData    = 27,
    /// DHT Request.
    DhtReq        = 32,
    /// LAN Discovery.
    LanDisc       = 33,
    /// Onion Reuqest 0.
    OnionReq0     = 128,
    /// Onion Request 1.
    OnionReq1     = 129,
    /// Onion Request 2.
    OnionReq2     = 130,
    /// Announce Request.
    AnnReq        = 131,
    /// Announce Response.
    AnnResp       = 132,
    /// Onion Data Request.
    OnionDataReq  = 133,
    /// Onion Data Response.
    OnionDataResp = 134,
    /// Onion Response 3.
    OnionResp3    = 140,
    /// Onion Response 2.
    OnionResp2    = 141,
    /// Onion Response 1.
    OnionResp1    = 142,
}

/** Parse first byte from provided `bytes` as `PacketKind`.

    Returns `None` if no bytes provided, or first byte doesn't match.
*/
from_bytes!(PacketKind, switch!(le_u8,
    0   => value!(PacketKind::PingReq) |
    1   => value!(PacketKind::PingResp) |
    2   => value!(PacketKind::GetN) |
    4   => value!(PacketKind::SendN) |
    24  => value!(PacketKind::CookieReq) |
    25  => value!(PacketKind::CookieResp) |
    26  => value!(PacketKind::CryptoHs) |
    27  => value!(PacketKind::CryptoData) |
    32  => value!(PacketKind::DhtReq) |
    33  => value!(PacketKind::LanDisc) |
    128 => value!(PacketKind::OnionReq0) |
    129 => value!(PacketKind::OnionReq1) |
    130 => value!(PacketKind::OnionReq2) |
    131 => value!(PacketKind::AnnReq) |
    132 => value!(PacketKind::AnnResp) |
    133 => value!(PacketKind::OnionDataReq) |
    134 => value!(PacketKind::OnionDataResp) |
    140 => value!(PacketKind::OnionResp3) |
    141 => value!(PacketKind::OnionResp2) |
    142 => value!(PacketKind::OnionResp1)
));
