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

use toxcore::binary_io::*;


/** Top-level packet kind names and their associated numbers.

    According to https://toktok.github.io/spec.html#packet-kind.
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
impl FromBytes<PacketKind> for PacketKind {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        debug!(target: "PacketKind", "Creating PacketKind from bytes.");
        trace!(target: "PacketKind", "Bytes: {:?}", bytes);
        if bytes.is_empty() {
            return parse_error!("There are 0 bytes!")
        }

        let result = match bytes[0] {
            0   => PacketKind::PingReq,
            1   => PacketKind::PingResp,
            2   => PacketKind::GetN,
            4   => PacketKind::SendN,
            24  => PacketKind::CookieReq,
            25  => PacketKind::CookieResp,
            26  => PacketKind::CryptoHs,
            27  => PacketKind::CryptoData,
            32  => PacketKind::DhtReq,
            33  => PacketKind::LanDisc,
            128 => PacketKind::OnionReq0,
            129 => PacketKind::OnionReq1,
            130 => PacketKind::OnionReq2,
            131 => PacketKind::AnnReq,
            132 => PacketKind::AnnResp,
            133 => PacketKind::OnionDataReq,
            134 => PacketKind::OnionDataResp,
            140 => PacketKind::OnionResp3,
            141 => PacketKind::OnionResp2,
            142 => PacketKind::OnionResp1,
            _   => {
                return parse_error!("Byte can't be parsed as PacketKind!")
            },
        };

        Ok(Parsed(result, &bytes[1..]))
    }
}
