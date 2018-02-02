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

/*! Data associated with the `PacketKind`. Used by most of other `dht`
    modules.

    Used by:

    * [`dht`](../dht/index.html)
*/

use nom::le_u8;

use toxcore::dht_new::binary_io::*;


/** Top-level packet kind names and their associated numbers.

    According to https://zetok.github.io/tox-spec.html#packet-kind.
*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketKind {
    /// [`Ping`](./struct.Ping.html) request number.
    PingRequest       = 0,
    /// [`Ping`](./struct.Ping.html) response number.
    PingResponse      = 1,
    /// [`GetNodes`](./struct.GetNodes.html) packet number.
    GetNodes          = 2,
    /// [`SendNodes`](./struct.SendNodes.html) packet number.
    SendNodes         = 4,
    /// DHT Request.
    DhtRequest        = 32,
}

/** Parse first byte from provided `bytes` as `PacketKind`.

    Returns `None` if no bytes provided, or first byte doesn't match.
*/
impl FromBytes for PacketKind {
    named!(from_bytes<PacketKind>, switch!(le_u8,
        0   => value!(PacketKind::PingRequest) |
        1   => value!(PacketKind::PingResponse) |
        2   => value!(PacketKind::GetNodes) |
        4   => value!(PacketKind::SendNodes) |
        32  => value!(PacketKind::DhtRequest)
    ));
}
