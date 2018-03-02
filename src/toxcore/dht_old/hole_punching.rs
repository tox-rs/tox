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


/*!
Module for hole-punching. Build on top of DHT.

https://zetok.github.io/tox-spec/#hole-punching
*/


/// Types of NATs.
pub enum NatKind {
    /// Cone NAT. Eeasiest to deal with, since friend will just respond to
    /// [DHT `Ping` request](../dht/struct.Ping.html). Close to use nodes will
    /// return same `IP:port` of friend.
    ///
    /// https://zetok.github.io/tox-spec/#cone-nat
    ConeNat,

    /// Doesn't respond to DHT Ping request. Close to us peers will return to us
    /// same `IP:port` of friend.
    ///
    /// https://zetok.github.io/tox-spec/#restricted-cone-nat
    ResConeNat,

    /// Doesn't respond to DHT Ping request. Close to us peers will return to us
    /// same `IP`, but differnt `port` of friend.
    ///
    /// https://zetok.github.io/tox-spec/#symmetric-nat
    SymNat,

    /// This kind of NAT either can't be hole-punched, or close to us nodes
    /// just provide us with an outdated info. Use most-common `IP:port` for
    /// hole-punching, hoping that it's just an outdated info.
    Other,
}
