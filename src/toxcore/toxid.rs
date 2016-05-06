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

//! `Tox ID` and stuff related to it.
// FIXME: ↑ improve


use std::ops::Deref;

use super::crypto_core::*;


/** `NoSpam` used in [`ToxId`](./struct.ToxId.html).

    Number is used to make sure that there is no friend requests from peers
    that know out long term PK, but don't actually know Tox ID.

    The preferred way of creating `NoSpam` is to generate a random one.

    Additionally, it should be possible to set a custom `NoSpam`.

    https://zetok.github.io/tox-spec/#messenger
*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoSpam(pub [u8; NOSPAMBYTES]);

/// Number of bytes that [`NoSpam`](./struct.NoSpam.html) has.
pub const NOSPAMBYTES: usize = 4;

impl NoSpam {
    /// Create new `NoSpam` with random bytes.
    ///
    /// Two `new()` `NoSpam`s will always be different:
    ///
    /// ```
    /// use self::tox::toxcore::toxid::NoSpam;
    ///
    /// assert!(NoSpam::new() != NoSpam::new());
    /// ```
    pub fn new() -> Self {
        let mut nospam = [0; NOSPAMBYTES];
        randombytes_into(&mut nospam);
        NoSpam(nospam)
    }
}

impl Deref for NoSpam {
    type Target = [u8; NOSPAMBYTES];

    fn deref(&self) -> &[u8; NOSPAMBYTES] {
        let NoSpam(ref ns_bytes) = *self;
        ns_bytes
    }
}
