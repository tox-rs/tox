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

extern crate sodiumoxide;

extern crate ip;


/// Core Tox module. Provides an API on top of which other modules and
/// applications may be build.
#[warn(missing_docs)]
pub mod toxcore {
    pub mod binary_io;
    pub mod crypto_core;
    pub mod dht;
}

#[cfg(test)]
extern crate quickcheck;

#[cfg(test)]
mod toxcore_tests {
    mod binary_io_tests;
    mod crypto_core_tests;
    mod dht_tests;
}
