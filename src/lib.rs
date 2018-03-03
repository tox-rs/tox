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
Rust implementation of the [Tox protocol](https://zetok.github.io/tox-spec).

Repo: https://github.com/tox-rs/tox

*/

#![cfg_attr(feature = "clippy", feature(plugin))]

#![cfg_attr(feature = "clippy", plugin(clippy))]

// Turn off clippy warnings that gives false positives
#![cfg_attr(feature = "clippy", allow(doc_markdown))]
#![cfg_attr(feature = "clippy", allow(useless_format))]
#![cfg_attr(feature = "clippy", allow(new_without_default, new_without_default_derive))]
// Remove it when in will be fixed in nom parser
#![cfg_attr(feature = "clippy", allow(redundant_closure))]
// Too many false positives in tests
#![cfg_attr(feature = "clippy", allow(needless_pass_by_value))]

// FIXME update to nom 4 and remove this rule
#![allow(unused_parens)]

extern crate bytes;
extern crate byteorder;
extern crate futures;
#[macro_use]
extern crate log;
#[macro_use]
extern crate nom;
#[macro_use]
extern crate cookie_factory;
extern crate sodiumoxide;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

extern crate tokio_core;
extern crate tokio_io;


// TODO: refactor macros
#[cfg(test)]
#[macro_use]
pub mod toxcore_tests {
    extern crate rand;
    extern crate rustc_serialize;

    // Helper macros for testing, no tests
    // #[warn(missing_docs)]
    // #[macro_use]
    // FIXME: use new dht code instead of old
    // pub mod test_macros;

    // tests
    mod crypto_core_tests;
    // FIXME: use new dht code instead of old
    // mod state_format_old_tests;
}


/** Core Tox module. Provides an API on top of which other modules and
    applications may be build.
*/
#[warn(missing_docs)]
pub mod toxcore {
    #[macro_use]
    pub mod binary_io;
    pub mod crypto_core;
    pub mod state_format;
    pub mod toxid;
    pub mod tcp;
    pub mod dht_new;
    pub mod onion;
}

/// Tox Encrypt Save (a.k.a. **TES**) module. Can be used to ecrypt / decrypt
/// data that will be stored on persistent storage.
// TODO: ↑ expand doc
#[warn(missing_docs)]
pub mod toxencryptsave;


#[cfg(test)]
mod toxencryptsave_tests {
    extern crate rand;

    mod encryptsave_tests;
}
