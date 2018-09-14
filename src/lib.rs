/*!
Rust implementation of the [Tox protocol](https://zetok.github.io/tox-spec).

Repo: https://github.com/tox-rs/tox

*/

#![cfg_attr(feature = "cargo-clippy", feature(tool_lints))]
// Turn off clippy warnings that gives false positives
#![cfg_attr(feature = "cargo-clippy", allow(clippy::new_without_default, clippy::new_without_default_derive))]
// Remove it when it will be fixed in nom parser
#![cfg_attr(feature = "cargo-clippy", allow(clippy::redundant_closure))]
// Too many false positives in tests
#![cfg_attr(all(feature = "cargo-clippy", test), allow(clippy::needless_pass_by_value))]

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
extern crate quickcheck;

extern crate tokio;
extern crate tokio_codec;
extern crate get_if_addrs;
extern crate parking_lot;
#[macro_use]
extern crate failure;

#[cfg(test)]
extern crate tokio_timer;
#[cfg(test)]
extern crate tokio_executor;

// TODO: refactor macros
#[cfg(test)]
#[macro_use]
pub mod toxcore_tests {
    extern crate rand;

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
    pub mod io_tokio;
    pub mod crypto_core;
    pub mod time;
    pub mod state_format;
    pub mod toxid;
    pub mod tcp;
    pub mod dht;
    pub mod onion;
    pub mod net_crypto;
    pub mod utils;
    pub mod friend_connection;
    pub mod messenger;
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
