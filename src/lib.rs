/*!
Rust implementation of the [Tox protocol](https://zetok.github.io/tox-spec).

Repo: https://github.com/tox-rs/tox

*/

#![doc(html_logo_url = "https://raw.githubusercontent.com/tox-rs/logo/master/logo.png")]
#![cfg_attr(feature = "cargo-clippy", feature(tool_lints))]
// Turn off clippy warnings that gives false positives
#![cfg_attr(feature = "cargo-clippy", allow(clippy::new_without_default, clippy::new_without_default_derive))]
// Remove it when it will be fixed in nom parser
#![cfg_attr(feature = "cargo-clippy", allow(clippy::redundant_closure))]

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

extern crate tokio;
extern crate tokio_codec;
extern crate get_if_addrs;
extern crate parking_lot;
#[macro_use]
extern crate failure;
extern crate lru;

#[cfg(test)]
extern crate tokio_timer;
#[cfg(test)]
extern crate tokio_executor;

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
    pub mod stats;
    pub mod error;
}

/// Tox Encrypt Save (a.k.a. **TES**) module. Can be used to ecrypt / decrypt
/// data that will be stored on persistent storage.
// TODO: ↑ expand doc
#[warn(missing_docs)]
pub mod toxencryptsave;


#[cfg(test)]
mod toxencryptsave_tests {
    mod encryptsave_tests;
}
