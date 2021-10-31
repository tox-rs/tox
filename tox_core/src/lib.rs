/*!
Rust implementation of the [Tox protocol](https://zetok.github.io/tox-spec).

Repo: https://github.com/tox-rs/tox

*/

#![type_length_limit="2097152"]
#![forbid(unsafe_code)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/tox-rs/logo/master/logo.png")]
// Remove it when it will be fixed in nom parser
#![allow(clippy::redundant_closure, clippy::result_unit_err)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate nom;
#[macro_use]
extern crate cookie_factory;

pub mod io_tokio;
pub mod time;
pub mod state_format;
pub mod relay;
pub mod dht;
pub mod onion;
pub mod net_crypto;
pub mod utils;
pub mod friend_connection;
pub mod stats;
pub mod udp;
