//! This crate rexports all tox crates in tox-rs.

pub use tox_core as core;
pub use tox_crypto as crypto;
pub use tox_encryptsave as encryptsave;
pub use tox_packet as packet;

pub fn crate_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
pub fn crate_version_major() -> u32 {
    env!("CARGO_PKG_VERSION_MAJOR").parse().expect("Invalid major version")
}
pub fn crate_version_minor() -> u32 {
    env!("CARGO_PKG_VERSION_MINOR").parse().expect("Invalid minor version")
}
pub fn crate_version_patch() -> u32 {
    env!("CARGO_PKG_VERSION_PATCH").parse().expect("Invalid patch version")
}
