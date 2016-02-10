extern crate libsodium_sys;
extern crate sodiumoxide;

#[cfg(test)]
extern crate quickcheck;

/// Core Tox module. Provides an API on top of which other modules and
/// applications may be build.
#[warn(missing_docs)]
pub mod toxcore {
    pub mod binary_io;
    pub mod crypto_core;
    pub mod network;
}
