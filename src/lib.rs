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
