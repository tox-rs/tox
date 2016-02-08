extern crate sodiumoxide;

#[cfg(test)]
extern crate quickcheck;

pub mod toxcore {
    pub mod binary_io;
    pub mod crypto_core;
    pub mod network;
}
