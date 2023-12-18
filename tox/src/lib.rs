//! This crate rexports all tox crates in tox-rs.

pub use tox_core as core;
pub use tox_crypto as crypto;
pub use tox_encryptsave as encryptsave;
pub use tox_packet as packet;

/// The tox crate version string in the form "major.minor.patch" (e.g. "1.2.3")
pub fn crate_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
/// The tox crate major version represented as unsigned integer
pub fn crate_version_major() -> u32 {
    env!("CARGO_PKG_VERSION_MAJOR").parse().expect("Invalid major version")
}
/// The tox crate minor version represented as unsigned integer
pub fn crate_version_minor() -> u32 {
    env!("CARGO_PKG_VERSION_MINOR").parse().expect("Invalid minor version")
}
/// The tox crate patch version represented as unsigned integer
pub fn crate_version_patch() -> u32 {
    env!("CARGO_PKG_VERSION_PATCH").parse().expect("Invalid patch version")
}

#[cfg(test)]
mod tests {
    #[test]
    fn crate_version_is_not_empty() {
        assert_ne!(crate::crate_version(), "");
    }

    #[test]
    fn crate_version_major() {
        let v = crate::crate_version_major();
        assert_eq!(v, env!("CARGO_PKG_VERSION_MAJOR").parse::<u32>().unwrap());
    }

    #[test]
    fn crate_version_minor() {
        let v = crate::crate_version_minor();
        assert_eq!(v, env!("CARGO_PKG_VERSION_MINOR").parse::<u32>().unwrap());
    }

    #[test]
    fn crate_version_patch() {
        let v = crate::crate_version_patch();
        assert_eq!(v, env!("CARGO_PKG_VERSION_PATCH").parse::<u32>().unwrap());
    }
}
