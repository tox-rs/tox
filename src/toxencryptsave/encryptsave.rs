/*
    Copyright © 2016 quininer kel <quininer@live.com>
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


use sodiumoxide::crypto::pwhash::{
    MEMLIMIT_INTERACTIVE, OPSLIMIT_INTERACTIVE,
    Salt, OpsLimit,
    gen_salt, derive_key
};

use sodiumoxide::crypto::box_::{
    PRECOMPUTEDKEYBYTES, NONCEBYTES, MACBYTES,
    Nonce, PrecomputedKey,
    gen_nonce
};

use sodiumoxide::crypto::hash::sha256;
use ::toxcore::crypto_core;

/// Length in bytes of the salt used to encrypt/decrypt data.
pub use sodiumoxide::crypto::pwhash::SALTBYTES as SALT_LENGTH;
/// Length in bytes of the key used to encrypt/decrypt data.
pub use sodiumoxide::crypto::box_::PRECOMPUTEDKEYBYTES as KEY_LENGTH;


/// Length (in bytes) of [`MAGIC_NUMBER`](./constant.MAGIC_NUMBER.html).
pub const MAGIC_LENGTH: usize = 8;
/** Bytes used to verify whether given data has been encrypted using
    toxencryptsave.

    Located at the beginning of the encrypted data.
*/
pub const MAGIC_NUMBER: &'static [u8; MAGIC_LENGTH] = b"toxEsave";
/// Minimal size in bytes of an encrypted file.
pub const EXTRA_LENGTH: usize = MAGIC_LENGTH + SALT_LENGTH + NONCEBYTES + MACBYTES;


#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PassKey {
    pub salt: Salt,
    pub key: PrecomputedKey
}

impl PassKey {
    /// Create a new `PassKey`.
    ///
    /// **Note that `passphrase` memory is not being zeroed after it has been
    /// used, contrary to what C toxcore does.** Code that provides `passphrase`
    /// should take care of zeroing that memory.
    ///
    /// Can fail for the same reasons as [`PassKey::with_salt()`]
    /// (./struct.PassKey.html#method.with_salt).
    pub fn new(passphrase: &[u8]) -> Result<PassKey, KeyDerivationError> {
        PassKey::with_salt(passphrase, gen_salt())
    }

    pub fn with_salt(passphrase: &[u8], salt: Salt) -> Result<PassKey, KeyDerivationError> {
        if passphrase.is_empty() { return Err(KeyDerivationError::Null) };

        let OpsLimit(ops) = OPSLIMIT_INTERACTIVE;
        let sha256::Digest(passhash) = sha256::hash(passphrase);
        let maybe_key = PrecomputedKey::from_slice(try!(
            derive_key(
                &mut [0; KEY_LENGTH],
                &passhash,
                &salt,
                OpsLimit(ops * 2),
                MEMLIMIT_INTERACTIVE
            ).or(Err(KeyDerivationError::Failed))
        ));

        Ok(PassKey {
            salt: salt,
            key: try!(maybe_key.ok_or(KeyDerivationError::Failed))
        })
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if data.is_empty() { return Err(EncryptionError::Null) };

        let mut output = Vec::new();
        output.extend_from_slice(MAGIC_NUMBER);
        output.extend_from_slice(&self.salt.0);
        let nonce = gen_nonce();
        output.extend_from_slice(&nonce.0);
        output.append(&mut crypto_core::encrypt_data_symmetric(
            &self.key,
            &nonce,
            data
        ));
        Ok(output)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, DecryptionError> {
        if data.is_empty() { return Err(DecryptionError::Null) };
        if data.len() <= EXTRA_LENGTH { return Err(DecryptionError::InvalidLength) };
        if !is_encrypted(data) { return Err(DecryptionError::BadFormat) };

        let nonce = try!(Nonce::from_slice(&data[
            MAGIC_LENGTH+SALT_LENGTH..MAGIC_LENGTH+SALT_LENGTH+NONCEBYTES
        ]).ok_or(DecryptionError::BadFormat));

        let output = try!(crypto_core::decrypt_data_symmetric(
            &self.key,
            &nonce,
            &data[MAGIC_LENGTH+SALT_LENGTH+NONCEBYTES..]
        ).or(Err(DecryptionError::Failed)));

        Ok(output)
    }
}

#[inline]
pub fn is_encrypted(data: &[u8]) -> bool {
    data.starts_with(MAGIC_NUMBER)
}

pub fn pass_encrypt(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    try!(PassKey::new(passphrase)).encrypt(data)
}

pub fn pass_decrypt(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, DecryptionError> {
    let salt = try!(get_salt(data).ok_or(KeyDerivationError::Failed));
    try!(PassKey::with_salt(passphrase, salt)).decrypt(data)
}

pub fn get_salt(data: &[u8]) -> Option<Salt> {
    if is_encrypted(data)
        && data.len() >= MAGIC_LENGTH + SALT_LENGTH
    {
        Salt::from_slice(&data[MAGIC_LENGTH..MAGIC_LENGTH+SALT_LENGTH])
    } else {
        None
    }
}

#[derive(Clone, Debug)]
pub enum KeyDerivationError {
    Null,
    Failed
}

#[derive(Clone, Debug)]
pub enum EncryptionError {
    Null,
    KeyDerivation(KeyDerivationError),
}

impl From<KeyDerivationError> for EncryptionError {
    fn from(err: KeyDerivationError) -> EncryptionError {
        EncryptionError::KeyDerivation(err)
    }
}

#[derive(Clone, Debug)]
pub enum DecryptionError {
    Null,
    InvalidLength,
    BadFormat,
    KeyDerivation(KeyDerivationError),
    Failed
}

impl From<KeyDerivationError> for DecryptionError {
    fn from(err: KeyDerivationError) -> DecryptionError {
        DecryptionError::KeyDerivation(err)
    }
}
