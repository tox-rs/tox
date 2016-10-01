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


/*!
E.g.

```
use tox::toxencryptsave::*;

let plaintext = b"pls no encrypt";
let password = b"123456";

// to encrypt data
let encrypted = pass_encrypt(plaintext, password)
    .expect("Failed to encrypt >.<\"");

// confirm that the data is encrypted
assert!(plaintext != encrypted.as_slice());
assert_eq!(true, is_encrypted(&encrypted));

// decrypted is same as plaintext
assert_eq!(plaintext,
           pass_decrypt(&encrypted, password).unwrap().as_slice());
```
*/


use sodiumoxide::crypto::pwhash::{
    MEMLIMIT_INTERACTIVE, OPSLIMIT_INTERACTIVE,
    Salt, OpsLimit,
    gen_salt, derive_key
};

use sodiumoxide::crypto::box_::{
    NONCEBYTES, MACBYTES,
    Nonce, PrecomputedKey,
    gen_nonce
};

use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::utils::memzero;
use ::toxcore::crypto_core;

/// Length in bytes of the salt used to encrypt/decrypt data.
pub use sodiumoxide::crypto::pwhash::SALTBYTES as SALT_LENGTH;
/// Length in bytes of the key used to encrypt/decrypt data.
pub use sodiumoxide::crypto::box_::PRECOMPUTEDKEYBYTES as KEY_LENGTH;


/// Length (in bytes) of [`MAGIC_NUMBER`](./constant.MAGIC_NUMBER.html).
pub const MAGIC_LENGTH: usize = 8;
/** Bytes used to verify whether given data has been encrypted using **TES**.

    Located at the beginning of the encrypted data.
*/
pub const MAGIC_NUMBER: &'static [u8; MAGIC_LENGTH] = b"toxEsave";
/** Minimal size in bytes of an encrypted file.

I.e. the amount of bytes that data will "gain" after encryption.
*/
pub const EXTRA_LENGTH: usize = MAGIC_LENGTH + SALT_LENGTH + NONCEBYTES + MACBYTES;

/** Key and `Salt` that are used to encrypt/decrypt data.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PassKey {
    /// Salt is saved along with encrypted data and used to decrypt it.
    pub salt: Salt,
    /// Key used to encrypt/decrypt data. **DO NOT SAVE**.
    pub key: PrecomputedKey
}

impl PassKey {
    /**
    Create a new `PassKey` with a random `Salt`.

    **Note that `passphrase` memory is not being zeroed after it has been
    used**. Code that provides `passphrase` should take care of zeroing that
    memory.

    Can fail for the same reasons as [`PassKey::with_salt()`]
    (./struct.PassKey.html#method.with_salt), that is:

      * passphrase is empty
      * deriving key failed (can happen due to OOM)

    E.g.

    ```
    use self::tox::toxencryptsave::*;

    // fails with an empty passphrase
    assert_eq!(Err(KeyDerivationError::Null), PassKey::new(&[]));
    ```
    */
    pub fn new(passphrase: &[u8]) -> Result<PassKey, KeyDerivationError> {
        PassKey::with_salt(passphrase, gen_salt())
    }

    /** Create a new `PassKey` with provided `Salt`, rather than using a random
        one.

    **Note that `passphrase` memory is not being zeroed after it has been
    used**. Code that provides `passphrase` should take care of zeroing that
    memory.

    ## Fails when:

      * passphrase is empty
      * deriving key failed (can happen due to OOM)

    E.g.

    ```
    extern crate sodiumoxide;
    extern crate tox;

    # fn main() {
    use sodiumoxide::crypto::pwhash::gen_salt;
    use tox::toxencryptsave::*;

    assert_eq!(Err(KeyDerivationError::Null),
                PassKey::with_salt(&[], gen_salt()));
    # }
    ```
    */
    pub fn with_salt(passphrase: &[u8], salt: Salt) -> Result<PassKey, KeyDerivationError> {
        if passphrase.is_empty() { return Err(KeyDerivationError::Null) };

        let sha256::Digest(passhash) = sha256::hash(passphrase);
        let OpsLimit(ops) = OPSLIMIT_INTERACTIVE;
        let mut key = [0; KEY_LENGTH];

        let maybe_key = PrecomputedKey::from_slice(try!(
            derive_key(
                &mut key,
                &passhash,
                &salt,
                OpsLimit(ops * 2),
                MEMLIMIT_INTERACTIVE
            ).or(Err(KeyDerivationError::Failed))
        ));

        memzero(&mut key);

        Ok(PassKey {
            salt: salt,
            key: try!(maybe_key.ok_or(KeyDerivationError::Failed))
        })
    }

    /**
    Encrypts provided `data` with `self` `PassKey`.

    Encrypted data is bigger than supplied data by [`EXTRA_LENGTH`]
    (./constant.EXTRA_LENGTH.html).

    ## Fails when:

      * provided `data` is empty

    E.g.

    ```
    use tox::toxencryptsave::*;

                              // ↓ don't
    let passkey = PassKey::new(&[0]).expect("Failed to unwrap PassKey!");

    assert_eq!(Err(EncryptionError::Null), passkey.encrypt(&[]));
    ```
    */
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if data.is_empty() { return Err(EncryptionError::Null) };

        let mut output = Vec::with_capacity(EXTRA_LENGTH + data.len());
        let nonce = gen_nonce();

        output.extend_from_slice(MAGIC_NUMBER);
        output.extend_from_slice(&self.salt.0);
        output.extend_from_slice(&nonce.0);
        output.append(&mut crypto_core::encrypt_data_symmetric(
            &self.key,
            &nonce,
            data
        ));

        Ok(output)
    }

    /**
    Decrypts provided `data` with `self` `PassKey`.

    Decrypted data is smaller by [`EXTRA_LENGTH`](./constant.EXTRA_LENGTH.html)
    than encrypted data.

    ## Fails when:

      * provided `data` is empty
      * size of provided `data` is less than `EXTRA_LENGTH`
      * format of provided `data` is wrong
      * decrypting `data` fails
        - could be due to OOM or by providing bytes that aren't encrypted after
          encrypted part

    E.g.

    ```
    use self::tox::toxencryptsave::*;

                              // ↓ don't
    let passkey = PassKey::new(&[0]).expect("Failed to unwrap PassKey!");

    // empty data
    assert_eq!(Err(DecryptionError::Null), passkey.decrypt(&[]));
    ```
    */
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

/// Check if given piece of data appears to be encrypted by **TES**.
#[inline]
pub fn is_encrypted(data: &[u8]) -> bool {
    data.starts_with(MAGIC_NUMBER)
}

/**
Try to encrypt given data with provided passphrase.

**Note that `passphrase` memory is not being zeroed after it has been
used**. Code that provides `passphrase` should take care of zeroing that
memory.

# Fails when:

  * `data` is empty
  * `passphrase` is empty
  * deriving key failed (can happen due to OOM)

E.g.

```
use self::tox::toxencryptsave::*;

// empty data
assert_eq!(Err(EncryptionError::Null), pass_encrypt(&[], &[0]));

// empty passphrase
assert_eq!(Err(EncryptionError::KeyDerivation(KeyDerivationError::Null)),
           pass_encrypt(&[0], &[]));
```
*/
pub fn pass_encrypt(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    try!(PassKey::new(passphrase)).encrypt(data)
}

/**
Try to decrypt given **TES** data with provided passphrase.

**Note that `passphrase` memory is not being zeroed after it has been
used**. Code that provides `passphrase` should take care of zeroing that
memory.

Decrypted data is smaller by [`EXTRA_LENGTH`](./constant.EXTRA_LENGTH.html)
than encrypted data.

## Fails when:

  * provided `data` is empty
  * size of provided `data` is less than `EXTRA_LENGTH`
  * format of provided `data` is wrong
  * decrypting `data` fails
    - could be due to OOM or by providing bytes that aren't encrypted after
      encrypted part
  * `passphrase` is empty

```
use self::tox::toxencryptsave::*;

// with an empty data
assert_eq!(Err(DecryptionError::Null), pass_decrypt(&[], &[0]));

// when there's not enough data to decrypt
assert_eq!(Err(DecryptionError::InvalidLength), pass_decrypt(MAGIC_NUMBER, &[0]));

let encrypted = pass_encrypt(&[0, 0], &[0]).expect("Failed to pass_encrypt!");

// when passphrase is empty
assert_eq!(Err(DecryptionError::KeyDerivation(KeyDerivationError::Null)),
           pass_decrypt(&encrypted, &[]));

// when data format is wrong
for pos in 0..MAGIC_LENGTH {
    let mut enc = encrypted.clone();
    if enc[pos] == 0 { enc[pos] = 1; } else { enc[pos] = 0; }
    assert_eq!(Err(DecryptionError::BadFormat), pass_decrypt(&enc, &[0]));
}

{ // there are more or less bytes than the encrypted ones
    let mut enc = encrypted.clone();
    enc.push(0);
    assert_eq!(Err(DecryptionError::Failed), pass_decrypt(&enc, &[0]));

    // less
    drop((enc.pop(), enc.pop()));
    assert_eq!(Err(DecryptionError::Failed), pass_decrypt(&enc, &[0]));
}
```
*/
pub fn pass_decrypt(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, DecryptionError> {
    if data.is_empty() { return Err(DecryptionError::Null) }
    if data.len() <= EXTRA_LENGTH { return Err(DecryptionError::InvalidLength) }
    if !is_encrypted(data) { return Err(DecryptionError::BadFormat) }

    let salt = try!(get_salt(data).ok_or(KeyDerivationError::Failed));
    try!(PassKey::with_salt(passphrase, salt)).decrypt(data)
}

/** Get `Salt` from data encrypted with **TES**.

## Fails when:

  * `data` doesn't appear to be a **TES**
  * number of bytes in `data` is not enough

E.g.

```
use self::tox::toxencryptsave::*;

assert_eq!(None, get_salt(&[]));
```
*/
pub fn get_salt(data: &[u8]) -> Option<Salt> {
    if is_encrypted(data)
        && data.len() >= MAGIC_LENGTH + SALT_LENGTH
    {
        Salt::from_slice(&data[MAGIC_LENGTH..MAGIC_LENGTH+SALT_LENGTH])
    } else {
        None
    }
}

/// Deriving secret key for [`PassKey`](./struct.PassKey.html).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyDerivationError {
    /// Provided passphrase is empty.
    Null,
    /// Failed to derive key, most likely due to OOM.
    // TODO: ↑ link to the used sodium memory constant * 2
    Failed
}

/// Error encrypting data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncryptionError {
    /// Data provided for encryption is empty.
    Null,
    /// Failed to derive key – [`KeyDerivationError`]
    /// (./enum.KeyDerivationError.html)
    KeyDerivation(KeyDerivationError),
}

impl From<KeyDerivationError> for EncryptionError {
    fn from(err: KeyDerivationError) -> EncryptionError {
        EncryptionError::KeyDerivation(err)
    }
}

/// Error when trying to decrypt data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecryptionError {
    /// Data to be decrypted is empty.
    Null,
    /// There's not enough data to decrypt.
    InvalidLength,
    /// Provided data has invalid format, incompatible with **TES**.
    BadFormat,
    /// Deriving key failed.
    KeyDerivation(KeyDerivationError),
    /**
    Failure due to encrypted data being invalid.

    Can happen when:

     * data is invalid
       - note that it can happen due to bitrot – i.e. even a single byte
         getting corrupted can render data ~impossible to decrypt
     * not all encrypted bytes were provided
     * some bytes that aren't encrypted were provided after encrypted bytes
    */
    Failed
}

impl From<KeyDerivationError> for DecryptionError {
    fn from(err: KeyDerivationError) -> DecryptionError {
        DecryptionError::KeyDerivation(err)
    }
}
