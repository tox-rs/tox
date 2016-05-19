use sodiumoxide::crypto::pwhash::{
    SALTBYTES, MEMLIMIT_INTERACTIVE, OPSLIMIT_INTERACTIVE,
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

const MAGIC_LENGTH: usize = 8;
const MAGIC_NUMBER: &'static [u8; MAGIC_LENGTH] = b"toxEsave";
const SALT_LENGTH: usize = SALTBYTES;
const KEY_LENGTH: usize = PRECOMPUTEDKEYBYTES;
const EXTRA_LENGTH: usize = MAGIC_LENGTH + SALT_LENGTH + NONCEBYTES + MACBYTES;


#[derive(Clone, Debug)]
pub struct PassKey {
    pub salt: Salt,
    pub key: PrecomputedKey
}

impl PassKey {
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

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Encryption> {
        if data.is_empty() { return Err(Encryption::Null) };

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

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Decryption> {
        if data.is_empty() { return Err(Decryption::Null) };
        if data.len() <= EXTRA_LENGTH { return Err(Decryption::InvalidLength) };
        if !is_encrypted(data) { return Err(Decryption::BadFormat) };

        let nonce = try!(Nonce::from_slice(&data[
            MAGIC_LENGTH+SALT_LENGTH..MAGIC_LENGTH+SALT_LENGTH+NONCEBYTES
        ]).ok_or(Decryption::BadFormat));

        let output = try!(crypto_core::decrypt_data_symmetric(
            &self.key,
            &nonce,
            &data[MAGIC_LENGTH+SALT_LENGTH+NONCEBYTES..]
        ).or(Err(Decryption::Failed)));

        Ok(output)
    }
}

#[inline]
pub fn is_encrypted(data: &[u8]) -> bool {
    data.starts_with(MAGIC_NUMBER)
}

pub fn pass_encrypt(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, Encryption> {
    try!(PassKey::new(passphrase)).encrypt(data)
}

pub fn pass_decrypt(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, Decryption> {
    let salt = try!(get_salt(data).ok_or(KeyDerivationError::Failed));
    try!(PassKey::with_salt(passphrase, salt)).decrypt(data)
}

pub fn get_salt(data: &[u8]) -> Option<Salt> {
    if is_encrypted(data)
        && data.len() >= MAGIC_LENGTH + SALT_LENGTH
    {
        let mut salt = [0; SALT_LENGTH];
        salt.clone_from_slice(&data[MAGIC_LENGTH..MAGIC_LENGTH+SALT_LENGTH]);
        Some(Salt(salt))
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
pub enum Encryption {
    Null,
    KeyDerivation(KeyDerivationError),
}

impl From<KeyDerivationError> for Encryption {
    fn from(err: KeyDerivationError) -> Encryption {
        Encryption::KeyDerivation(err)
    }
}

#[derive(Clone, Debug)]
pub enum Decryption {
    Null,
    InvalidLength,
    BadFormat,
    KeyDerivation(KeyDerivationError),
    Failed
}

impl From<KeyDerivationError> for Decryption {
    fn from(err: KeyDerivationError) -> Decryption {
        Decryption::KeyDerivation(err)
    }
}
