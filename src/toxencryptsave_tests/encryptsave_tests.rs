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


use super::quickcheck::{
    Arbitrary,
    Gen,
    quickcheck,
    TestResult,
};

use sodiumoxide::crypto::pwhash::gen_salt;

use toxencryptsave::*;


// PassKey::

impl Arbitrary for PassKey {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let up_to_range = g.gen_range(2, 1000000);
        let mut passwd = Vec::with_capacity(up_to_range);
        for _ in 1..up_to_range {
            passwd.push(g.gen());
        }
        PassKey::new(&passwd).expect("Failed to unwrap PassKey!")
    }
}

// PassKey::new()

#[test]
fn pass_key_new_test() {
    fn with_pw(passwd: Vec<u8>) -> TestResult {
        // empty password is already tested in docs test
        if passwd.is_empty() { return TestResult::discard() }

        let pk = PassKey::new(&passwd).expect("Failed to unwrap PassKey!");

        assert!(pk.salt.0.as_ref() != passwd.as_slice());
        assert!(pk.salt.0.as_ref() != [0; SALT_LENGTH].as_ref());
        assert!(pk.key.0.as_ref() != passwd.as_slice());
        assert!(pk.key.0 != [0; KEY_LENGTH]);
        TestResult::passed()
    }
    quickcheck(with_pw as fn(Vec<u8>) -> TestResult);
}

// PassKey::with_salt()

#[test]
fn pass_key_with_salt_test() {
    fn with_pw(passwd: Vec<u8>) -> TestResult {
        // test for an empty passphrase is done in docs test
        if passwd.is_empty() { return TestResult::discard() }

        let salt = gen_salt();
        let pk = PassKey::with_salt(&passwd, salt.clone())
                    .expect("Failed to unwrap PassKey!");

        assert_eq!(&pk.salt, &salt);
        assert!(pk.key.0.as_ref() != passwd.as_slice());
        assert!(pk.key.0 != [0; KEY_LENGTH]);
        TestResult::passed()
    }
    quickcheck(with_pw as fn(Vec<u8>) -> TestResult);
}

// PassKey::encrypt()

#[test]
fn pass_key_encrypt_test() {
    fn with_data(plain: Vec<u8>, passk: PassKey) -> TestResult {
        // test for empty data is done in docs test
        if plain.is_empty() { return TestResult::discard() }

        let encrypted = passk.encrypt(&plain).expect("Encrypting failed!");
        assert_eq!(plain.len() + EXTRA_LENGTH, encrypted.len());
        assert!(plain.as_slice() != &encrypted[EXTRA_LENGTH..]);
        assert_eq!(plain, passk.decrypt(&encrypted).expect("Decrypting failed"));
        TestResult::passed()
    }
    quickcheck(with_data as fn(Vec<u8>, PassKey) -> TestResult);
}


#[test]
fn encrypt_test() {
    use sodiumoxide::randombytes::randombytes;

    let plaintext = randombytes(16);
    let passphrase = randombytes(16);
    let ciphertext = pass_encrypt(&plaintext, &passphrase).unwrap();
    assert!(plaintext != ciphertext);
    assert_eq!(
        pass_decrypt(&ciphertext,&passphrase).unwrap(),
        plaintext
    );
}

#[test]
fn decrypt_test() {
    let passphrase = b"encryptsave";
    let plaintext = b"Hello world.\n";
    let ciphertext = include_bytes!("ciphertext");

    assert_eq!(
        pass_decrypt(ciphertext, passphrase).unwrap(),
        plaintext
    );
}

#[test]
fn is_encrypted_test() {
    assert!(is_encrypted(include_bytes!("ciphertext")));
    assert!(!is_encrypted(b"Hello world.\n"));
}

#[test]
fn get_salt_test() {
    assert_eq!(
        get_salt(include_bytes!("ciphertext")).unwrap().0,
        [208, 154, 232, 3, 210, 251, 220, 103, 10, 139, 111, 145, 165, 238, 157, 170, 62, 76, 91, 231, 46, 254, 215, 174, 12, 195, 128, 5, 171, 229, 237, 60]
    );
}
