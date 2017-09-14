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


use super::quickcheck::*;

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

// PassKey::encrypt()

#[test]
fn pass_key_encrypt_test() {
    fn with_data(plain: Vec<u8>, passk: PassKey) -> TestResult {
        // test for empty data is done in docs test
        // TODO: test can fail with small amounts of data – change it to
        //       require bigger minimal amount of data, and note in the
        //       encryption docs that encrypted data is guaranteed to differ
        //       from plaintext only for amounts of data bigger than just a few
        //       bytes
        if plain.is_empty() { return TestResult::discard() }

        let encrypted = passk.encrypt(&plain).expect("Encrypting failed!");
        assert_eq!(plain.len() + EXTRA_LENGTH, encrypted.len());
        assert!(plain.as_slice() != &encrypted[EXTRA_LENGTH..]);
        assert_eq!(plain, passk.decrypt(&encrypted).expect("Decrypting failed"));
        TestResult::passed()
    }
    QuickCheck::new().max_tests(20).quickcheck(with_data as fn(Vec<u8>, PassKey) -> TestResult);
}

// PassKey::decrypt()

#[test]
fn pass_key_decrypt_test() {
    fn with_data(plain: Vec<u8>, passk: PassKey) -> TestResult {
        // need some valid data for encryption to test with
        // + empty encrypted data is tested in docs test
        if plain.is_empty() { return TestResult::discard() }

        let encrypted = passk.encrypt(&plain).expect("Encrypting failed!");

        // decrypting should just work™
        assert_eq!(&plain, &passk.decrypt(&encrypted).expect("Decrypting failed!"));

        // check if fails if one of `MAGIC_NUMBER` bytes is wrong
        for pos in 0..MAGIC_LENGTH {
            let mut ec = encrypted.clone();
            if ec[pos] == 0 { ec[pos] = 1; } else { ec[pos] = 0; }
            assert_eq!(Err(DecryptionError::BadFormat), passk.decrypt(&ec));
        }

        // check if fails if a data byte is wrong
        for pos in EXTRA_LENGTH..encrypted.len() {
            let mut ec = encrypted.clone();
            if ec[pos] == 0 { ec[pos] = 1; } else { ec[pos] = 0; }
            assert_eq!(Err(DecryptionError::Failed), passk.decrypt(&ec));
        }

        // fails if not enough bytes?
        for n in 1..EXTRA_LENGTH {
            assert_eq!(Err(DecryptionError::InvalidLength),
                    passk.decrypt(&encrypted[..EXTRA_LENGTH - n]));
        }

        TestResult::passed()
    }
    QuickCheck::new().max_tests(20).quickcheck(with_data as fn(Vec<u8>, PassKey) -> TestResult);
}


// is_encrypted()

#[test]
fn is_encrypted_test() {
    fn with_bytes(bytes: Vec<u8>) {
        assert_eq!(false, is_encrypted(&bytes));
    }
    quickcheck(with_bytes as fn(Vec<u8>));

    with_bytes(b"Hello world.\n".to_vec());
    assert!(is_encrypted(MAGIC_NUMBER));
    assert!(is_encrypted(include_bytes!("ciphertext")));
}


// pass_encrypt()

#[test]
fn pass_encrypt_test() {
    fn with_data_pass(data: Vec<u8>, pass: Vec<u8>) -> TestResult {
        // tested for empty data / passphrase in docs test
        if data.is_empty() || pass.is_empty() {
            return TestResult::discard()
        }

        let encrypted = pass_encrypt(&data, &pass)
            .expect("Failed to unwrap pass_encrypt!");
        assert!(is_encrypted(&encrypted));

        assert_eq!(data.len() + EXTRA_LENGTH, encrypted.len());
        assert_eq!(data, pass_decrypt(&encrypted, &pass)
                            .expect("Failed to pass_decrypt!"));

        let encrypted2 = pass_encrypt(&data, &pass)
            .expect("Failed to unwrap pass_encrypt 2!");
        assert!(encrypted != encrypted2);

        TestResult::passed()
    }
    QuickCheck::new().max_tests(20).quickcheck(with_data_pass as
        fn(Vec<u8>, Vec<u8>) -> TestResult);

    {
        use sodiumoxide::randombytes::randombytes;

        let plaintext = randombytes(16);
        let passphrase = randombytes(16);
        with_data_pass(plaintext, passphrase);
    }
}


// pass_decrypt()

#[test]
fn pass_decrypt_test() {
    let passphrase = b"encryptsave";
    let plaintext = b"Hello world.\n";
    let ciphertext = include_bytes!("ciphertext");

    assert_eq!(
        pass_decrypt(ciphertext, passphrase).unwrap(),
        plaintext
    );
}

#[test]
fn get_salt_test() {
    fn with_bytes(bytes: Vec<u8>) {
        let mut res = Vec::with_capacity(MAGIC_LENGTH + bytes.len());
        res.extend_from_slice(MAGIC_NUMBER);
        res.extend_from_slice(&bytes);

        if bytes.len() < SALT_LENGTH {
            assert_eq!(None, get_salt(&res));
            return
        }

        // check if will work with any bytes
        assert_eq!(&bytes[..SALT_LENGTH], get_salt(&res)
            .expect("Failed to get Salt!").0);

        // check if will fail with any malformed magic byte
        for pos in 0..MAGIC_LENGTH {
            let mut v = res.clone();
            if v[pos] == 0 { v[pos] = 1; } else { v[pos] = 0; }
            assert_eq!(None, get_salt(&v));
        }
    }
    QuickCheck::new().max_tests(20).quickcheck(with_bytes as fn(Vec<u8>));

    assert_eq!(
        get_salt(include_bytes!("ciphertext")).unwrap().0,
        [208, 154, 232, 3, 210, 251, 220, 103, 10, 139, 111, 145, 165, 238, 157, 170, 62, 76, 91, 231, 46, 254, 215, 174, 12, 195, 128, 5, 171, 229, 237, 60]
    );
}
