/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2016 Roman <humbug@deeptown.org>
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

//! Tests for `crypto_core` module.

use std::str::FromStr;

use toxcore::crypto_core::*;

use quickcheck::quickcheck;


#[test]
// test comparing empty keys
// testing since it would appear that sodiumoxide doesn't do testing for it
fn public_key_cmp_test_empty() {
    let alice_publickey = PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap();
    let bob_publickey = PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap();

    assert_eq!(alice_publickey.eq(&bob_publickey), true);
    assert_eq!(bob_publickey.eq(&alice_publickey), true);
}

#[test]
// test comparing random public keys
// testing since it would appear that sodiumoxide doesn't do testing for it
fn public_key_cmp_test_random() {
    let (alice_publickey, _alice_secretkey) = gen_keypair();
    let (bob_publickey, _bob_secretkey) = gen_keypair();

    assert_eq!(alice_publickey.eq(&bob_publickey), false);
    assert_eq!(bob_publickey.eq(&alice_publickey), false);

    assert_eq!(alice_publickey.eq(&alice_publickey), true);
    assert_eq!(bob_publickey.eq(&bob_publickey), true);
}


#[test]
fn random_u32_test() {
    let a = random_u32();
    let b = random_u32();
    assert!(a != 0);
    assert!(b != 0);
    // The probability to fail equals 5.4*10^-20
    assert!(a != b);
}


#[test]
fn random_u64_test() {
    let a = random_u64();
    let b = random_u64();
    assert!(a != 0);
    assert!(b != 0);
    // The probability to fail equals 2.9*10^-39
    assert!(a != b);
}


#[test]
fn public_key_valid_test() {
    let (pk, _) = gen_keypair();
    assert_eq!(true, public_key_valid(&pk));

    assert_eq!(true, public_key_valid(&(PublicKey::from_slice(&[0b00000000; PUBLICKEYBYTES]).unwrap()))); // 0
    assert_eq!(true, public_key_valid(&(PublicKey::from_slice(&[0b01111111; PUBLICKEYBYTES]).unwrap()))); // 127
    assert_eq!(false, public_key_valid(&(PublicKey::from_slice(&[0b10000000; PUBLICKEYBYTES]).unwrap()))); // 128
    assert_eq!(false, public_key_valid(&(PublicKey::from_slice(&[0b11111111; PUBLICKEYBYTES]).unwrap()))); // 255

    fn pk_from_u8(num: u8) {
        let pk = PublicKey::from_slice(&[num; PUBLICKEYBYTES]).unwrap();

        if num < 128 {
            assert_eq!(true, public_key_valid(&pk));
        } else {
            assert_eq!(false, public_key_valid(&pk));
        }
    }
    quickcheck(pk_from_u8 as fn(u8));
}


#[test]
// test uses "bare" functions provided by `sodiumoxide`, with an exception
// of the tested function
fn encrypt_precompute_test() {
    fn encrypt_decrypt_msg(msg: String) {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();

        let alice_plaintext = &msg.into_bytes()[..];
        let alice_precomputed_key = encrypt_precompute(&bob_pk, &alice_sk);

        let nonce = gen_nonce();

        let ciphertext = seal_precomputed(alice_plaintext, &nonce, &alice_precomputed_key);

        let bob_precomputed_key = encrypt_precompute(&alice_pk, &bob_sk);
        let bob_plaintext = open_precomputed(&ciphertext, &nonce, &bob_precomputed_key).unwrap();

        assert!(alice_plaintext == &bob_plaintext[..]);
    }
    encrypt_decrypt_msg(String::from_str("Hi, Bob.").unwrap());
    quickcheck(encrypt_decrypt_msg as fn(String));
}


#[test]
// test uses "bare" functions provided by `sodiumoxide`, with an "exception"
// of the tested function
pub fn encrypt_data_symmetric_test() {
    fn encrypt_decrypt_msg(msg: String) {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();

        let alice_plain = &msg.into_bytes()[..];

        let precomputed_key = precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();

        let ciphertext = encrypt_data_symmetric(&precomputed_key, &nonce, alice_plain);

        let bob_plain = open(&ciphertext, &nonce, &alice_pk, &bob_sk).unwrap();

        assert!(alice_plain == &bob_plain[..]);
    }
    encrypt_decrypt_msg(String::from_str("Hi, Bob.").unwrap());
    quickcheck(encrypt_decrypt_msg as fn(String));
}

// TODO: test for pubkey/skey/nonce being all `0`s, which would produce
// ciphertext that should be compared to already known result of this
// computation. This way it would be ensured that cipher algorithm is
// actually working as it should.
// There should be also some additional variations of this test, with different
// pkey/skey/nonce values that would produce known ciphertext.
//
// Also, similar test for decrypting.


#[test]
// test uses "bare" functions provided by `sodiumoxide`, with an exception
// of the tested function
fn decrypt_data_symmetric_test() {
    fn encrypt_decrypt_msg(msg: String) {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();

        let alice_plain = &msg.into_bytes()[..];

        let precomputed_key = precompute(&alice_pk, &bob_sk);
        let nonce = gen_nonce();

        let ciphertext = seal(alice_plain, &nonce, &bob_pk, &alice_sk);

        let bob_plain = decrypt_data_symmetric(&precomputed_key, &nonce, &ciphertext).unwrap();

        assert!(alice_plain == &bob_plain[..]);
    }
    encrypt_decrypt_msg(String::from_str("Hi, Bob.").unwrap());
    quickcheck(encrypt_decrypt_msg as fn(String));
}


#[test]
fn increment_nonce_test_zero_plus_one() {
    let cmp_nonce = Nonce::from_slice(&[1, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0]).unwrap();

    let mut nonce = Nonce::from_slice(&[0; NONCEBYTES]).unwrap();
    increment_nonce(&mut nonce);
    assert!(nonce == cmp_nonce);
}

#[test]
fn increment_nonce_test_0xf_plus_one() {
    let cmp_nonce = Nonce::from_slice(&[0x10, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0]).unwrap();

    let mut nonce = Nonce::from_slice(&[0xf, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    increment_nonce(&mut nonce);
    assert!(nonce == cmp_nonce);
}

#[test]
fn increment_nonce_test_0xff_plus_one() {
    let cmp_nonce = Nonce::from_slice(&[0, 1, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0]).unwrap();

    let mut nonce = Nonce::from_slice(&[0xff, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    increment_nonce(&mut nonce);
    assert!(nonce == cmp_nonce);
}

#[test]
fn increment_nonce_test_random() {
    let mut nonce = gen_nonce();
    let cmp_nonce = nonce.clone();
    increment_nonce(&mut nonce);
    assert!(nonce != cmp_nonce);
}


#[test]
fn increment_nonce_number_test_zero_plus_0xff00() {
    let cmp_nonce = Nonce::from_slice(&[0, 0xff, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    let mut nonce = Nonce::from_slice(&[0; NONCEBYTES]).unwrap();

    increment_nonce_number(&mut nonce, 0xff00);
    assert!(nonce == cmp_nonce);
}

#[test]
fn increment_nonce_number_test_0xff0000_plus_0x011000() {
    let cmp_nonce = Nonce::from_slice(&[0, 0x10, 0, 1, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0]).unwrap();

    let mut nonce = Nonce::from_slice(&[0, 0, 0xff, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0]).unwrap();

    increment_nonce_number(&mut nonce, 0x11000);
    assert!(nonce == cmp_nonce);
}
