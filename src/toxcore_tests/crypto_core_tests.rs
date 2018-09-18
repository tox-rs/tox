//! Tests for `crypto_core` module.

use std::thread;

use toxcore::binary_io::*;
use toxcore::crypto_core::*;


// crypto_init()

#[test]
// test whether crypto init behaves well when one tries to run it in parallel.
// Its code should **not** be ran in parallel.
fn crypto_init_test() {
    // apparently hundreds of threads can cause OOM on appveyor
    #[cfg(not(target_os = "windows"))]
    let num = 255;
    #[cfg(target_os = "windows")]
    let num = 32;

    thread::spawn(move || {
        for _ in 0..num {
            thread::spawn(move || {
                assert_eq!(true, crypto_init());
                // second run, value should be the same
                assert_eq!(true, crypto_init());
            });
        }
    });
}


#[test]
// test comparing empty keys
// testing since it would appear that sodiumoxide doesn't do testing for it
fn public_key_cmp_test_empty() {
    let alice_publickey = PublicKey([0; PUBLICKEYBYTES]);
    let bob_publickey = PublicKey([0; PUBLICKEYBYTES]);

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
fn random_usize_test() {
    let a = random_usize();
    let b = random_usize();
    assert!(a != 0);
    assert!(b != 0);
    // The probability to fail equals 2.9*10^-39
    assert!(a != b);
}

#[test]
fn public_key_valid_test() {
    let (pk, _) = gen_keypair();
    assert!(public_key_valid(&pk));

    assert!(public_key_valid(&PublicKey([0; PUBLICKEYBYTES]))); // 0
    assert!(public_key_valid(&PublicKey([0b01_11_11_11; PUBLICKEYBYTES]))); // 127
    assert!(!public_key_valid(&PublicKey([0b10_00_00_00; PUBLICKEYBYTES]))); // 128
    assert!(!public_key_valid(&PublicKey([0b11_11_11_11; PUBLICKEYBYTES]))); // 255
}


#[test]
// test uses "bare" functions provided by `sodiumoxide`, with an exception
// of the tested function
fn encrypt_precompute_test() {
    let (alice_pk, alice_sk) = gen_keypair();
    let (bob_pk, bob_sk) = gen_keypair();

    let alice_plaintext = b"Hi, Bob.";
    let alice_precomputed_key = encrypt_precompute(&bob_pk, &alice_sk);

    let nonce = gen_nonce();

    let ciphertext = seal_precomputed(alice_plaintext, &nonce, &alice_precomputed_key);

    let bob_precomputed_key = encrypt_precompute(&alice_pk, &bob_sk);
    let bob_plaintext = open_precomputed(&ciphertext, &nonce, &bob_precomputed_key).unwrap();

    assert_eq!(alice_plaintext, &bob_plaintext[..]);
}


#[test]
// test uses "bare" functions provided by `sodiumoxide`, with an "exception"
// of the tested function
pub fn encrypt_data_symmetric_test() {
    let (alice_pk, alice_sk) = gen_keypair();
    let (bob_pk, bob_sk) = gen_keypair();

    let alice_plain = b"Hi, Bob.";

    let precomputed_key = precompute(&bob_pk, &alice_sk);
    let nonce = gen_nonce();

    let ciphertext = encrypt_data_symmetric(&precomputed_key, &nonce, alice_plain);

    let bob_plain = open(&ciphertext, &nonce, &alice_pk, &bob_sk).unwrap();

    assert_eq!(alice_plain, &bob_plain[..]);
}

/* TODO: test for pubkey/skey/nonce being all `0`s, which would produce
   ciphertext that should be compared to already known result of this
   computation. This way it would be ensured that cipher algorithm is
   actually working as it should.
   There should be also some additional variations of this test, with different
   pkey/skey/nonce values that would produce known ciphertext.

   Also, similar test for decrypting.
*/


#[test]
// test uses "bare" functions provided by `sodiumoxide`, with an exception
// of the tested function
fn decrypt_data_symmetric_test() {
    let (alice_pk, alice_sk) = gen_keypair();
    let (bob_pk, bob_sk) = gen_keypair();

    let alice_plain = b"Hi, Bob.";

    let precomputed_key = precompute(&alice_pk, &bob_sk);
    let nonce = gen_nonce();

    let ciphertext = seal(alice_plain, &nonce, &bob_pk, &alice_sk);

    let bob_plain = decrypt_data_symmetric(&precomputed_key, &nonce, &ciphertext).unwrap();

    assert_eq!(alice_plain, &bob_plain[..]);
}


// increment_nonce()

#[test]
fn increment_nonce_test_zero_plus_one() {
    let cmp_nonce = Nonce([0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 1]);

    let mut nonce = Nonce([0; NONCEBYTES]);
    increment_nonce(&mut nonce);
    assert_eq!(nonce, cmp_nonce);
}

#[test]
fn increment_nonce_test_0xf_plus_one() {
    let cmp_nonce = Nonce([0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0x10]);

    let mut nonce = Nonce([0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0xf]);
    increment_nonce(&mut nonce);
    assert_eq!(nonce, cmp_nonce);
}

#[test]
fn increment_nonce_test_0xff_plus_one() {
    let cmp_nonce = Nonce([0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 1, 0]);

    let mut nonce = Nonce([0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0xff]);
    increment_nonce(&mut nonce);
    assert_eq!(nonce, cmp_nonce);
}

#[test]
fn increment_nonce_test_0xff_max() {
    let cmp_nonce = Nonce([0; NONCEBYTES]);
    let mut nonce = Nonce([0xff; NONCEBYTES]);
    increment_nonce(&mut nonce);
    assert_eq!(cmp_nonce, nonce);
}

#[test]
fn increment_nonce_test_random() {
    let mut nonce = gen_nonce();
    let cmp_nonce = nonce;
    increment_nonce(&mut nonce);
    assert!(nonce != cmp_nonce);
}

// increment_nonce_number()

#[test]
fn increment_nonce_number_test_zero_plus_0xff00() {
    let cmp_nonce = Nonce([0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0xff, 0]);
    let mut nonce = Nonce([0; NONCEBYTES]);

    increment_nonce_number(&mut nonce, 0xff00);
    assert_eq!(nonce, cmp_nonce);
}

#[test]
fn increment_nonce_number_test_0xff0000_plus_0x011000() {
    let cmp_nonce = Nonce([0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 1, 0, 0x10, 0]);

    let mut nonce = Nonce([0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0xff, 0, 0]);

    increment_nonce_number(&mut nonce, 0x01_10_00);
    assert_eq!(nonce, cmp_nonce);
}


// PublicKey::parse_bytes()

#[test]
fn public_key_parse_bytes_test() {
    let bytes = [42; PUBLICKEYBYTES];
    let (_rest, PublicKey(pk_bytes)) = PublicKey::from_bytes(&bytes).unwrap();

    assert_eq!(pk_bytes, &bytes as &[u8]);
}


// SecretKey::parse_bytes()

#[test]
fn secret_key_parse_bytes_test() {
    let bytes = [42; SECRETKEYBYTES];
    let (_rest, SecretKey(sk_bytes)) = SecretKey::from_bytes(&bytes).unwrap();

    assert_eq!(sk_bytes, &bytes as &[u8]);
}

// Nonce::parse_bytes

#[test]
fn nonce_parse_bytes_test() {
    let bytes = [42; NONCEBYTES];
    let (_rest, Nonce(nonce_bytes)) = Nonce::from_bytes(&bytes).unwrap();

    assert_eq!(nonce_bytes, &bytes as &[u8]);
}
