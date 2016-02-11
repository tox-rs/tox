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

use quickcheck::quickcheck;

use std::str::FromStr;

use toxcore::crypto_core::*;
use toxcore::network::NetPacket;


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


#[test]
fn create_request_test() {
    let (alice_pk, alice_sk) = gen_keypair();
    let (bob_pk, bob_sk) = gen_keypair();

    let alice_msg = b"Hi, bub.";

    let packet_friend1 = create_request(&alice_pk, &alice_sk, &bob_pk,
                                        alice_msg, CryptoPacket::FriendReq
                                       ).unwrap();
    let packet_friend2 = create_request(&alice_pk, &alice_sk, &bob_pk,
                                        alice_msg, CryptoPacket::FriendReq
                                       ).unwrap();

    let i2pk: usize = 1 + PUBLICKEYBYTES * 2;
    let i2pkn: usize = i2pk + NONCEBYTES;

    // should differ by nonce, and thus also ciphertext
    assert!(packet_friend1 != packet_friend2);
    // packet type (1 byte), 2 * PK (64 bytes)
    assert!(&packet_friend1[..i2pk] == &packet_friend2[..i2pk]);
    // nonce (24 bytes)
    assert!(&packet_friend1[i2pk..i2pkn] != &packet_friend2[i2pk..i2pkn]);
    // encrypted data (1 byte packet id + ..)
    assert!(&packet_friend1[i2pkn..] != &packet_friend2[i2pkn..]);


    let packet_ping1 = create_request(&alice_pk, &alice_sk, &bob_pk,
                                      alice_msg, CryptoPacket::NAT_Ping
                                     ).unwrap();
    let packet_ping2 = create_request(&alice_pk, &alice_sk, &bob_pk,
                                      alice_msg, CryptoPacket::NAT_Ping
                                     ).unwrap();
    // should differ by nonce, and thus also ciphertext
    assert!(packet_ping1 != packet_ping2);
    assert!(&packet_ping1[..i2pk] == &packet_ping2[..i2pk]); // request id + PK
    assert!(&packet_ping1[i2pk..i2pkn] != &packet_ping2[i2pk..i2pkn]);
    assert!(&packet_ping1[i2pkn..] != &packet_ping2[i2pkn..]);

    assert!(&packet_friend1[0] == &packet_ping1[0]);
    assert!(packet_friend1[0] == NetPacket::Crypto as u8);
    assert!(packet_ping1[0] == NetPacket::Crypto as u8);

    // and decrypting..
    // ..fr
    let recv_pk_fr = PublicKey::from_slice(&packet_friend1[33..i2pk]).unwrap();
    let nonce_fr1 = Nonce::from_slice(&packet_friend1[i2pk..i2pkn]).unwrap();
    let ciphertext_fr1 = &packet_friend1[i2pkn..];

    let bob_msg_fr1 = open(ciphertext_fr1, &nonce_fr1, &recv_pk_fr, &bob_sk).unwrap();
    assert!(bob_msg_fr1[0] == CryptoPacket::FriendReq as u8);
    assert!(&bob_msg_fr1[1..] == alice_msg);

    // ..ping
    let recv_pk_ping = PublicKey::from_slice(&packet_ping1[33..i2pk]).unwrap();
    let nonce_ping1 = Nonce::from_slice(&packet_ping1[i2pk..i2pkn]).unwrap();
    let ciphertext_ping1 = &packet_ping1[i2pkn..];

    let bob_msg_ping1 = open(ciphertext_ping1, &nonce_ping1, &recv_pk_ping, &bob_sk).unwrap();
    assert!(bob_msg_ping1[0] == CryptoPacket::NAT_Ping as u8);
    assert!(&bob_msg_ping1[1..] == alice_msg);
}

#[test]
fn create_request_test_min_length() {
    let (alice_pk, alice_sk) = gen_keypair();
    let (bob_pk, _) = gen_keypair();

    let msg = b"";

    let packet = create_request(&alice_pk, &alice_sk, &bob_pk, msg,
                                CryptoPacket::FriendReq).unwrap();
    assert!(packet.len() == 106);
}

#[test]
fn create_request_test_max_length() {
    let (alice_pk, alice_sk) = gen_keypair();
    let (bob_pk, _) = gen_keypair();

    let msg = [0; MAX_CRYPTO_REQUEST_SIZE - (2 + 2 * PUBLICKEYBYTES + NONCEBYTES + MACBYTES)];

    let packet = create_request(&alice_pk, &alice_sk, &bob_pk, &msg,
                                CryptoPacket::FriendReq).unwrap();
    assert!(packet.len() == MAX_CRYPTO_REQUEST_SIZE);
}

#[test]
fn create_request_test_max_length_plus_1() {
    let (alice_pk, alice_sk) = gen_keypair();
    let (bob_pk, _) = gen_keypair();

    let msg = [0; MAX_CRYPTO_REQUEST_SIZE - (2 + 2 * PUBLICKEYBYTES + NONCEBYTES + MACBYTES) + 1];

    let packet = create_request(&alice_pk, &alice_sk, &bob_pk, &msg,
                                CryptoPacket::FriendReq);
    assert!(packet == None);
}

#[test]
fn create_request_test_random_length() {
    fn with_some_vec(vec: Vec<u8>) {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _) = gen_keypair();

        let packet = create_request(&alice_pk, &alice_sk, &bob_pk, &vec,
                                    CryptoPacket::FriendReq);

        if vec.len() < 918 {
            let length = 1 + 2 * PUBLICKEYBYTES + NONCEBYTES + 1 + vec.len() + MACBYTES;
            assert_eq!(length, packet.unwrap().len());
        } else {
            assert_eq!(None, packet);
        }
    }
    quickcheck(with_some_vec as fn(Vec<u8>));
}


#[test]
#[allow(non_snake_case)]
fn handle_request_test_correct_empty_FriendReq() {
    let (alice_pk, alice_sk) = gen_keypair();
    let (bob_pk, bob_sk) = gen_keypair();

    let packet = create_request(&alice_pk,
                                &alice_sk,
                                &bob_pk,
                                &[],
                                CryptoPacket::FriendReq).unwrap();

    match handle_request(&bob_pk, &bob_sk, &packet[..]) {
        None => panic!("This should have worked, since it was a correct request!"),
        Some(_) => {},
    }
}

#[test]
#[allow(non_snake_case)]
fn handle_request_test_correct_empty_Hardening() {
    let (alice_pk, alice_sk) = gen_keypair();
    let (bob_pk, bob_sk) = gen_keypair();

    let packet = create_request(&alice_pk,
                                &alice_sk,
                                &bob_pk,
                                &[],
                                CryptoPacket::Hardening).unwrap();

    match handle_request(&bob_pk, &bob_sk, &packet[..]) {
        None => panic!("This should have worked, since it was a correct request!"),
        Some(_) => {},
    }
}

#[test]
#[allow(non_snake_case)]
fn handle_request_test_correct_empty_DHT_PK() {
    let (alice_pk, alice_sk) = gen_keypair();
    let (bob_pk, bob_sk) = gen_keypair();

    let packet = create_request(&alice_pk,
                                &alice_sk,
                                &bob_pk,
                                &[],
                                CryptoPacket::DHT_PK).unwrap();

    match handle_request(&bob_pk, &bob_sk, &packet[..]) {
        None => panic!("This should have worked, since it was a correct request!"),
        Some(_) => {},
    }
}

#[test]
#[allow(non_snake_case)]
fn handle_request_test_correct_empty_NAT_Ping() {
    let (alice_pk, alice_sk) = gen_keypair();
    let (bob_pk, bob_sk) = gen_keypair();

    let packet = create_request(&alice_pk,
                                &alice_sk,
                                &bob_pk,
                                &[],
                                CryptoPacket::NAT_Ping).unwrap();

    match handle_request(&bob_pk, &bob_sk, &packet[..]) {
        None => panic!("This should have worked, since it was a correct request!"),
        Some(_) => {},
    }
}

#[test]
fn handle_request_test_invalid_empty() {
    let (pk, sk) = gen_keypair();
    match handle_request(&pk, &sk, &[0; 106]) {
        None => {},
        Some(_) => panic!("This should have failed, since packed did not have *any* valid data!"),
    }
}

#[test]
fn handle_request_test_too_short() {
    let (pk, sk) = gen_keypair();
    match handle_request(&pk, &sk, &[0; 0]) {
        None => {},
        Some(_) => panic!("This should have failed, since packed was too short!"),
    }
    match handle_request(&pk, &sk, &[0; 1]) {
        None => {},
        Some(_) => panic!("This should have failed, since packed was too short!"),
    }
    match handle_request(&pk, &sk, &[0; 105]) {
        None => {},
        Some(_) => panic!("This should have failed, since packed was too short!"),
    }
}

#[test]
fn handle_request_test_invalid_pk() {
    let (alice_pk, alice_sk) = gen_keypair();
    let (bob_pk, bob_sk) = gen_keypair();

    let packet = create_request(&alice_pk,
                                &alice_sk,
                                &bob_pk,
                                &[],
                                CryptoPacket::FriendReq).unwrap();
    // test whether..
    //  ..testing method is correct
    let PublicKey(alice_pk_bytes) = alice_pk;
    let mut packet_test = Vec::with_capacity(packet.len());
    packet_test.extend_from_slice(&packet[..(1 + PUBLICKEYBYTES)]);
    packet_test.extend_from_slice(&alice_pk_bytes[..]);
    packet_test.extend_from_slice(&packet[(1 + 2 * PUBLICKEYBYTES)..]);
    match handle_request(&bob_pk, &bob_sk, &packet_test) {
        None => panic!("This should *not* have failed!"),
        Some(_) => {},
    }

    //  ..fails when PK of sender is `0`s
    let mut packet_zeros = Vec::with_capacity(packet.len());
    packet_zeros.extend_from_slice(&packet[..(1 + PUBLICKEYBYTES)]);
    packet_zeros.extend_from_slice(&[0; PUBLICKEYBYTES]);
    packet_zeros.extend_from_slice(&packet[(1 + 2 * PUBLICKEYBYTES)..]);
    match handle_request(&bob_pk, &bob_sk, &packet_zeros) {
        None => {},
        Some(_) => panic!("This should have failed, since sender's PK was `0`s!"),
    }

    //  ..fails when PK of sender is the same as receiver
    let PublicKey(ref bob_pk_bytes) = bob_pk;
    let mut packet_receiver = Vec::with_capacity(packet.len());
    packet_receiver.extend_from_slice(&packet[..(1 + PUBLICKEYBYTES)]);
    packet_receiver.extend_from_slice(&bob_pk_bytes[..]);
    packet_receiver.extend_from_slice(&packet[(1 + 2 * PUBLICKEYBYTES)..]);
    match handle_request(&bob_pk, &bob_sk, &packet_receiver[..]) {
        None => {},
        Some(_) => panic!("This should have failed, since sender's PK was our own!"),
    }

    //  ..fails when PK of sender is wrong (random)
    let (PublicKey(rand_pk), _) = gen_keypair();
    let mut packet_random = Vec::with_capacity(packet.len());
    packet_random.extend_from_slice(&packet[..(1 + PUBLICKEYBYTES)]);
    packet_random.extend_from_slice(&rand_pk[..]);
    packet_random.extend_from_slice(&packet[(1 + 2 * PUBLICKEYBYTES)..]);

    //  ..fails when received own packet
    match handle_request(&alice_pk, &alice_sk, &packet[..]) {
        None => {},
        Some(_) => panic!("This should have failed, since it was own packet!"),
    }
}

#[test]
fn handle_request_test_nonce() {
    let (alice_pk, alice_sk) = gen_keypair();
    let (bob_pk, bob_sk) = gen_keypair();

    let packet = create_request(&alice_pk,
                                &alice_sk,
                                &bob_pk,
                                &[],
                                CryptoPacket::FriendReq).unwrap();

    // test whether it fails
    let Nonce(ref nonce) = gen_nonce();
    let mut test = Vec::with_capacity(packet.len());
    test.extend_from_slice(&packet[..(1 + 2 * PUBLICKEYBYTES)]);
    test.extend_from_slice(nonce);
    test.extend_from_slice(&packet[(1 + 2 * PUBLICKEYBYTES + NONCEBYTES)..]);
    match handle_request(&bob_pk, &bob_sk, &test[..]) {
        None => {},
        Some(_) => panic!("This should have failed, since nonce was wrong!"),
    }
}

// TODO: write more test for when `handle_request`..
//  ..fails when ciphertext is wrong
//  ..fails when decrypted payload is wrong (e.g. request id doesn't match)
