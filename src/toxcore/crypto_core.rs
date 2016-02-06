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

//! Functions for the core crypto.

use sodiumoxide::randombytes::randombytes_into;

pub use sodiumoxide::crypto::box_::*;

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


/// Return a random number.
pub fn random_u32() -> u32 {
    const BYTES: usize = 4;

    let mut array = [0; BYTES];
    randombytes_into(&mut array);

    let mut result: u32 = 0;
    for byte in 0..array.len() {
        result = result << 8;
        result = result | array[byte] as u32;
    }
    result
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


/// Return a random number.
pub fn random_u64() -> u64 {
    const BYTES: usize = 8;

    let mut array = [0; BYTES];
    randombytes_into(&mut array);

    let mut result: u64 = 0;
    for byte in 0..array.len() {
        result = result << 8;
        result = result | array[byte] as u64;
    }
    result
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


/// Check if Tox public key `PUBLICKEYBYTES` is valid. Should be used only for
/// input validation.
///
/// Returns `true` if valid, `false` otherwise.
pub fn public_key_valid(&PublicKey(ref pk): &PublicKey) -> bool {
    pk[PUBLICKEYBYTES - 1] <= 127 /* Last bit of key is always zero. */
}

#[test]
fn public_key_valid_test() {
    let (pk, _) = gen_keypair();
    assert_eq!(true, public_key_valid(&pk));

    assert_eq!(true, public_key_valid(&(PublicKey::from_slice(&[0b00000000; PUBLICKEYBYTES]).unwrap()))); // 0
    assert_eq!(true, public_key_valid(&(PublicKey::from_slice(&[0b01111111; PUBLICKEYBYTES]).unwrap()))); // 127
    assert_eq!(false, public_key_valid(&(PublicKey::from_slice(&[0b10000000; PUBLICKEYBYTES]).unwrap()))); // 128
    assert_eq!(false, public_key_valid(&(PublicKey::from_slice(&[0b11111111; PUBLICKEYBYTES]).unwrap()))); // 255
}


/// Precomputes the shared key from `their_public_key` and `our_secret_key`.
///
/// For fast encrypt/decrypt - this way we can avoid an expensive elliptic
/// curve scalar multiply for each encrypt/decrypt operation.
///
/// Use if communication is not one-time.
///
/// `encrypt_precompute` does the shared-key generation once, so that it does
/// not have to be performed on every encrypt/decrypt.
///
/// This a wrapper for the
/// [`precompute()`](../../../sodiumoxide/crypto/box_/curve25519xsalsa20poly1305/fn.precompute.html)
/// function from `sodiumoxide` crate.
#[inline]
pub fn encrypt_precompute(their_public_key: &PublicKey,
                          our_secret_key: &SecretKey) -> PrecomputedKey {
    precompute(their_public_key, our_secret_key)
}
// ↓ can't use, since there's no way to add additional docs
//pub use sodiumoxide::crypto::box_::precompute as encrypt_precompute;

#[test]
// test uses "bare" functions provided by `sodiumoxide`, with an exception
// of the tested function
fn encrypt_precompute_test() {
    let (alice_pk, alice_sk) = gen_keypair();
    let (bob_pk, bob_sk) = gen_keypair();

    let alice_precomputed_key = encrypt_precompute(&bob_pk, &alice_sk);

    let nonce1 = gen_nonce();
    let nonce2 = gen_nonce();

    let alice_plaintext1 = b"Hi, Bob.";
    let alice_plaintext2 = b"Pls respond.";

    let ciphertext1 = seal_precomputed(alice_plaintext1, &nonce1, &alice_precomputed_key);
    let ciphertext2 = seal_precomputed(alice_plaintext2, &nonce2, &alice_precomputed_key);

    let bob_precomputed_key = encrypt_precompute(&alice_pk, &bob_sk);

    let bob_plaintext1 = open_precomputed(&ciphertext1, &nonce1, &bob_precomputed_key).unwrap();
    let bob_plaintext2 = open_precomputed(&ciphertext2, &nonce2, &bob_precomputed_key).unwrap();

    assert!(alice_plaintext1 == &bob_plaintext1[..]);
    assert!(alice_plaintext2 == &bob_plaintext2[..]);
}


/// Returns encrypted data from `plain`, with length of `plain + 16` due to
/// padding.
///
/// Encryption is done using precomputed key (from the public key (32 bytes)
/// of receiver and the secret key of sender) and a 24 byte nonce.
///
/// `sodiumoxide` takes care of padding the data, so the resulting encrypted
/// data has length of `plain + 16`.
///
/// A wrapper for the
/// [`seal_precomputed()`](../../../sodiumoxide/crypto/box_/curve25519xsalsa20poly1305/fn.seal_precomputed.html)
/// function from `sodiumoxide`.
#[inline]
pub fn encrypt_data_symmetric(precomputed_key: &PrecomputedKey,
                              nonce: &Nonce,
                              plain: &[u8]) -> Vec<u8> {
    seal_precomputed(plain, nonce, precomputed_key)
}
// not using ↓ since it doesn't allow to add additional documentation
//pub use sodiumoxide::crypto::box_::seal_precomputed as encrypt_data_symmetric;

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

    assert!(alice_plain == &bob_plain[..]);
}

// TODO: test for pubkey/skey/nonce being all `0`s, which would produce
// ciphertext that should be compared to already known result of this
// computation. This way it would be ensured that cipher algorithm is
// actually working as it should.
// There should be also some additional variations of this test, with different
// pkey/skey/nonce values that would produce known ciphertext.
//
// Also, similar test for decrypting.


/// Returns plain data from `encrypted`, with length of `encrypted - 16` due to
/// padding, or `()` if data couldn't be decrypted.
///
/// Decryption is done using precomputed key (from the secret key of receiver
/// and the public key of sender) and a 24 byte nonce.
///
/// `sodiumoxide` takes care of removing padding from the data, so the
/// resulting plain data has length of `encrypted - 16`.
///
/// This function is a wrapper for the
/// [`open_precomputed()`](../../../sodiumoxide/crypto/box_/curve25519xsalsa20poly1305/fn.open_precomputed.html)
/// function from `sodiumoxide`.
#[inline]
pub fn decrypt_data_symmetric(precomputed_key: &PrecomputedKey,
                              nonce: &Nonce,
                              encrypted: &[u8]) -> Result<Vec<u8>, ()> {
    open_precomputed(encrypted, nonce, precomputed_key)
}

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

    assert!(alice_plain == &bob_plain[..]);
}


/// Inrement given nonce by 1.
#[inline]
// FIXME: sodiumoxide is broken - nonce isn't incremented
// TODO: since sodiumoxide/sodium don't check for arithmetic overflow, do it
//
// overflow doesn't /seem/ to be likely to happen in the first place, given
// that no nonce should be incremented long enough for it to happen, but still..
pub fn increment_nonce(nonce: &mut Nonce) {
    nonce.increment_le();
}

#[test]
fn increment_nonce_test_zero_plus_one() {
    let cmp_nonce = Nonce::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 1]).unwrap();

    let mut nonce = Nonce::from_slice(&[0; NONCEBYTES]).unwrap();
    increment_nonce(&mut nonce);
    assert!(nonce == cmp_nonce);
}

#[test]
fn increment_nonce_test_0xf_plus_one() {
    let cmp_nonce = Nonce::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0x10]).unwrap();

    let mut nonce = Nonce::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0xf]).unwrap();
    increment_nonce(&mut nonce);
    assert!(nonce == cmp_nonce);
}

#[test]
fn increment_nonce_test_0xff_plus_one() {
    let cmp_nonce = Nonce::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 1, 0]).unwrap();

    let mut nonce = Nonce::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0xff]).unwrap();
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


/// Inrement given nonce by number `num`.
// FIXME: sodiumoxide is broken - nonce isn't incremented
// TODO: since sodiumoxide/sodium don't check for arithmetic overflow, do it
pub fn increment_nonce_number(mut nonce: &mut Nonce, num: usize) {
    for _ in 0..num {
        increment_nonce(&mut nonce);
    }
}

#[test]
fn increment_nonce_number_test_zero_plus_0xff00() {
    let cmp_nonce = Nonce::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0xff, 0]).unwrap();
    let mut nonce = Nonce::from_slice(&[0; NONCEBYTES]).unwrap();

    increment_nonce_number(&mut nonce, 0xff00);
    assert!(nonce == cmp_nonce);
}

#[test]
fn increment_nonce_number_test_0xff0000_plus_0x011000() {
    let cmp_nonce = Nonce::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 1, 0, 0x10, 0]).unwrap();

    let mut nonce = Nonce::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0xff, 0, 0]).unwrap();

    increment_nonce_number(&mut nonce, 0x11000);
    assert!(nonce == cmp_nonce);
}

pub const MAX_CRYPTO_REQUEST_SIZE: usize = 1024;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug)]
pub enum CryptoPacket {
    FriendReq = 32,
    Hardening = 48,
    DHT_PK    = 156,
    NAT_Ping  = 254,
}


/// Create a request to the peer.
///
/// `send_public_key` - sender's public key.
///
/// `send_secret_key` - sender's secret key.
///
/// `recv_public_key` - receiver's public key.
///
/// `data` - data we send with the request.
///
/// `request_id` - id of the request. Use either `FriendReq` or `NAT_Ping`.
///
/// Upon success, return created packet, and `None` on faliure.
//                   ↓      ↓      ↓
// Packet structure          (74 bytes minimum)
//  +---------------------------------------------+
//  | *Unencrypted section:* (57 bytes total)     |
//  |  - Packet type         (1 byte, value `32`) |
//  |  - Sender public key   (32 bytes)           |
//  |  - Random nonce        (24 bytes)           |
//  +---------------------------------------------+
//  | *Encrypted payload:*   (17 bytes minimum)   |
//  |  - Request ID          (1 byte)             |
//  |  - Data                (varies)             |
//  +---------------------------------------------+
//
// TODO: use some enums for things? perhaps for created packet?
pub fn create_request(&PublicKey(ref send_public_key): &PublicKey,
                      send_secret_key: &SecretKey,
                      recv_public_key: &PublicKey,
                      data: &[u8],
                      request_id: CryptoPacket) -> Vec<u8> {

    let nonce = gen_nonce();

    let mut temp = Vec::with_capacity(data.len() + 1);
    temp.push(request_id as u8);
    temp.extend_from_slice(data);

    let encrypted = seal(&temp, &nonce, recv_public_key, send_secret_key);

    let mut packet: Vec<u8> = Vec::with_capacity(1 // NetPacket
                                                 + 32 // PublicKey
                                                 + 24 // Nonce
                                                 + encrypted.len());

    packet.push(NetPacket::Crypto as u8);
    packet.extend_from_slice(send_public_key);
    let Nonce(ref nonce) = nonce;
    packet.extend_from_slice(nonce);
    packet.extend_from_slice(&encrypted);

    packet
}

#[test]
fn create_request_test() {
    let (alice_pk, alice_sk) = gen_keypair();
    let (bob_pk, bob_sk) = gen_keypair();

    let alice_msg = b"Hi, bub.";

    let packet_friend1 = create_request(&alice_pk, &alice_sk, &bob_pk,
                                        alice_msg, CryptoPacket::FriendReq);
    let packet_friend2 = create_request(&alice_pk, &alice_sk, &bob_pk,
                                        alice_msg, CryptoPacket::FriendReq);
    // should differ by nonce, and thus also ciphertext
    assert!(packet_friend1 != packet_friend2);
    assert!(&packet_friend1[0..33] == &packet_friend2[0..33]); // request id + PK
    assert!(&packet_friend1[33..57] != &packet_friend2[33..57]); // nonce
    assert!(&packet_friend1[57..] != &packet_friend2[57..]);


    let packet_ping1 = create_request(&alice_pk, &alice_sk, &bob_pk,
                                        alice_msg, CryptoPacket::NAT_Ping);
    let packet_ping2 = create_request(&alice_pk, &alice_sk, &bob_pk,
                                        alice_msg, CryptoPacket::NAT_Ping);
    // should differ by nonce, and thus also ciphertext
    assert!(packet_ping1 != packet_ping2);
    assert!(&packet_ping1[0..33] == &packet_ping2[0..33]); // request id + PK
    assert!(&packet_ping1[33..57] != &packet_ping2[33..57]);
    assert!(&packet_ping1[57..] != &packet_ping2[57..]);

    assert!(&packet_friend1[0] == &packet_ping1[0]);
    assert!(packet_friend1[0] == NetPacket::Crypto as u8);
    assert!(packet_ping1[0] == NetPacket::Crypto as u8);

    // and decrypting..
    // ..fr
    let recv_pk_fr = PublicKey::from_slice(&packet_friend1[1..33]).unwrap();
    let nonce_fr1 = Nonce::from_slice(&packet_friend1[33..57]).unwrap();
    let ciphertext_fr1 = &packet_friend1[57..];

    let bob_msg_fr1 = open(ciphertext_fr1, &nonce_fr1, &recv_pk_fr, &bob_sk).unwrap();
    assert!(bob_msg_fr1[0] == CryptoPacket::FriendReq as u8);
    assert!(&bob_msg_fr1[1..] == alice_msg);

    // ..ping
    let recv_pk_ping = PublicKey::from_slice(&packet_ping1[1..33]).unwrap();
    let nonce_ping1 = Nonce::from_slice(&packet_ping1[33..57]).unwrap();
    let ciphertext_ping1 = &packet_ping1[57..];

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
                                CryptoPacket::FriendReq);
    assert!(packet.len() == 74);
}

// TODO: check max request packet size and make test for it
//  - should fail if packet size can exceed limit


/// Returns senders public key, request id, and data from the request,
/// or `None` if request was invalid.
//
// The way it's supposed™ to work:
//  1. Check if length of received packet is at least 74 bytes long, if it's
//     not, return `None`.
//      - 74 bytes is a miminum when ~no encrypted data is being sent, spare
//        for the request ID (1 byte).
//  2. Check if public key is valid, if it's not, return `None`.
//  3. Check if public key is not our own, if it is, return `None`.
//  4. Check if payload can be decrypted, if it can't, return `None`.
//  5. Check if request id matches some existing one, if not, return `None`.
//      - request id is the first byte of decrypted payload.
//  6. If everything else was successful, return sender's PK, request id and
//     data.
//      - data from the payload should be located after the first byte - if
//        there was nothing there, it means that there was no data, and rest
//        was just padding that decrypting removed.
pub fn handle_request(our_public_key: &PublicKey,
                      our_secret_key: &SecretKey,
                      packet: &[u8])
                -> Option<(PublicKey, CryptoPacket, Vec<u8>)> {
    if packet.len() < 74 {
        return None;
    }

    if let Some(pk) = PublicKey::from_slice(&packet[1..(PUBLICKEYBYTES + 1)]) {
        if !public_key_valid(&pk) {
            return None;
        }

        if &pk == our_public_key {
            return None;
        }

        if let Some(nonce) = Nonce::from_slice(&packet[(1 + PUBLICKEYBYTES)..(1 + PUBLICKEYBYTES + NONCEBYTES)]) {
            if let Ok(payload) = open(&packet[(1 + PUBLICKEYBYTES + NONCEBYTES)..], 
                                   &nonce, &pk, our_secret_key) {
                let request_id = match payload[0] {
                    32 => CryptoPacket::FriendReq,
                    48 => CryptoPacket::Hardening,
                    156 => CryptoPacket::DHT_PK,
                    254 => CryptoPacket::NAT_Ping,
                    _ => return None,
                };

                let mut data: Vec<u8> = Vec::with_capacity(payload[1..].len());
                data.extend_from_slice(&payload[1..]);
                return Some((pk, request_id, data))
            }
        }
    }

    None
}

// TODO: test ↑
