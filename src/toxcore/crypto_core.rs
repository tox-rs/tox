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

use toxcore::binary_io::{array_to_u32, array_to_u64};
use toxcore::network::NetPacket;

// TODO: check if `#[inline]` is actually useful

/// Return a random number.
pub fn random_u32() -> u32 {
    let mut array = [0; 4];
    randombytes_into(&mut array);
    array_to_u32(&array)
}

/// Return a random number.
pub fn random_u64() -> u64 {
    let mut array = [0; 8];
    randombytes_into(&mut array);
    array_to_u64(&array)
}


/// Check if Tox public key `PUBLICKEYBYTES` is valid. Should be used only for
/// input validation.
///
/// Returns `true` if valid, `false` otherwise.
pub fn public_key_valid(&PublicKey(ref pk): &PublicKey) -> bool {
    pk[PUBLICKEYBYTES - 1] <= 127 // Last bit of key is always zero.
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


/// Inrement given nonce by 1.
#[inline]
// TODO: since sodiumoxide/sodium don't check for arithmetic overflow, do it
//
// overflow doesn't /seem/ to be likely to happen in the first place, given
// that no nonce should be incremented long enough for it to happen, but still..
// FIXME: since toxcore increments nonce as big endian num, same has to be done
//        here: https://toktok.github.io/spec#nonce-2
//
//        Alternatively, make toxcore C reference use libsodium function for
//        incrementing nonces, which is LE – this is marked in toxcore as
//        `FIXME`.
pub fn increment_nonce(nonce: &mut Nonce) {
    nonce.increment_le_inplace();
}


/// Inrement given nonce by number `num`.
// TODO: since sodiumoxide/sodium don't check for arithmetic overflow, do it
pub fn increment_nonce_number(mut nonce: &mut Nonce, num: usize) {
    for _ in 0..num {
        increment_nonce(&mut nonce);
    }
}


/// Max size of crypto request. Should be used in `create_request` and
/// `handle_request` to check if request isn't too big.
pub const MAX_CRYPTO_REQUEST_SIZE: usize = 1024;

/// Types of packets that `crypto_request` can create, and `handle_request`
/// should handle. It should be located in the first encrypted byte of a packet.
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug)]
pub enum CryptoPacket {
    /// Friend request crypto packet ID.
    FriendReq = 32,
    /// Hardening crypto packet ID.
    Hardening = 48,
    /// Used by some onion stuff .. ???
    // FIXME: ↑
    DHT_PK    = 156,
    /// NAT ping crypto packet ID.
    NAT_Ping  = 254,
}


/// Create a request to the peer. Fails if data is bigger than `918` bytes.
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
///
/// Maximum size of returned packet equals
/// [`MAX_CRYPTO_REQUEST_SIZE`](./constant.MAX_CRYPTO_REQUEST_SIZE.html).
///
/// ```text
/// Packet structure          (106 bytes minimum, 1024 max)
///  +----------------------------------------------+
///  | *Unencrypted section:* (89 bytes total)      |
///  |  - Packet type         (1 byte, value `32`)  |
///  |  - Receiver public key (32 bytes)            |
///  |  - Sender public key   (32 bytes)            |
///  |  - Random nonce        (24 bytes)            |
///  +----------------------------------------------+
///  | *Encrypted payload:*   (17 bytes minimum)    |
///  |  - Request ID          (1 byte)              |
///  |  - Data                (varies, <=918 bytes) |
///  +----------------------------------------------+
/// ```
//
// TODO: use some structs for things? perhaps for created packet?
pub fn create_request(&PublicKey(ref send_public_key): &PublicKey,
                      send_secret_key: &SecretKey,
                      recv_public_key: &PublicKey,
                      data: &[u8],
                      request_id: CryptoPacket) -> Option<Vec<u8>> {

    // too much data for a request
    if 1 + 2 * PUBLICKEYBYTES + NONCEBYTES + 1 + data.len() + MACBYTES > MAX_CRYPTO_REQUEST_SIZE {
        return None;
    }

    let nonce = gen_nonce();

    let mut temp = Vec::with_capacity(data.len() + 1);
    temp.push(request_id as u8);
    temp.extend_from_slice(data);

    let encrypted = seal(&temp, &nonce, recv_public_key, send_secret_key);

    let mut packet: Vec<u8> = Vec::with_capacity(1 // NetPacket
                                                 + 32 // Receiver PublicKey
                                                 + 32 // Sender PublicKey
                                                 + 24 // Nonce
                                                 + encrypted.len());

    packet.push(NetPacket::Crypto as u8);
    let &PublicKey(ref recv_pk_bytes) = recv_public_key;
    packet.extend_from_slice(recv_pk_bytes);
    packet.extend_from_slice(send_public_key);
    let Nonce(ref nonce) = nonce;
    packet.extend_from_slice(nonce);
    packet.extend_from_slice(&encrypted);

    Some(packet)
}


/// Returns senders public key, request id, and data from the request,
/// or `None` if request was invalid.
///
// Not checked by this function:
//  * packet type (first byte of the packet)
//
// The way it's supposed™ to work:
//  1. Check if length of received packet is at least 106 bytes long, if it's
//     not, return `None`.
//      - 106 bytes is a miminum when ~no encrypted data is being sent, spare
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
//
// TODO: use some struct for packet, and `impl` for it needed methods
// TODO: Return `Result<_, ENUM_ERR>` instead of `Option<_>`
pub fn handle_request(our_public_key: &PublicKey,
                      our_secret_key: &SecretKey,
                      packet: &[u8])
                -> Option<(PublicKey, CryptoPacket, Vec<u8>)> {
    if packet.len() < 106 || packet.len() > MAX_CRYPTO_REQUEST_SIZE {
        return None;
    }

    let send_pk_bytes = &packet[(1 + PUBLICKEYBYTES)..(1 + 2 * PUBLICKEYBYTES)];
    if let Some(pk) = PublicKey::from_slice(send_pk_bytes) {
        if !public_key_valid(&pk) {
            return None;
        }

        if &pk == our_public_key {
            return None;
        }

        if let Some(nonce) = Nonce::from_slice(&packet[(1 + 2 * PUBLICKEYBYTES)..(1 + 2 * PUBLICKEYBYTES + NONCEBYTES)]) {
            if let Ok(payload) = open(&packet[(1 + 2 * PUBLICKEYBYTES + NONCEBYTES)..],
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
