/*
    Copyright © 2016 quininer kel <quininer@live.com>

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


use toxencryptsave::encryptsave::*;


#[test]
fn encrypt_test() {
    use sodiumoxide::randombytes::randombytes;

    let plaintext = randombytes(16);
    let passphrase = randombytes(16);
    assert_eq!(pass_decrypt(
        &pass_encrypt(&plaintext, &passphrase).unwrap(),
        &passphrase
    ).unwrap(), plaintext);
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
