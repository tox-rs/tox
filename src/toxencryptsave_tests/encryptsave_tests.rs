use toxencryptsave::*;


// is_encrypted()

#[test]
fn is_encrypted_test() {
    assert!(!is_encrypted(b"Hello world.\n"));;
    assert!(is_encrypted(MAGIC_NUMBER));
    assert!(is_encrypted(include_bytes!("ciphertext")));
}


// pass_encrypt()

#[test]
fn pass_encrypt_error_test() {
    // empty data
    assert_eq!(Err(EncryptionError::Null), pass_encrypt(&[], &[0]));

    // empty passphrase
    assert_eq!(Err(EncryptionError::KeyDerivation(KeyDerivationError::Null)),
           pass_encrypt(&[0], &[]));
}

#[test]
fn pass_encrypt_test() {
    let plaintext = [42; 16];
    let passphrase = [53; 16];

    let encrypted = pass_encrypt(&plaintext, &passphrase).unwrap();
    assert!(is_encrypted(&encrypted));

    assert_eq!(plaintext.len() + EXTRA_LENGTH, encrypted.len());
    assert_eq!(&plaintext as &[u8], &pass_decrypt(&encrypted, &passphrase).unwrap() as &[u8]);

    let encrypted2 = pass_encrypt(&plaintext, &passphrase).unwrap();
    assert!(encrypted != encrypted2);
}


// pass_decrypt()

#[test]
fn pass_decrypt_error_null_test() {
    // empty data
    assert_eq!(Err(DecryptionError::Null), pass_decrypt(&[], &[0]));
}

#[test]
fn pass_decrypt_error_invalid_length_test() {
    // not enough data
    assert_eq!(Err(DecryptionError::InvalidLength),
           pass_decrypt(&[0], &[]));
}

#[test]
fn pass_decrypt_error_key_derivation_test() {
    // empty passphrase
    let ciphertext = include_bytes!("ciphertext");
    assert_eq!(Err(DecryptionError::KeyDerivation(KeyDerivationError::Null)),
           pass_decrypt(ciphertext, &[]));
}

#[test]
fn pass_decrypt_error_bad_format_test() {
    // one of `MAGIC_NUMBER` bytes is wrong
    let ciphertext = include_bytes!("ciphertext");
    let mut bad_ciphertext = Vec::with_capacity(MAGIC_LENGTH + SALT_LENGTH);
    bad_ciphertext.extend_from_slice(&[0; MAGIC_LENGTH]);
    bad_ciphertext.extend_from_slice(&ciphertext[MAGIC_LENGTH..]);
    assert_eq!(Err(DecryptionError::BadFormat), pass_decrypt(&bad_ciphertext, &[]));
}

#[test]
fn pass_decrypt_error_failed_test() {
    // a data byte is wrong
    let ciphertext = include_bytes!("ciphertext");
    let mut bad_ciphertext = Vec::with_capacity(EXTRA_LENGTH + 123);
    bad_ciphertext.extend_from_slice(&ciphertext[..EXTRA_LENGTH]);
    bad_ciphertext.extend_from_slice(&[42; 123]);
    assert_eq!(Err(DecryptionError::Failed), pass_decrypt(&bad_ciphertext, b"encryptsave"));
}

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
    let ciphertext = include_bytes!("ciphertext");
    let salt = &ciphertext[MAGIC_LENGTH .. MAGIC_LENGTH + SALT_LENGTH];

    assert_eq!(get_salt(ciphertext).unwrap().0, salt);
}

#[test]
fn get_salt_wrong_magic_test() {
    let ciphertext = include_bytes!("ciphertext");

    let mut bad_ciphertext = Vec::with_capacity(MAGIC_LENGTH + SALT_LENGTH);
    bad_ciphertext.extend_from_slice(&[0; MAGIC_LENGTH]);
    bad_ciphertext.extend_from_slice(&ciphertext[MAGIC_LENGTH..]);

    assert_eq!(get_salt(&bad_ciphertext), None);
}
