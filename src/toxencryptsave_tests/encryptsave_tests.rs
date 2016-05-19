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
