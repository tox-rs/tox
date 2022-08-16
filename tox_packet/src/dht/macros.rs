/*! Macros for test functions
*/

macro_rules! dht_packet_encode_decode (
    ($test:ident, $packet:ident) => (
        encode_decode_test!(
            $test,
            Packet::$packet($packet {
                pk: crypto_box::SecretKey::generate(&mut rand::thread_rng()).public_key(),
                nonce: SalsaBox::generate_nonce(&mut rand::thread_rng()).into(),
                payload: vec![42; 123],
            })
        );
    )
);

macro_rules! dht_packet_encrypt_decrypt (
    ($test:ident, $packet:ident, $payload:expr) => (
        #[test]
        fn $test() {
            use crypto_box::SecretKey;

            let mut rng = rand::thread_rng();
            let alice_sk = SecretKey::generate(&mut rng);
            let alice_pk = alice_sk.public_key();
            let bob_pk = SecretKey::generate(&mut rng).public_key();
            let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
            let payload = $payload;
            // encode payload with shared secret
            let dht_packet = $packet::new(&shared_secret, alice_pk, &payload);
            // decode payload with shared secret
            let decoded_payload = dht_packet.get_payload(&shared_secret).unwrap();
            // payloads should be equal
            assert_eq!(decoded_payload, payload);
        }
    )
);

macro_rules! dht_packet_encrypt_decrypt_invalid_key (
    ($test:ident, $packet:ident, $payload:expr) => (
        #[test]
        fn $test() {
            use crypto_box::SecretKey;

            let mut rng = rand::thread_rng();
            let alice_sk = SecretKey::generate(&mut rng);
            let alice_pk = alice_sk.public_key();
            let bob_pk = SecretKey::generate(&mut rng).public_key();
            let eve_sk = SecretKey::generate(&mut rng);
            let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
            let shared_secret_invalid = SalsaBox::new(&bob_pk, &eve_sk);
            let payload = $payload;
            // encode payload with shared secret
            let dht_packet = $packet::new(&shared_secret, alice_pk, &payload);
            // try to decode payload with invalid shared secret
            let decoded_payload = dht_packet.get_payload(&shared_secret_invalid);
            assert!(decoded_payload.is_err());
        }
    )
);

macro_rules! dht_packet_decode_invalid (
    ($test:ident, $packet:ident) => (
        #[test]
        fn $test() {
            use aead::Aead;
            use crypto_box::SecretKey;

            let mut rng = rand::thread_rng();
            let alice_sk = SecretKey::generate(&mut rng);
            let alice_pk = alice_sk.public_key();
            let bob_pk = SecretKey::generate(&mut rng).public_key();
            let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
            let nonce = SalsaBox::generate_nonce(&mut rng);
            // Try long invalid array
            let invalid_payload = [42; 123];
            let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
            let invalid_packet = $packet {
                pk: alice_pk.clone(),
                nonce: nonce.into(),
                payload: invalid_payload_encoded
            };
            let decoded_payload = invalid_packet.get_payload(&shared_secret);
            assert!(decoded_payload.is_err());
            // Try short incomplete array
            let invalid_payload = [];
            let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
            let invalid_packet = $packet {
                pk: alice_pk,
                nonce: nonce.into(),
                payload: invalid_payload_encoded
            };
            let decoded_payload = invalid_packet.get_payload(&shared_secret);
            assert!(decoded_payload.is_err());
        }
    );
);
