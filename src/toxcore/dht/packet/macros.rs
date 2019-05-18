/*! Macros for test functions
*/

macro_rules! dht_packet_encode_decode (
    ($test:ident, $packet:ident) => (
        encode_decode_test!(
            $test,
            Packet::$packet($packet {
                pk: gen_keypair().0,
                nonce: gen_nonce(),
                payload: vec![42; 123],
            })
        );
    )
);

macro_rules! dht_packet_encrypt_decrypt (
    ($test:ident, $packet:ident, $payload:expr) => (
        #[test]
        fn $test() {
            crypto_init().unwrap();
            let (alice_pk, alice_sk) = gen_keypair();
            let (bob_pk, _bob_sk) = gen_keypair();
            let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
            let payload = $payload;
            // encode payload with shared secret
            let dht_packet = $packet::new(&shared_secret, &alice_pk, &payload);
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
            crypto_init().unwrap();
            let (alice_pk, alice_sk) = gen_keypair();
            let (bob_pk, _bob_sk) = gen_keypair();
            let (_eve_pk, eve_sk) = gen_keypair();
            let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
            let shared_secret_invalid = encrypt_precompute(&bob_pk, &eve_sk);
            let payload = $payload;
            // encode payload with shared secret
            let dht_packet = $packet::new(&shared_secret, &alice_pk, &payload);
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
            crypto_init().unwrap();
            let (alice_pk, alice_sk) = gen_keypair();
            let (bob_pk, _bob_sk) = gen_keypair();
            let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
            let nonce = gen_nonce();
            // Try long invalid array
            let invalid_payload = [42; 123];
            let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
            let invalid_packet = $packet {
                pk: alice_pk,
                nonce,
                payload: invalid_payload_encoded
            };
            let decoded_payload = invalid_packet.get_payload(&shared_secret);
            assert!(decoded_payload.is_err());
            // Try short incomplete array
            let invalid_payload = [];
            let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
            let invalid_packet = $packet {
                pk: alice_pk,
                nonce,
                payload: invalid_payload_encoded
            };
            let decoded_payload = invalid_packet.get_payload(&shared_secret);
            assert!(decoded_payload.is_err());
        }
    );
);
