/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2016-2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2018 Namsoo CHO <nscho66@gmail.com>
    Copyright © 2018 Evgeny Kurnevsky <kurnevsky@gmail.com>
    Copyright © 2018 Roman Proskuryakov <humbug@deeptown.org>

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

/*! Macros for test functions
*/

use super::*;

use quickcheck::{Arbitrary, Gen};

impl Arbitrary for DhtPacket {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let choice = g.gen_range(0, 5);
        match choice {
            0 => DhtPacket::PingRequest(PingRequest::arbitrary(g)),
            1 => DhtPacket::PingResponse(PingResponse::arbitrary(g)),
            2 => DhtPacket::NodesRequest(NodesRequest::arbitrary(g)),
            3 => DhtPacket::NodesResponse(NodesResponse::arbitrary(g)),
            4 => DhtPacket::DhtRequest(DhtRequest::arbitrary(g)),
            _ => unreachable!("Arbitrary for DhtPacket - should not have happened!")
        }
    }
}

macro_rules! dht_packet_arbitrary (
    ($packet:ident, $payload:ident) => (
        impl Arbitrary for $packet {
            fn arbitrary<G: Gen>(g: &mut G) -> Self {
                let (pk, sk) = gen_keypair();  // "sender" keypair
                let (r_pk, _) = gen_keypair();  // receiver PK
                let precomputed = encrypt_precompute(&r_pk, &sk);
                $packet::new(&precomputed, &pk, $payload::arbitrary(g))
            }
        }
    )
);

macro_rules! dht_packet_encode_decode (
    ($test:ident, $packet:ident) => (
        encode_decode_test!(
            $test,
            DhtPacket::$packet($packet {
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
            let (alice_pk, alice_sk) = gen_keypair();
            let (bob_pk, bob_sk) = gen_keypair();
            let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
            let payload = $payload;
            // encode payload with shared secret
            let dht_packet = $packet::new(&shared_secret, &alice_pk, payload.clone());
            // decode payload with bob's secret key
            let decoded_payload = dht_packet.get_payload(&bob_sk).unwrap();
            // payloads should be equal
            assert_eq!(decoded_payload, payload);
        }
    )
);

macro_rules! dht_packet_encrypt_decrypt_invalid_key (
    ($test:ident, $packet:ident, $payload:expr) => (
        #[test]
        fn $test() {
            let (alice_pk, alice_sk) = gen_keypair();
            let (bob_pk, _bob_sk) = gen_keypair();
            let (_eve_pk, eve_sk) = gen_keypair();
            let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
            let payload = $payload;
            // encode payload with shared secret
            let dht_packet = $packet::new(&shared_secret, &alice_pk, payload.clone());
            // try to decode payload with eve's secret key
            let decoded_payload = dht_packet.get_payload(&eve_sk);
            assert!(decoded_payload.is_err());
        }
    )
);

macro_rules! dht_packet_decode_invalid (
    ($test:ident, $packet:ident) => (
        #[test]
        fn $test() {
            let (alice_pk, alice_sk) = gen_keypair();
            let (bob_pk, bob_sk) = gen_keypair();
            let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
            let nonce = gen_nonce();
            // Try long invalid array
            let invalid_payload = [42; 123];
            let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
            let invalid_packet = $packet {
                pk: alice_pk,
                nonce: nonce,
                payload: invalid_payload_encoded
            };
            let decoded_payload = invalid_packet.get_payload(&bob_sk);
            assert!(decoded_payload.is_err());
            // Try short incomplete for *Requests
            let invalid_payload = [0x00];
            let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
            let invalid_packet = $packet {
                pk: alice_pk,
                nonce: nonce,
                payload: invalid_payload_encoded
            };
            let decoded_payload = invalid_packet.get_payload(&bob_sk);
            assert!(decoded_payload.is_err());
            // Try short incomplete for *Responses
            let invalid_payload = [0x01];
            let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
            let invalid_packet = $packet {
                pk: alice_pk,
                nonce: nonce,
                payload: invalid_payload_encoded
            };
            let decoded_payload = invalid_packet.get_payload(&bob_sk);
            assert!(decoded_payload.is_err());
        }
    );
);
