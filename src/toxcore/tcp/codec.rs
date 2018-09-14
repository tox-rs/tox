/*! Codec implementation for encoding/decoding TCP Packets in terms of tokio-io
*/

use toxcore::binary_io::*;
use toxcore::tcp::packet::*;
use toxcore::tcp::secure::*;

use nom::Offset;
use std::io::{Error, ErrorKind};
use bytes::BytesMut;
use tokio_codec::{Decoder, Encoder};

/// implements tokio-io's Decoder and Encoder to deal with Packet
pub struct Codec {
    channel: Channel
}

impl Codec {
    /// create a new Codec with the given Channel
    pub fn new(channel: Channel) -> Codec {
        Codec { channel }
    }
}

impl Decoder for Codec {
    type Item = Packet;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // deserialize EncryptedPacket
        let (consumed, encrypted_packet) = match EncryptedPacket::from_bytes(buf) {
            IResult::Incomplete(_) => {
                return Ok(None)
            },
            IResult::Error(e) => {
                return Err(Error::new(ErrorKind::Other,
                    format!("EncryptedPacket deserialize error: {:?}", e)))
            },
            IResult::Done(i, encrypted_packet) => {
                (buf.offset(i), encrypted_packet)
            }
        };

        // decrypt payload
        let decrypted_data = self.channel.decrypt(&encrypted_packet.payload)
            .map_err(|_|
                Error::new(ErrorKind::Other, "EncryptedPacket decrypt failed")
            )?;

        // deserialize Packet
        match Packet::from_bytes(&decrypted_data) {
            IResult::Incomplete(_) => {
                Err(Error::new(ErrorKind::Other,
                    "Packet should not be incomplete"))
            },
            IResult::Error(e) => {
                Err(Error::new(ErrorKind::Other,
                    format!("deserialize Packet error: {:?}", e)))
            },
            IResult::Done(_, packet) => {
                buf.split_to(consumed);
                Ok(Some(packet))
            }
        }
    }
}

impl Encoder for Codec {
    type Item = Packet;
    type Error = Error;

    fn encode(&mut self, packet: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        // serialize Packet
        let mut packet_buf = [0; MAX_TCP_PACKET_SIZE];
        let (_, packet_size) = packet.to_bytes((&mut packet_buf, 0))
            .map_err(|e|
                Error::new(ErrorKind::Other,
                    format!("Packet serialize error: {:?}", e))
            )?;

        // encrypt it
        let encrypted = self.channel.encrypt(&packet_buf[..packet_size]);

        // create EncryptedPacket
        let encrypted_packet = EncryptedPacket { payload: encrypted };

        // serialize EncryptedPacket to binary form
        let mut encrypted_packet_buf = [0; MAX_TCP_ENC_PACKET_SIZE];
        let (_, encrypted_packet_size) = encrypted_packet.to_bytes((&mut encrypted_packet_buf, 0))
            .expect("EncryptedPacket serialize failed"); // there is nothing to fail since
                    // serialized Packet is not longer than 2032 bytes
                    // and we provided 2050 bytes for EncryptedPacket
        buf.extend_from_slice(&encrypted_packet_buf[..encrypted_packet_size]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ::toxcore::crypto_core::*;
    use ::toxcore::onion::packet::*;
    use ::toxcore::tcp::codec::*;

    use std::net::{
      IpAddr,
      Ipv4Addr,
      Ipv6Addr,
    };

    fn create_channels() -> (Channel, Channel) {
        let alice_session = Session::new();
        let bob_session = Session::new();

        // assume we got Alice's PK & Nonce via handshake
        let alice_pk = *alice_session.pk();
        let alice_nonce = *alice_session.nonce();

        // assume we got Bob's PK & Nonce via handshake
        let bob_pk = *bob_session.pk();
        let bob_nonce = *bob_session.nonce();

        // Now both Alice and Bob may create secure Channels
        let alice_channel = Channel::new(&alice_session, &bob_pk, &bob_nonce);
        let bob_channel = Channel::new(&bob_session, &alice_pk, &alice_nonce);

        (alice_channel, bob_channel)
    }

    #[test]
    fn encode_decode() {
        let (pk, _) = gen_keypair();
        let (alice_channel, bob_channel) = create_channels();
        let mut buf = BytesMut::new();
        let mut alice_codec = Codec::new(alice_channel);
        let mut bob_codec = Codec::new(bob_channel);

        let test_packets = vec![
            Packet::RouteRequest( RouteRequest { pk } ),
            Packet::RouteResponse( RouteResponse { connection_id: 42, pk } ),
            Packet::ConnectNotification( ConnectNotification { connection_id: 42 } ),
            Packet::DisconnectNotification( DisconnectNotification { connection_id: 42 } ),
            Packet::PingRequest( PingRequest { ping_id: 4242 } ),
            Packet::PongResponse( PongResponse { ping_id: 4242 } ),
            Packet::OobSend( OobSend { destination_pk: pk, data: vec![13; 42] } ),
            Packet::OobReceive( OobReceive { sender_pk: pk, data: vec![13; 24] } ),
            Packet::OnionRequest( OnionRequest {
                nonce: gen_nonce(),
                ip_port: IpPort {
                    protocol: ProtocolType::TCP,
                    ip_addr: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
                    port: 12345,
                },
                temporary_pk: gen_keypair().0,
                payload: vec![13; 207]
            } ),
            Packet::OnionRequest( OnionRequest {
                nonce: gen_nonce(),
                ip_port: IpPort {
                    protocol: ProtocolType::TCP,
                    ip_addr: IpAddr::V6(Ipv6Addr::new(5, 6, 7, 8, 5, 6, 7, 8)),
                    port: 54321,
                },
                temporary_pk: gen_keypair().0,
                payload: vec![13; 201]
            } ),
            Packet::OnionResponse( OnionResponse {
                payload: InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
                    sendback_data: 12345,
                    nonce: gen_nonce(),
                    payload: vec![42; 123]
                })
            } ),
            Packet::OnionResponse( OnionResponse {
                payload: InnerOnionResponse::OnionDataResponse(OnionDataResponse {
                    nonce: gen_nonce(),
                    temporary_pk: gen_keypair().0,
                    payload: vec![42; 123]
                })
            } ),
            Packet::Data( Data { connection_id: 42, data: vec![13; 2031] } )
        ];
        for packet in test_packets {
            alice_codec.encode(packet.clone(), &mut buf).expect("Alice should encode");
            let res = bob_codec.decode(&mut buf).unwrap().expect("Bob should decode");
            assert_eq!(packet, res);

            bob_codec.encode(packet.clone(), &mut buf).expect("Bob should encode");
            let res = alice_codec.decode(&mut buf).unwrap().expect("Alice should decode");
            assert_eq!(packet, res);
        }
    }
    #[test]
    fn decode_encrypted_packet_incomplete() {
        let (alice_channel, _) = create_channels();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(b"\x00");
        let mut alice_codec = Codec::new(alice_channel);

        // not enought bytes to decode EncryptedPacket
        assert_eq!(alice_codec.decode(&mut buf).unwrap(), None);
    }
    #[test]
    fn decode_encrypted_packet_zero_length() {
        let (alice_channel, _) = create_channels();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(b"\x00\x00");
        let mut alice_codec = Codec::new(alice_channel);

        // not enought bytes to decode EncryptedPacket
        assert!(alice_codec.decode(&mut buf).is_err());
    }
    #[test]
    fn decode_encrypted_packet_wrong_key() {
        let (alice_channel, _) = create_channels();
        let (mallory_channel, _) = create_channels();

        let mut alice_codec = Codec::new(alice_channel);
        let mut mallory_codec = Codec::new(mallory_channel);

        let mut buf = BytesMut::new();
        let packet = Packet::PingRequest( PingRequest { ping_id: 4242 } );

        alice_codec.encode(packet.clone(), &mut buf).expect("Alice should encode");
        // Mallory cannot decode the payload of EncryptedPacket
        assert!(mallory_codec.decode(&mut buf).err().is_some());
    }
    fn encode_bytes_to_packet(channel: &Channel, bytes: &[u8]) -> Vec<u8> {
        // encrypt it
        let encrypted = channel.encrypt(bytes);

        // create EncryptedPacket
        let encrypted_packet = EncryptedPacket { payload: encrypted };

        // serialize EncryptedPacket to binary form
        let mut stack_buf = [0; MAX_TCP_ENC_PACKET_SIZE];
        let (_, encrypted_packet_size) = encrypted_packet.to_bytes((&mut stack_buf, 0)).unwrap();
        stack_buf[..encrypted_packet_size].to_vec()
    }
    #[test]
    fn decode_packet_imcomplete() {
        let (alice_channel, bob_channel) = create_channels();

        let mut buf = BytesMut::from(encode_bytes_to_packet(&alice_channel,b"\x00"));
        let mut bob_codec = Codec::new(bob_channel);

        // not enought bytes to decode Packet
        assert!(bob_codec.decode(&mut buf).err().is_some());
    }
    #[test]
    fn decode_packet_error() {
        let (alice_channel, bob_channel) = create_channels();

        let mut alice_codec = Codec::new(alice_channel);
        let mut bob_codec = Codec::new(bob_channel);

        let mut buf = BytesMut::new();

        // bad Data with connection id = 0x0F
        let packet = Packet::Data( Data { connection_id: 0x0F, data: vec![13; 42] } );

        alice_codec.encode(packet.clone(), &mut buf).expect("Alice should encode");
        assert!(bob_codec.decode(&mut buf).is_err());

        buf.clear();

        // bad Data with connection id = 0xF0
        let packet = Packet::Data( Data { connection_id: 0xF0, data: vec![13; 42] } );

        alice_codec.encode(packet.clone(), &mut buf).expect("Alice should encode");
        assert!(bob_codec.decode(&mut buf).is_err());
    }

    #[test]
    fn encode_packet_too_big() {
        let (alice_channel, _) = create_channels();
        let mut buf = BytesMut::new();
        let mut alice_codec = Codec::new(alice_channel);
        let packet = Packet::Data( Data { connection_id: 42, data: vec![13; 2032] } );

        // Alice cannot serialize Packet because it is too long
        assert!(alice_codec.encode(packet, &mut buf).is_err());
    }
}
