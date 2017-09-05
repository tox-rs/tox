/*
    Copyright © 2017 Zetok Zalbavar <zetok@openmailbox.org>

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


//! Functionality needed to work as a DHT node.
//!
//! Made on top of `dht` and `network` modules.

//use tokio_core::net::UdpCodec;

use tokio_core::net::UdpSocket;
use tokio_core::reactor::Core;

use std::io::{self, ErrorKind};

use toxcore::binary_io::ToBytes;
use toxcore::crypto_core::*;
use toxcore::dht::*;


/** Own DHT node data.
*/
pub struct DhtNode {
    dht_secret_key: Box<SecretKey>,
    dht_public_key: Box<PublicKey>,
    // TODO: move it somewhere "down" (or elsewhere) in implementation?
    reactor: Box<Core>,

    // TODO: have a table with precomputed keys for all known NetNodes?
    // TODO: add k-bucket?
}


impl DhtNode {
    /** Create new DhtNode instance.

    Note: a new instance generates new DHT public and secret keys.

    DHT PublicKey and SecretKey are supposed to be ephemeral.
    */
    pub fn new() -> io::Result<Self> {
        if !crypto_init() {
            return Err(io::Error::new(ErrorKind::Other,
                       "Crypto initialization failed."));
        }

        let (pk, sk) = gen_keypair();
        let reactor = Core::new()?;

        debug!("Created new DhtNode instance");

        Ok(DhtNode {
            dht_secret_key: Box::new(sk),
            dht_public_key: Box::new(pk),
            reactor: Box::new(reactor),
        })
    }

    /** Request nodes from a peer. Peer might or might not even reply.
    */
    // TODO: track requests
    pub fn request_nodes(&mut self,
                         socket: UdpSocket,
                         peer: &PackedNode)
        -> io::Result<UdpSocket>
    {
        // request for nodes that are close to our own DHT PK
        let getn_req = GetNodes::new(&self.dht_public_key).as_packet();
        let shared_secret = &encrypt_precompute(&peer.pk, &self.dht_secret_key);
        let nonce = &gen_nonce();
        let dht_packet = DhtPacket::new(shared_secret,
                                        &self.dht_public_key,
                                        nonce,
                                        getn_req).to_bytes();

        let future_send = socket.send_dgram(dht_packet, peer.saddr);
        let (udpsocket, _) = self.reactor.as_mut().run(future_send)?;
        Ok(udpsocket)
    }


}





#[cfg(test)]
mod test {
    use futures::future::Future;
    use tokio_core::reactor::Timeout;

    use std::io;
    use std::time::Duration;

    use toxcore::binary_io::*;
    use toxcore::dht::*;
    use toxcore::network::*;
    use toxcore::packet_kind::PacketKind;
    use toxcore::dht_node::DhtNode;

    /// Bind to this IpAddr.
    // TODO: rename
    //const SOCKETADDR: IpAddr = IpAddr::V6(Ipv6Addr::new(0,0,0,0,0,0,0,0));
    // NOTE: apparently using `0.0.0.0`/`::` is not allowed on CIs like
    //       appveyor / travis
    const SOCKET_ADDR: &'static str = "127.0.0.1";

    #[test]
    fn dht_node_new() {
        let _ = DhtNode::new().unwrap();
    }


    #[test]
    fn dht_node_request_nodes() {
        let mut server = DhtNode::new().unwrap();
        let server_socket = bind_udp(SOCKET_ADDR.parse().unwrap(),
                                    PORT_MIN..PORT_MAX,
                                    &server.reactor.handle())
            .unwrap();
        let server_node = PackedNode::new(
            true,
            server_socket.local_addr().unwrap(),
            &server.dht_public_key);

        let mut client = DhtNode::new().unwrap();
        let client_socket = bind_udp(SOCKET_ADDR.parse().unwrap(),
                                    PORT_MIN..PORT_MAX,
                                    &client.reactor.handle())
            .unwrap();

        let _client_socket = client.request_nodes(client_socket, &server_node);

        let mut recv_buf = [0; MAX_UDP_PACKET_SIZE];
        let timeout = Timeout::new(Duration::from_secs(10),
            &server.reactor.handle()).unwrap();
        let future_recv = server_socket.recv_dgram(&mut recv_buf[..])
            .map(Ok)
            .select(timeout.map(Err))
            .then(|res| {
                match res {
                    Ok((Err(()), _received)) =>
                        Err(io::Error::new(io::ErrorKind::TimedOut,
                            "timed out waiting for receive")),
                    Err((e, _other)) => Err(e),
                    Ok((r, _timeout)) => Ok(r),
                }
            });

        let received = server.reactor.as_mut().run(future_recv).unwrap();
        let (_server_socket, recv_buf, size, _saddr) = received.unwrap();
        assert!(size != 0);

        let recv_packet = DhtPacket::from_bytes(&recv_buf[..size]).unwrap();
        let payload = recv_packet.get_packet(&server.dht_secret_key)
            .expect("Failed to decrypt payload");
        assert_eq!(PacketKind::GetN, payload.kind());

        let pk = match payload {
            DhtPacketT::GetNodes(g) => g.pk,
            _ => panic!("Not a GetNodes packet"),
        };

        assert_eq!(pk, *client.dht_public_key);
    }
}
