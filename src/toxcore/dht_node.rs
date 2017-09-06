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
    /// contains nodes close to own DHT PK
    kbucket: Box<Kbucket>,
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
        let kbucket = Kbucket::new(KBUCKET_BUCKETS, &pk);

        debug!("Created new DhtNode instance");

        Ok(DhtNode {
            dht_secret_key: Box::new(sk),
            dht_public_key: Box::new(pk),
            kbucket: Box::new(kbucket),
            reactor: Box::new(reactor),
        })
    }


    /** Try to add nodes to [Kbucket](../dht/struct.Kbucket.html).

    Wrapper around Kbucket's method.
    */
    pub fn try_add(&mut self, node: &PackedNode) -> bool {
        self.kbucket.try_add(node)
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

    /** Send nodes close to requested PK.

    Can fail if Kbucket is empty.
    */
    pub fn send_nodes(&mut self,
                      socket: UdpSocket,
                      peer: &PackedNode,
                      request: &GetNodes) -> io::Result<UdpSocket>
    {
        let close_nodes = self.kbucket.get_closest(&peer.pk);
        if close_nodes.is_empty() {
            return Err(io::Error::new(ErrorKind::Other, "no nodes in kbucket"))
        }

        let to_send = match SendNodes::from_request(request, close_nodes)
            .map(|s| s.into_packet())
        {

            Some(s) => s,
            None => return Err(io::Error::new(ErrorKind::Other,
                        "failed to create SendNodes response")),
        };

        let shared_secret = &encrypt_precompute(&peer.pk, &self.dht_secret_key);
        let nonce = &gen_nonce();
        let dht_packet = DhtPacket::new(shared_secret,
                                        &self.dht_public_key,
                                        nonce,
                                        to_send).to_bytes();

        let future_send = socket.send_dgram(dht_packet, peer.saddr);
        let (udpsocket, _) = self.reactor.as_mut().run(future_send)?;
        Ok(udpsocket)
    }

}





#[cfg(test)]
mod test {
    use futures::future::Future;
    use tokio_core::reactor::Timeout;

    use std::time::Duration;

    use toxcore::binary_io::*;
    use toxcore::dht::*;
    use toxcore::network::*;
    use toxcore::packet_kind::PacketKind;
    use toxcore::dht_node::DhtNode;

    use toxcore_tests::quickcheck::{quickcheck, TestResult};

    /// Bind to this IpAddr.
    // TODO: rename
    //const SOCKETADDR: IpAddr = IpAddr::V6(Ipv6Addr::new(0,0,0,0,0,0,0,0));
    // NOTE: apparently using `0.0.0.0`/`::` is not allowed on CIs like
    //       appveyor / travis
    const SOCKET_ADDR: &'static str = "127.0.0.1";

    /// Provide:
    ///   - mut DhtNode $name
    ///   - socket $name_socket
    macro_rules! node_socket {
        ($($name:ident, $name_socket:ident),+) => ($(
            let mut $name = DhtNode::new().unwrap();
            let $name_socket = bind_udp(SOCKET_ADDR.parse().unwrap(),
                                        // make port range sufficiently big
                                        2048..65000,
                                        &$name.reactor.handle())
                .expect("failed to bind to socket");
        )+)
    }

    /// Add timeout to the future, and panic upon timing out.
    ///
    /// If not specified, default timeout = 5s.
    macro_rules! add_timeout {
        ($f:expr, $handle:expr) => (
            add_timeout!($f, $handle, 5)
        );

        ($f:expr, $handle:expr, $seconds:expr) => (
            $f.map(Ok)
              .select(
                Timeout::new(Duration::from_secs($seconds), $handle)
                    .unwrap()
                    .map(Err))
              .then(|res| {
                  match res {
                      Ok((Err(()), _received)) =>
                              panic!("timed out"),
                      Err((e, _other)) => panic!("{}", e),
                      Ok((f, _timeout)) => f,
                  }
              })
        );
    }



    #[test]
    fn dht_node_new() {
        let _ = DhtNode::new().unwrap();
    }

    #[test]
    fn dht_node_try_add_to_empty() {
        fn with_nodes(pns: Vec<PackedNode>) {
            let mut dhtn = DhtNode::new().unwrap();
            let mut kbuc = Kbucket::new(KBUCKET_BUCKETS, &dhtn.dht_public_key);

            for pn in &pns {
                assert_eq!(dhtn.try_add(pn), kbuc.try_add(pn));
                assert_eq!(kbuc, *dhtn.kbucket);
            }
        }
        quickcheck(with_nodes as fn(Vec<PackedNode>));
    }


    #[test]
    fn dht_node_request_nodes() {
        node_socket!(server, server_socket,
                     client, client_socket);

        let server_node = PackedNode::new(true,
            server_socket.local_addr().unwrap(),
            &server.dht_public_key);

        let mut recv_buf = [0; MAX_UDP_PACKET_SIZE];

        let _client_socket = client.request_nodes(client_socket, &server_node);

        let future_recv = server_socket.recv_dgram(&mut recv_buf[..]);
        let future_recv = add_timeout!(future_recv, &server.reactor.handle());

        let received = server.reactor.as_mut().run(future_recv).unwrap();
        let (_server_socket, recv_buf, size, _saddr) = received;
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

    #[test]
    fn dht_node_send_nodes() {
        fn with_nodes(pns: Vec<PackedNode>, gn: GetNodes) -> TestResult {
            if pns.is_empty() { return TestResult::discard() }

            node_socket!(server, server_socket,
                        client, client_socket);

            let client_node = PackedNode::new(true,
                client_socket.local_addr()
                    .expect("failed to get saddr"),
                &client.dht_public_key);

            for pn in &pns {
                drop(server.try_add(pn));
            }

            drop(server.send_nodes(server_socket, &client_node, &gn)
                .expect("Failed to send nodes"));

            let mut recv_buf = [0; MAX_UDP_PACKET_SIZE];

            let future_recv = client_socket.recv_dgram(&mut recv_buf[..]);
            let future_recv = add_timeout!(future_recv, &client.reactor.handle());

            let received = client.reactor.as_mut().run(future_recv).unwrap();
            let (_client_socket, recv_buf, size, _saddr) = received;
            assert!(size != 0);

            let recv_packet = DhtPacket::from_bytes(&recv_buf[..size])
                .expect("failed to parse as DhtPacket");
            let payload = recv_packet.get_packet(&client.dht_secret_key)
                .expect("Failed to decrypt payload");
            assert_eq!(PacketKind::SendN, payload.kind());

            let sn = match payload {
                DhtPacketT::SendNodes(s) => s,
                _ => panic!("Not a SendNodes packet"),
            };

            assert!(!sn.nodes.is_empty());
            assert_eq!(sn.id, gn.id);
            TestResult::passed()
        }
        quickcheck(with_nodes as fn(Vec<PackedNode>, GetNodes) -> TestResult);
    }



}
