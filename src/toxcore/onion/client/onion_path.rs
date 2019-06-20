//! Onion path definition.

use std::net::SocketAddr;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packed_node::*;
use crate::toxcore::ip_port::*;
use crate::toxcore::onion::packet::*;
use crate::toxcore::tcp::packet::OnionRequest;

/// Whether the first node of onion path is a TCP relay or DHT node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnionPathType {
    /// The first node of onion path is a TCP relay.
    TCP,
    /// The first node of onion path is a DHT node.
    UDP
}

/// Onion path is identified by 3 public keys of nodes it consists of.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnionPathId {
    /// Public keys of nodes the path consists of.
    pub keys: [PublicKey; 3],
    /// Whether the first node is a TCP relay or DHT node.
    pub path_type: OnionPathType,
}

/// Node for onion path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionPathNode {
    /// Node's `PublicKey`.
    pub public_key: PublicKey,
    /// Temporary `PublicKey` for this node.
    pub temporary_public_key: PublicKey,
    /// Temporary `PrecomputedKey` to encrypt packets for this node.
    pub temporary_precomputed_key: PrecomputedKey,
    /// Node's IP address.
    pub saddr: SocketAddr,
}

impl OnionPathNode {
    /// Create new `OnionPathNode` from `PackedNode` generating random key pair
    /// to encrypt packets intended for this node.
    pub fn new(node: PackedNode) -> Self {
        let (temporary_public_key, temporary_secret_key) = gen_keypair();
        let temporary_precomputed_key = precompute(&node.pk, &temporary_secret_key);
        OnionPathNode {
            public_key: node.pk,
            temporary_public_key,
            temporary_precomputed_key,
            saddr: node.saddr,
        }
    }
}

/// Onion path that consists of 3 random nodes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionPath {
    /// Random path nodes.
    pub nodes: [OnionPathNode; 3],
    /// Whether the first node is a TCP relay or DHT node.
    pub path_type: OnionPathType,
}

impl OnionPath {
    /// Create new `OnionPath` from 3 `PackedNode`s generating random key pair
    /// for each node.
    pub fn new(nodes: [PackedNode; 3], path_type: OnionPathType) -> Self {
        OnionPath {
            nodes: [
                OnionPathNode::new(nodes[0]),
                OnionPathNode::new(nodes[1]),
                OnionPathNode::new(nodes[2]),
            ],
            path_type,
        }
    }

    /// Array of 3 public keys of nodes the path consists of.
    pub fn id(&self) -> OnionPathId {
        let keys = [
            self.nodes[0].public_key,
            self.nodes[1].public_key,
            self.nodes[2].public_key,
        ];
        OnionPathId {
            keys,
            path_type: self.path_type,
        }
    }

    /// Create `OnionRequest0` packet from `InnerOnionRequest` that should be
    /// sent through this path.
    pub fn create_udp_onion_request(&self, destination: SocketAddr, inner_onion_request: InnerOnionRequest) -> OnionRequest0 {
        let nonce = gen_nonce();
        let mut buf = [0; ONION_MAX_PACKET_SIZE];

        let payload = OnionRequest2Payload {
            ip_port: IpPort::from_udp_saddr(destination),
            inner: inner_onion_request,
        };
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let encrypted = seal_precomputed(&buf[..size], &nonce, &self.nodes[2].temporary_precomputed_key);

        let payload = OnionRequest1Payload {
            ip_port: IpPort::from_udp_saddr(self.nodes[2].saddr),
            temporary_pk: self.nodes[2].temporary_public_key,
            inner: encrypted,
        };
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let encrypted = seal_precomputed(&buf[..size], &nonce, &self.nodes[1].temporary_precomputed_key);

        let payload = OnionRequest0Payload {
            ip_port: IpPort::from_udp_saddr(self.nodes[1].saddr),
            temporary_pk: self.nodes[1].temporary_public_key,
            inner: encrypted,
        };
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let encrypted = seal_precomputed(&buf[..size], &nonce, &self.nodes[0].temporary_precomputed_key);

        OnionRequest0 {
            nonce,
            temporary_pk: self.nodes[0].temporary_public_key,
            payload: encrypted
        }
    }

    /// Create `OnionRequest` packet from `InnerOnionRequest` that should be
    /// sent through this path.
    pub fn create_tcp_onion_request(&self, destination: SocketAddr, inner_onion_request: InnerOnionRequest) -> OnionRequest {
        let nonce = gen_nonce();
        let mut buf = [0; ONION_MAX_PACKET_SIZE];

        let payload = OnionRequest2Payload {
            ip_port: IpPort::from_udp_saddr(destination),
            inner: inner_onion_request,
        };
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let encrypted = seal_precomputed(&buf[..size], &nonce, &self.nodes[2].temporary_precomputed_key);

        let payload = OnionRequest1Payload {
            ip_port: IpPort::from_udp_saddr(self.nodes[2].saddr),
            temporary_pk: self.nodes[2].temporary_public_key,
            inner: encrypted,
        };
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let encrypted = seal_precomputed(&buf[..size], &nonce, &self.nodes[1].temporary_precomputed_key);

        OnionRequest {
            nonce,
            ip_port: IpPort::from_udp_saddr(self.nodes[1].saddr),
            temporary_pk: self.nodes[1].temporary_public_key,
            payload: encrypted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onion_path_node_new() {
        let saddr = "127.0.0.1:12345".parse().unwrap();
        let (pk, sk) = gen_keypair();
        let node = OnionPathNode::new(PackedNode::new(saddr, &pk));
        let precomputed = precompute(&node.temporary_public_key, &sk);
        assert_eq!(node.saddr, saddr);
        assert_eq!(node.public_key, pk);
        assert_eq!(node.temporary_precomputed_key, precomputed);
    }

    #[test]
    fn onion_path_id() {
        let saddr_1 = "127.0.0.1:12345".parse().unwrap();
        let saddr_2 = "127.0.0.1:12346".parse().unwrap();
        let saddr_3 = "127.0.0.1:12347".parse().unwrap();
        let pk_1 = gen_keypair().0;
        let pk_2 = gen_keypair().0;
        let pk_3 = gen_keypair().0;
        let path = OnionPath::new([
            PackedNode::new(saddr_1, &pk_1),
            PackedNode::new(saddr_2, &pk_2),
            PackedNode::new(saddr_3, &pk_3),
        ], OnionPathType::UDP);
        assert_eq!(path.id(), OnionPathId {
            keys: [pk_1, pk_2, pk_3],
            path_type: OnionPathType::UDP,
        });
    }

    #[test]
    fn onion_path_create_udp_onion_request() {
        let saddr_1 = "127.0.0.1:12345".parse().unwrap();
        let saddr_2 = "127.0.0.1:12346".parse().unwrap();
        let saddr_3 = "127.0.0.1:12347".parse().unwrap();
        let pk_1 = gen_keypair().0;
        let pk_2 = gen_keypair().0;
        let pk_3 = gen_keypair().0;
        let path = OnionPath::new([
            PackedNode::new(saddr_1, &pk_1),
            PackedNode::new(saddr_2, &pk_2),
            PackedNode::new(saddr_3, &pk_3),
        ], OnionPathType::UDP);
        let inner_onion_request = InnerOnionRequest::InnerOnionAnnounceRequest(InnerOnionAnnounceRequest {
            nonce: gen_nonce(),
            pk: gen_keypair().0,
            payload: vec![42; 123],
        });
        let destination = "127.0.0.1:12348".parse().unwrap();
        let onion_request = path.create_udp_onion_request(destination, inner_onion_request.clone());

        assert_eq!(onion_request.temporary_pk, path.nodes[0].temporary_public_key);
        let payload = onion_request.get_payload(&path.nodes[0].temporary_precomputed_key).unwrap();
        assert_eq!(payload.ip_port, IpPort::from_udp_saddr(saddr_2));
        assert_eq!(payload.temporary_pk, path.nodes[1].temporary_public_key);
        let payload = open_precomputed(&payload.inner, &onion_request.nonce, &path.nodes[1].temporary_precomputed_key).unwrap();
        let payload = OnionRequest1Payload::from_bytes(&payload).unwrap().1;
        assert_eq!(payload.ip_port, IpPort::from_udp_saddr(saddr_3));
        assert_eq!(payload.temporary_pk, path.nodes[2].temporary_public_key);
        let payload = open_precomputed(&payload.inner, &onion_request.nonce, &path.nodes[2].temporary_precomputed_key).unwrap();
        let payload = OnionRequest2Payload::from_bytes(&payload).unwrap().1;
        assert_eq!(payload.ip_port, IpPort::from_udp_saddr(destination));
        assert_eq!(payload.inner, inner_onion_request);
    }

    #[test]
    fn onion_path_create_tcp_onion_request() {
        let saddr_1 = "127.0.0.1:12345".parse().unwrap();
        let saddr_2 = "127.0.0.1:12346".parse().unwrap();
        let saddr_3 = "127.0.0.1:12347".parse().unwrap();
        let pk_1 = gen_keypair().0;
        let pk_2 = gen_keypair().0;
        let pk_3 = gen_keypair().0;
        let path = OnionPath::new([
            PackedNode::new(saddr_1, &pk_1),
            PackedNode::new(saddr_2, &pk_2),
            PackedNode::new(saddr_3, &pk_3),
        ], OnionPathType::UDP);
        let inner_onion_request = InnerOnionRequest::InnerOnionAnnounceRequest(InnerOnionAnnounceRequest {
            nonce: gen_nonce(),
            pk: gen_keypair().0,
            payload: vec![42; 123],
        });
        let destination = "127.0.0.1:12348".parse().unwrap();
        let onion_request = path.create_tcp_onion_request(destination, inner_onion_request.clone());

        assert_eq!(onion_request.temporary_pk, path.nodes[1].temporary_public_key);
        assert_eq!(onion_request.ip_port, IpPort::from_udp_saddr(saddr_2));
        let payload = open_precomputed(&onion_request.payload, &onion_request.nonce, &path.nodes[1].temporary_precomputed_key).unwrap();
        let payload = OnionRequest1Payload::from_bytes(&payload).unwrap().1;
        assert_eq!(payload.ip_port, IpPort::from_udp_saddr(saddr_3));
        assert_eq!(payload.temporary_pk, path.nodes[2].temporary_public_key);
        let payload = open_precomputed(&payload.inner, &onion_request.nonce, &path.nodes[2].temporary_precomputed_key).unwrap();
        let payload = OnionRequest2Payload::from_bytes(&payload).unwrap().1;
        assert_eq!(payload.ip_port, IpPort::from_udp_saddr(destination));
        assert_eq!(payload.inner, inner_onion_request);
    }
}
