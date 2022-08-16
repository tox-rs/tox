//! Onion path definition.

use std::net::SocketAddr;

use crypto_box::{SalsaBox, aead::{Aead, AeadCore}};
use rand::thread_rng;
use tox_binary_io::*;
use tox_crypto::*;
use tox_packet::dht::packed_node::*;
use tox_packet::ip_port::*;
use tox_packet::onion::*;
use tox_packet::relay::OnionRequest;

/// Whether the first node of onion path is a TCP relay or DHT node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnionPathType {
    /// The first node of onion path is a TCP relay.
    Tcp,
    /// The first node of onion path is a DHT node.
    Udp
}

/// Onion path is identified by 3 public keys of nodes it consists of.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionPathId {
    /// Public keys of nodes the path consists of.
    pub keys: [PublicKey; 3],
    /// Whether the first node is a TCP relay or DHT node.
    pub path_type: OnionPathType,
}

/// Node for onion path.
#[derive(Clone)]
pub struct OnionPathNode {
    /// Node's `PublicKey`.
    pub public_key: PublicKey,
    /// Temporary `PublicKey` for this node.
    pub temporary_public_key: PublicKey,
    /// Temporary `SalsaBox` to encrypt packets for this node.
    pub temporary_precomputed_key: SalsaBox,
    /// Node's IP address.
    pub saddr: SocketAddr,
}

impl OnionPathNode {
    /// Create new `OnionPathNode` from `PackedNode` generating random key pair
    /// to encrypt packets intended for this node.
    pub fn new(node: PackedNode) -> Self {
        let temporary_secret_key = SecretKey::generate(&mut thread_rng());
        let temporary_public_key = temporary_secret_key.public_key();
        let temporary_precomputed_key = SalsaBox::new(&node.pk, &temporary_secret_key);
        OnionPathNode {
            public_key: node.pk,
            temporary_public_key,
            temporary_precomputed_key,
            saddr: node.saddr,
        }
    }
}

/// Onion path that consists of 3 random nodes.
#[derive(Clone)]
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
        let [node_1, node_2, node_3] = nodes;
        OnionPath {
            nodes: [
                OnionPathNode::new(node_1),
                OnionPathNode::new(node_2),
                OnionPathNode::new(node_3),
            ],
            path_type,
        }
    }

    /// Array of 3 public keys of nodes the path consists of.
    pub fn id(&self) -> OnionPathId {
        let keys = [
            self.nodes[0].public_key.clone(),
            self.nodes[1].public_key.clone(),
            self.nodes[2].public_key.clone(),
        ];
        OnionPathId {
            keys,
            path_type: self.path_type,
        }
    }

    /// Create `OnionRequest0` packet from `InnerOnionRequest` that should be
    /// sent through this path.
    pub fn create_udp_onion_request(&self, destination: SocketAddr, inner_onion_request: InnerOnionRequest) -> OnionRequest0 {
        let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
        let mut buf = [0; ONION_MAX_PACKET_SIZE];

        let payload = OnionRequest2Payload {
            ip_port: IpPort::from_udp_saddr(destination),
            inner: inner_onion_request,
        };
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let encrypted = self.nodes[2].temporary_precomputed_key.encrypt(&nonce, &buf[..size]).unwrap();

        let payload = OnionRequest1Payload {
            ip_port: IpPort::from_udp_saddr(self.nodes[2].saddr),
            temporary_pk: self.nodes[2].temporary_public_key.clone(),
            inner: encrypted,
        };
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let encrypted = self.nodes[1].temporary_precomputed_key.encrypt(&nonce, &buf[..size]).unwrap();

        let payload = OnionRequest0Payload {
            ip_port: IpPort::from_udp_saddr(self.nodes[1].saddr),
            temporary_pk: self.nodes[1].temporary_public_key.clone(),
            inner: encrypted,
        };
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let encrypted = self.nodes[0].temporary_precomputed_key.encrypt(&nonce, &buf[..size]).unwrap();

        OnionRequest0 {
            nonce: nonce.into(),
            temporary_pk: self.nodes[0].temporary_public_key.clone(),
            payload: encrypted
        }
    }

    /// Create `OnionRequest` packet from `InnerOnionRequest` that should be
    /// sent through this path.
    pub fn create_tcp_onion_request(&self, destination: SocketAddr, inner_onion_request: InnerOnionRequest) -> OnionRequest {
        let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
        let mut buf = [0; ONION_MAX_PACKET_SIZE];

        let payload = OnionRequest2Payload {
            ip_port: IpPort::from_udp_saddr(destination),
            inner: inner_onion_request,
        };
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let encrypted = self.nodes[2].temporary_precomputed_key.encrypt(&nonce, &buf[..size]).unwrap();

        let payload = OnionRequest1Payload {
            ip_port: IpPort::from_udp_saddr(self.nodes[2].saddr),
            temporary_pk: self.nodes[2].temporary_public_key.clone(),
            inner: encrypted,
        };
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let encrypted = self.nodes[1].temporary_precomputed_key.encrypt(&nonce, &buf[..size]).unwrap();

        OnionRequest {
            nonce: nonce.into(),
            ip_port: IpPort::from_udp_saddr(self.nodes[1].saddr),
            temporary_pk: self.nodes[1].temporary_public_key.clone(),
            payload: encrypted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_box::{SalsaBox, aead::{AeadCore, generic_array::typenum::marker_traits::Unsigned}};

    #[test]
    fn onion_path_node_new() {
        let saddr = "127.0.0.1:12345".parse().unwrap();
        let pk = SecretKey::generate(&mut thread_rng()).public_key();
        let node = OnionPathNode::new(PackedNode::new(saddr, pk.clone()));
        assert_eq!(node.saddr, saddr);
        assert_eq!(node.public_key, pk);
    }

    #[test]
    fn onion_path_id() {
        let mut rng = thread_rng();
        let saddr_1 = "127.0.0.1:12345".parse().unwrap();
        let saddr_2 = "127.0.0.1:12346".parse().unwrap();
        let saddr_3 = "127.0.0.1:12347".parse().unwrap();
        let pk_1 = SecretKey::generate(&mut rng).public_key();
        let pk_2 = SecretKey::generate(&mut rng).public_key();
        let pk_3 = SecretKey::generate(&mut rng).public_key();
        let path = OnionPath::new([
            PackedNode::new(saddr_1, pk_1.clone()),
            PackedNode::new(saddr_2, pk_2.clone()),
            PackedNode::new(saddr_3, pk_3.clone()),
        ], OnionPathType::Udp);
        assert_eq!(path.id(), OnionPathId {
            keys: [pk_1, pk_2, pk_3],
            path_type: OnionPathType::Udp,
        });
    }

    #[test]
    fn onion_path_create_udp_onion_request() {
        let mut rng = thread_rng();
        let saddr_1 = "127.0.0.1:12345".parse().unwrap();
        let saddr_2 = "127.0.0.1:12346".parse().unwrap();
        let saddr_3 = "127.0.0.1:12347".parse().unwrap();
        let pk_1 = SecretKey::generate(&mut rng).public_key();
        let pk_2 = SecretKey::generate(&mut rng).public_key();
        let pk_3 = SecretKey::generate(&mut rng).public_key();
        let path = OnionPath::new([
            PackedNode::new(saddr_1, pk_1),
            PackedNode::new(saddr_2, pk_2),
            PackedNode::new(saddr_3, pk_3),
        ], OnionPathType::Udp);
        let inner_onion_request = InnerOnionRequest::InnerOnionAnnounceRequest(InnerOnionAnnounceRequest {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            pk: SecretKey::generate(&mut rng).public_key(),
            payload: vec![42; 123],
        });
        let destination = "127.0.0.1:12348".parse().unwrap();
        let onion_request = path.create_udp_onion_request(destination, inner_onion_request.clone());

        assert_eq!(onion_request.temporary_pk, path.nodes[0].temporary_public_key);
        let payload = onion_request.get_payload(&path.nodes[0].temporary_precomputed_key).unwrap();
        assert_eq!(payload.ip_port, IpPort::from_udp_saddr(saddr_2));
        assert_eq!(payload.temporary_pk, path.nodes[1].temporary_public_key);
        let payload = path.nodes[1].temporary_precomputed_key.decrypt((&onion_request.nonce).into(), payload.inner.as_slice()).unwrap();
        let payload = OnionRequest1Payload::from_bytes(&payload).unwrap().1;
        assert_eq!(payload.ip_port, IpPort::from_udp_saddr(saddr_3));
        assert_eq!(payload.temporary_pk, path.nodes[2].temporary_public_key);
        let payload = path.nodes[2].temporary_precomputed_key.decrypt((&onion_request.nonce).into(), payload.inner.as_slice()).unwrap();
        let payload = OnionRequest2Payload::from_bytes(&payload).unwrap().1;
        assert_eq!(payload.ip_port, IpPort::from_udp_saddr(destination));
        assert_eq!(payload.inner, inner_onion_request);
    }

    #[test]
    fn onion_path_create_tcp_onion_request() {
        let mut rng = thread_rng();
        let saddr_1 = "127.0.0.1:12345".parse().unwrap();
        let saddr_2 = "127.0.0.1:12346".parse().unwrap();
        let saddr_3 = "127.0.0.1:12347".parse().unwrap();
        let pk_1 = SecretKey::generate(&mut rng).public_key();
        let pk_2 = SecretKey::generate(&mut rng).public_key();
        let pk_3 = SecretKey::generate(&mut rng).public_key();
        let path = OnionPath::new([
            PackedNode::new(saddr_1, pk_1),
            PackedNode::new(saddr_2, pk_2),
            PackedNode::new(saddr_3, pk_3),
        ], OnionPathType::Udp);
        let inner_onion_request = InnerOnionRequest::InnerOnionAnnounceRequest(InnerOnionAnnounceRequest {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            pk: SecretKey::generate(&mut rng).public_key(),
            payload: vec![42; 123],
        });
        let destination = "127.0.0.1:12348".parse().unwrap();
        let onion_request = path.create_tcp_onion_request(destination, inner_onion_request.clone());

        assert_eq!(onion_request.temporary_pk, path.nodes[1].temporary_public_key);
        assert_eq!(onion_request.ip_port, IpPort::from_udp_saddr(saddr_2));
        let payload = path.nodes[1].temporary_precomputed_key.decrypt((&onion_request.nonce).into(), onion_request.payload.as_slice()).unwrap();
        let payload = OnionRequest1Payload::from_bytes(&payload).unwrap().1;
        assert_eq!(payload.ip_port, IpPort::from_udp_saddr(saddr_3));
        assert_eq!(payload.temporary_pk, path.nodes[2].temporary_public_key);
        let payload = path.nodes[2].temporary_precomputed_key.decrypt((&onion_request.nonce).into(), payload.inner.as_slice()).unwrap();
        let payload = OnionRequest2Payload::from_bytes(&payload).unwrap().1;
        assert_eq!(payload.ip_port, IpPort::from_udp_saddr(destination));
        assert_eq!(payload.inner, inner_onion_request);
    }
}
