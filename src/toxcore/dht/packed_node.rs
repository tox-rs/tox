/*! A pair of Socket address & PublicKey.
This struct object is inserted into KBucket.
Socket address is something complex, because Ipv4, Ipv6, tcp and udp infomations are all contained
in this type.
*/

use nom::{le_u8, be_u16};

use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    SocketAddr,
};

use toxcore::binary_io::*;
use toxcore::crypto_core::*;

/** `PackedNode` format is a way to store the node info in a small yet easy to
parse format.

It is used in many places in Tox, e.g. in `DHT Send nodes`.

To store more than one node, simply append another on to the previous one:

`[packed node 1][packed node 2][...]`

Serialized Packed node:

Length | Content
------ | -------
1      | Ip type (v4 or v6)
4 or 16| IPv4 or IPv6 address
2      | port
32     | node ID

Size of serialized `PackedNode` is 39 bytes with IPv4 node info, or 51 with
IPv6 node info.

DHT module *should* use only UDP variants of Ip type, given that DHT runs
solely on the UDP.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PackedNode {
    /// Socket addr of node.
    pub saddr: SocketAddr,
    /// Public Key of the node.
    pub pk: PublicKey,
}

impl ToBytes for PackedNode {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_if_else!(self.saddr.is_ipv4(), gen_be_u8!(2), gen_be_u8!(10)) >>
            gen_call!(|buf, addr| IpAddr::to_bytes(addr, buf), &self.saddr.ip()) >>
            gen_be_u16!(self.saddr.port()) >>
            gen_slice!(self.pk.as_ref())
        )
    }
}

/** Deserialize bytes into `PackedNode`. Returns `Error` if deseralizing
failed.

Can fail if:

 - length is too short for given Ip Type
 - PK can't be parsed

Blindly trusts that provided `Ip Type` matches - i.e. if there are provided
51 bytes (which is length of `PackedNode` that contains IPv6), and `Ip Type`
says that it's actually IPv4, bytes will be parsed as if that was an IPv4
address.
*/

impl FromBytes for PackedNode {
    named!(from_bytes<PackedNode>, do_parse!(
        addr: switch!(le_u8,
            2  => map!(Ipv4Addr::from_bytes, IpAddr::V4) |
            10 => map!(Ipv6Addr::from_bytes, IpAddr::V6)
        ) >>
        port: be_u16 >>
        saddr: value!(SocketAddr::new(addr, port)) >>
        pk: call!(PublicKey::from_bytes) >>
        (PackedNode { saddr, pk })
    ));
}

impl PackedNode {
    /// Create new `PackedNode`.
    pub fn new(saddr: SocketAddr, pk: &PublicKey) -> Self {
        debug!(target: "PackedNode", "Creating new PackedNode.");
        trace!(target: "PackedNode", "With args: saddr: {:?}, PK: {:?}",
            &saddr, pk);

        PackedNode { saddr, pk: *pk }
    }

    /// Get an IP type from the `PackedNode`.
    pub fn ip_type(&self) -> u8 {
        trace!(target: "PackedNode", "Getting IP type from PackedNode.");
        trace!("With address: {:?}", self);
        if self.saddr.is_ipv4() {
            2
        }
        else {
            10
        }
    }

    /// Get an IP address from the `PackedNode`.
    pub fn ip(&self) -> IpAddr {
        trace!(target: "PackedNode", "Getting IP address from PackedNode.");
        trace!("With address: {:?}", self);
        self.saddr.ip()
    }

    /// Get a Socket address from the `PackedNode`.
    pub fn socket_addr(&self) -> SocketAddr {
        trace!(target: "PackedNode", "Getting Socket address from PackedNode.");
        trace!("With address: {:?}", self);
        self.saddr
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddrV4, SocketAddrV6};

    use quickcheck::{Arbitrary, Gen, quickcheck};

    // PackedNode::
    /// Valid, random `PackedNode`.
    impl Arbitrary for PackedNode {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let ipv4: bool = g.gen();

            let mut pk_bytes = [0; PUBLICKEYBYTES];
            g.fill_bytes(&mut pk_bytes);
            let pk = PublicKey(pk_bytes);

            if ipv4 {
                let addr = Ipv4Addr::new(g.gen(), g.gen(), g.gen(), g.gen());
                let saddr = SocketAddrV4::new(addr, g.gen());

                PackedNode::new(SocketAddr::V4(saddr), &pk)
            } else {
                let addr = Ipv6Addr::new(g.gen(), g.gen(), g.gen(), g.gen(),
                                        g.gen(), g.gen(), g.gen(), g.gen());
                let saddr = SocketAddrV6::new(addr, g.gen(), 0, 0);

                PackedNode::new(SocketAddr::V6(saddr), &pk)
            }
        }
    }

    #[test]
    fn packed_node_new_test() {
        fn with_params(saddr: SocketAddr) {
            let (pk, _sk) = gen_keypair();

            let a = PackedNode::new(saddr, &pk);
            let b = PackedNode {
                saddr,
                pk,
            };
            assert_eq!(a, b);
        }
        quickcheck(with_params as fn(SocketAddr));
    }
    #[test]
    fn packed_node_ip_type_test() {
        fn with_packed_node(pnode: PackedNode) {
            let a = pnode.ip_type();
            let b =
                if pnode.saddr.is_ipv4() {
                    2
                } else {
                    10
                };
            assert_eq!(a, b);
        }
        quickcheck(with_packed_node as fn(PackedNode));
    }
    #[test]
    fn packed_node_ip_test() {
        fn with_packed_node(pnode: PackedNode) {
            let a = pnode.ip();
            let b = pnode.saddr.ip();
            assert_eq!(a, b);
        }
        quickcheck(with_packed_node as fn(PackedNode));
    }
    #[test]
    fn packed_node_socket_addr_test() {
        fn with_packed_node(pnode: PackedNode) {
            let a = pnode.socket_addr();
            let b = pnode.saddr;
            assert_eq!(a, b);
        }
        quickcheck(with_packed_node as fn(PackedNode));
    }
}
