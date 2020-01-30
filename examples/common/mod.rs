use std::net::SocketAddr;

use tokio::net::UdpSocket;

pub const BOOTSTRAP_NODES: [(&str, &str); 9] = [
    // Impyy
    ("1D5A5F2F5D6233058BF0259B09622FB40B482E4FA0931EB8FD3AB8E7BF7DAF6F", "198.98.51.198:33445"),
    // nurupo
    ("F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67", "67.215.253.85:33445"),
    // Manolis
    ("461FA3776EF0FA655F1A05477DF1B3B614F7D6B124F7DB1DD4FE3C08B03B640F", "130.133.110.14:33445"),
    // Busindre
    ("A179B09749AC826FF01F37A9613F6B57118AE014D4196A0E1105A98F93A54702", "205.185.116.116:33445"),
    // ray65536
    ("8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832", "85.172.30.117:33445"),
    // fluke571
    ("3CEE1F054081E7A011234883BC4FC39F661A55B73637A5AC293DDF1251D9432B", "194.249.212.109:33445"),
    // MAH69K
    ("DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43", "185.25.116.107:33445"),
    // clearmartin
    ("CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707", "46.101.197.175:443"),
    // tastytea
    ("2B2137E094F743AC8BD44652C55F41DFACC502F125E99E4FE24D40537489E32F", "5.189.176.217:5190"),
];

/// Bind a UDP listener to the socket address.
pub async fn bind_socket(addr: SocketAddr) -> UdpSocket {
    let socket = UdpSocket::bind(&addr)
        .await
        .expect("Failed to bind UDP socket");

    socket.set_broadcast(true).expect("set_broadcast call failed");
    if addr.is_ipv6() {
        socket.set_multicast_loop_v6(true)
            .expect("set_multicast_loop_v6 call failed");
    }

    socket
}

