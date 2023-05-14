#[macro_use]
extern crate log;

use anyhow::Error;
use tox_core::relay::server::{tcp_run, Server};
use tox_core::stats::Stats;
use tox_crypto::*;

use tokio::net::TcpListener;

const TCP_CONNECTIONS_LIMIT: usize = 1024;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    // Server constant PK for examples/tests
    let server_pk = PublicKey::from([
        177, 185, 54, 250, 10, 168, 174, 148, 0, 93, 99, 13, 131, 131, 239, 193, 129, 141, 80, 158, 50, 133, 100, 182,
        179, 183, 234, 116, 142, 102, 53, 38,
    ]);
    let server_sk = SecretKey::from([
        74, 163, 57, 111, 32, 145, 19, 40, 44, 145, 233, 210, 173, 67, 88, 217, 140, 147, 14, 176, 106, 255, 54, 249,
        159, 12, 18, 39, 123, 29, 125, 230,
    ]);

    let addr: std::net::SocketAddr = "0.0.0.0:12345".parse().unwrap();

    info!("Listening on addr={}, {:?}", addr, &server_pk);

    let server = Server::new();

    let stats = Stats::new();
    let listener = TcpListener::bind(&addr).await.unwrap();
    tcp_run(&server, listener, server_sk, stats, TCP_CONNECTIONS_LIMIT)
        .await
        .map_err(Error::from)
}
