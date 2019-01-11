#[macro_use]
extern crate log;

use tox::toxcore::crypto_core::*;
use tox::toxcore::tcp::server::{Server, ServerExt};
use tox::toxcore::stats::Stats;

use tokio::net::TcpListener;
use futures::Future;

const TCP_CONNECTIONS_LIMIT: usize = 1024;

fn main() {
    env_logger::init();
    // Server constant PK for examples/tests
    // Use `gen_keypair` to generate random keys
    let server_pk = PublicKey([177, 185, 54, 250, 10, 168, 174,
                            148, 0, 93, 99, 13, 131, 131, 239,
                            193, 129, 141, 80, 158, 50, 133, 100,
                            182, 179, 183, 234, 116, 142, 102, 53, 38]);
    let server_sk = SecretKey([74, 163, 57, 111, 32, 145, 19, 40,
                            44, 145, 233, 210, 173, 67, 88, 217,
                            140, 147, 14, 176, 106, 255, 54, 249,
                            159, 12, 18, 39, 123, 29, 125, 230]);
    let addr = "0.0.0.0:12345".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();

    info!("Listening on addr={}, {:?}", addr, &server_pk);

    let server = Server::new();

    let stats = Stats::new();
    let future = server.run(listener, server_sk, stats, TCP_CONNECTIONS_LIMIT)
        .map_err(|_| ());

    tokio::run(future);
}
