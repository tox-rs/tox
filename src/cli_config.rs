use std::net::ToSocketAddrs;
use std::num::ParseIntError;
use std::str::FromStr;

use clap::{Arg, App, AppSettings};
use hex::FromHex;
use itertools::Itertools;
use tox::toxcore::crypto_core::*;
use tox::toxcore::dht::packed_node::PackedNode;

/// Config for threading.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ThreadsConfig {
    /// Detect number of threads automatically by the number of CPU cores.
    Auto,
    /// Exact number of threads.
    N(u16)
}

impl FromStr for ThreadsConfig {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "auto" {
            Ok(ThreadsConfig::Auto)
        } else {
            u16::from_str(s).map(ThreadsConfig::N)
        }
    }
}

/// Config parsed from command line arguments.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CliConfig {
    pub sk: Option<SecretKey>,
    /// Path to the file where DHT keys are stored.
    pub keys_file: Option<String>,
    /// List of bootstrap nodes.
    pub bootstrap_nodes: Vec<PackedNode>,
    /// Number of threads for execution.
    pub threads_config: ThreadsConfig,
}

/// Parse command line arguments.
pub fn cli_parse() -> CliConfig {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .setting(AppSettings::ColoredHelp)
        .arg(Arg::with_name("secret-key")
            .short("s")
            .long("secret-key")
            .help("DHT secret key")
            .takes_value(true)
            .required(true)
            .conflicts_with("keys-file"))
        .arg(Arg::with_name("keys-file")
            .short("k")
            .long("keys-file")
            .help("Path to the file where DHT keys are stored")
            .takes_value(true)
            .required(true)
            .conflicts_with("secret-key"))
        .arg(Arg::with_name("bootstrap-node")
            .short("b")
            .long("bootstrap-node")
            .help("Node to perform initial bootstrap")
            .multiple(true)
            .takes_value(true)
            .number_of_values(2)
            .value_names(&["public key", "address"]))
        .arg(Arg::with_name("threads")
            .short("j")
            .long("threads")
            .help("Number of threads to use. The value 'auto' means that the \
                   number of threads will be determined automatically by the \
                   number of CPU cores")
            .takes_value(true)
            .default_value("1"))
        .get_matches();

    let sk = matches.value_of("secret-key").map(|s| {
        let sk_bytes: [u8; 32] = FromHex::from_hex(s).expect("Invalid DHT secret key");
        SecretKey::from_slice(&sk_bytes).expect("Invalid DHT secret key")
    });

    let keys_file = matches.value_of("keys-file").map(|s| s.to_owned());

    let bootstrap_nodes = matches
        .values_of("bootstrap-node")
        .into_iter()
        .flat_map(|values| values)
        .tuples()
        .map(|(pk, saddr)| {
            // get PK bytes of the bootstrap node
            let bootstrap_pk_bytes: [u8; 32] = FromHex::from_hex(pk).expect("Invalid node key");
            // create PK from bytes
            let bootstrap_pk = PublicKey::from_slice(&bootstrap_pk_bytes).expect("Invalid node key");

            let saddr = saddr
                .to_socket_addrs()
                .expect("Invalid node address")
                .next()
                .expect("Invalid node address");
            PackedNode::new(true, saddr, &bootstrap_pk)
        })
        .collect();

    let threads_config = value_t!(matches.value_of("threads"), ThreadsConfig).unwrap_or_else(|e| e.exit());

    CliConfig {
        sk,
        keys_file,
        bootstrap_nodes,
        threads_config,
    }
}
