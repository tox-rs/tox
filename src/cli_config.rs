use std::net::ToSocketAddrs;

use clap::{Arg, App, AppSettings};
use hex::FromHex;
use itertools::Itertools;
use num_cpus;
use tox::toxcore::crypto_core::*;
use tox::toxcore::dht::packed_node::PackedNode;

/// Config parsed from command line arguments.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CliConfig {
    /// List of bootstrap nodes.
    pub bootstrap_nodes: Vec<PackedNode>,
    /// Number of threads for execution. None if single threaded runtime should
    /// be used.
    pub threads_count: Option<usize>,
}

/// Parse command line arguments.
pub fn cli_parse() -> CliConfig {
    let num_cpus_string = num_cpus::get().to_string();

    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .setting(AppSettings::ColoredHelp)
        .arg(Arg::with_name("bootstrap-node")
            .short("b")
            .long("bootstrap-node")
            .help("Node to perform initial bootstrap")
            .multiple(true)
            .takes_value(true)
            .number_of_values(2)
            .value_names(&["public key", "address"]))
        .arg(Arg::with_name("threaded")
            .long("threaded")
            .short("t")
            .help("Use threaded runtime. By default the number of threads is \
                   determined automatically by the number of CPU cores"))
        .arg(Arg::with_name("threads-count")
            .short("T")
            .long("threads-count")
            .requires("threaded")
            .help("Number of threads to use if threaded flag is specified. \
                   Will be determined automatically by the number of CPU cores \
                   if not specified")
            .takes_value(true)
            .default_value_if("threaded", None, &num_cpus_string))
        .get_matches();

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

    let threads_count = if matches.is_present("threaded") {
        Some(value_t!(matches.value_of("threads-count"), usize).unwrap_or_else(|e| e.exit()))
    } else {
        None
    };

    CliConfig {
        bootstrap_nodes,
        threads_count,
    }
}
