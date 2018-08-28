use std::net::{SocketAddr, ToSocketAddrs};
use std::num::ParseIntError;
use std::str::FromStr;

use clap::{App, AppSettings, Arg, ArgGroup};
use hex::FromHex;
use itertools::Itertools;
use tox::toxcore::crypto_core::*;
use tox::toxcore::dht::packed_node::PackedNode;
use tox::toxcore::dht::packet::BOOSTRAP_SERVER_MAX_MOTD_LENGTH;

/// Config for threading.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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

#[cfg(unix)]
arg_enum! {
    /// Specifies where to write logs.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum LogType {
        Stderr,
        Stdout,
        Syslog,
        None,
    }
}

#[cfg(not(unix))]
arg_enum! {
    /// Specifies where to write logs.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum LogType {
        Stderr,
        Stdout,
        None,
    }
}

/// Config parsed from command line arguments.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CliConfig {
    /// UDP address to run DHT node
    pub udp_addr: Option<SocketAddr>,
    /// TCP addresses to run TCP relay
    pub tcp_addrs: Vec<SocketAddr>,
    /// DHT SecretKey
    pub sk: Option<SecretKey>,
    /// Path to the file where DHT keys are stored.
    pub keys_file: Option<String>,
    /// List of bootstrap nodes.
    pub bootstrap_nodes: Vec<PackedNode>,
    /// Number of threads for execution.
    pub threads_config: ThreadsConfig,
    /// Specifies where to write logs.
    pub log_type: LogType,
    /// Message of the day
    pub motd: String,
    /// Whether LAN discovery is enabled
    pub lan_discovery_enabled: bool,
}

/// Parse command line arguments.
pub fn cli_parse() -> CliConfig {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .setting(AppSettings::ColoredHelp)
        .arg(Arg::with_name("udp-address")
            .short("u")
            .long("udp-address")
            .help("UDP address to run DHT node")
            .takes_value(true)
            .required_unless("tcp-address"))
        .arg(Arg::with_name("tcp-address")
            .short("t")
            .long("tcp-address")
            .help("TCP address to run TCP relay")
            .multiple(true)
            .takes_value(true)
            .use_delimiter(true)
            .required_unless("udp-address"))
        .group(ArgGroup::with_name("credentials")
            .args(&["secret-key", "keys-file"])
            .required(true))
        .arg(Arg::with_name("secret-key")
            .short("s")
            .long("secret-key")
            .help("DHT secret key")
            .takes_value(true))
        .arg(Arg::with_name("keys-file")
            .short("k")
            .long("keys-file")
            .help("Path to the file where DHT keys are stored")
            .takes_value(true))
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
        .arg(Arg::with_name("log-type")
            .short("l")
            .long("log-type")
            .help("Where to write logs")
            .takes_value(true)
            .default_value("Stderr")
            .possible_values(&LogType::variants()))
        .arg(Arg::with_name("motd")
            .short("m")
            .long("motd")
            .help("Message of the day")
            .takes_value(true)
            .validator(|m|
                if m.len() > BOOSTRAP_SERVER_MAX_MOTD_LENGTH {
                    Err(format!("Message of the day must not be longer than {} bytes", BOOSTRAP_SERVER_MAX_MOTD_LENGTH))
                } else {
                    Ok(())
                }
            )
            .default_value("This is tox-rs"))
        .arg(Arg::with_name("no-lan")
            .long("no-lan")
            .help("Disable LAN discovery"))
        .get_matches();

    let udp_addr = if matches.is_present("udp-address") {
        Some(value_t!(matches.value_of("udp-address"), SocketAddr).unwrap_or_else(|e| e.exit()))
    } else {
        None
    };

    let tcp_addrs = if matches.is_present("tcp-address") {
        values_t!(matches.values_of("tcp-address"), SocketAddr).unwrap_or_else(|e| e.exit())
    } else {
        Vec::new()
    };

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
            PackedNode::new(saddr, &bootstrap_pk)
        })
        .collect();

    let threads_config = value_t!(matches.value_of("threads"), ThreadsConfig).unwrap_or_else(|e| e.exit());

    let log_type = value_t!(matches.value_of("log-type"), LogType).unwrap_or_else(|e| e.exit());

    let motd = value_t!(matches.value_of("motd"), String).unwrap_or_else(|e| e.exit());

    let lan_discovery_enabled = !matches.is_present("no-lan");

    CliConfig {
        udp_addr,
        tcp_addrs,
        sk,
        keys_file,
        bootstrap_nodes,
        threads_config,
        log_type,
        motd,
        lan_discovery_enabled,
    }
}
