use std::convert::TryInto;
use std::net::{SocketAddr, ToSocketAddrs};
use std::num::ParseIntError;
use std::str::FromStr;
use std::path::Path;
use std::collections::HashMap;

use config::{Config, File as CfgFile};
use serde::{de, Deserialize, Deserializer};
use serde_yaml::Value;
use clap::{App, AppSettings, Arg, SubCommand, ArgMatches};
use hex::FromHex;
use itertools::Itertools;
use tox::crypto::*;
use tox::packet::dht::packed_node::PackedNode;
use tox::packet::dht::BOOSTRAP_SERVER_MAX_MOTD_LENGTH;

/// Config for threading.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
pub enum Threads {
    /// Detect number of threads automatically by the number of CPU cores.
    Auto,
    /// Exact number of threads.
    N(u16)
}

impl FromStr for Threads {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "auto" {
            Ok(Threads::Auto)
        } else {
            u16::from_str(s).map(Threads::N)
        }
    }
}

#[cfg(unix)]
arg_enum! {
    /// Specifies where to write logs.
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
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
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
    pub enum LogType {
        Stderr,
        Stdout,
        None,
    }
}

/// Bootstrap node with generic string address which might be either IP address
/// or DNS name.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct BootstrapNode {
    /// `PublicKey` of the node.
    #[serde(deserialize_with = "de_from_hex")]
    pk: PublicKey,
    /// Generic string address which might be either IP address or DNS name.
    addr: String,
}

impl BootstrapNode {
    /// Resolve string address of the node to possible multiple `SocketAddr`s.
    pub fn resolve(&self) -> impl Iterator<Item = PackedNode> {
        let pk = self.pk.clone();
        let addrs = match self.addr.to_socket_addrs() {
            Ok(addrs) => addrs,
            Err(e) => {
                warn!("Failed to resolve bootstrap node address '{}': {}", self.addr, e);
                Vec::new().into_iter()
            },
        };
        addrs.map(move |addr| PackedNode::new(addr, pk.clone()))
    }
}

fn de_from_hex<'de, D>(deserializer: D) -> Result<PublicKey, D::Error> where D: Deserializer<'de> {
    let s = String::deserialize(deserializer)?;

    let bootstrap_pk_bytes: [u8; 32] = FromHex::from_hex(s)
        .map_err(|e| de::Error::custom(format!("Can't make bytes from hex string {:?}", e)))?;
    Ok(PublicKey::from(bootstrap_pk_bytes))
}

fn de_threads<'de, D>(deserializer: D) -> Result<Threads, D::Error> where D: Deserializer<'de> {
    let s = String::deserialize(deserializer)?;

    Threads::from_str(&s)
        .map_err(|e| de::Error::custom(format!("threads: {:?}", e)))
}

/// Config parsed from command line arguments.
#[derive(Clone, Debug, Deserialize)]
pub struct NodeConfig {
    /// UDP address to run DHT node
    #[serde(rename = "udp-address")]
    #[serde(default)]
    pub udp_addr: Option<SocketAddr>,
    /// TCP addresses to run TCP relay
    #[serde(rename = "tcp-addresses")]
    #[serde(default)]
    pub tcp_addrs: Vec<SocketAddr>,
    /// Maximum number of active TCP connections relay can hold.
    #[serde(rename = "tcp-connections-limit")]
    pub tcp_connections_limit: usize,
    /// DHT SecretKey
    #[serde(skip_deserializing)]
    pub sk: Option<SecretKey>,
    /// True if the SecretKey was passed as an argument instead of environment
    /// variable. Necessary to print a warning since the logger backend is not
    /// initialized when we parse arguments.
    #[serde(skip_deserializing)]
    pub sk_passed_as_arg: bool,
    /// Path to the file where DHT keys are stored.
    /// Required with config.
    #[serde(rename = "keys-file")]
    pub keys_file: Option<String>,
    /// List of bootstrap nodes.
    #[serde(rename = "bootstrap-nodes")]
    #[serde(default)]
    pub bootstrap_nodes: Vec<BootstrapNode>,
    /// Number of threads for execution.
    #[serde(deserialize_with = "de_threads")]
    pub threads: Threads,
    /// Specifies where to write logs.
    #[serde(rename = "log-type")]
    pub log_type: LogType,
    /// Message of the day
    pub motd: String,
    /// Whether LAN discovery is enabled
    #[serde(rename = "lan-discovery")]
    pub lan_discovery_enabled: bool,
    /// Unused fields while parsing config file
    #[serde(flatten)]
    pub unused: HashMap<String, Value>,
}

fn create_sk_arg() -> Arg<'static, 'static> {
    Arg::with_name("secret-key")
        .short("s")
        .long("secret-key")
        .help("DHT secret key. Note that you should not pass the key via \
               arguments due to security reasons. Use this argument for \
               test purposes only. In the real world use the environment \
               variable instead")
        .takes_value(true)
        .conflicts_with("keys-file")
        .env("TOX_SECRET_KEY")
        .hidden(true)
}

fn create_keys_file_arg() -> Arg<'static, 'static> {
    Arg::with_name("keys-file")
        .short("k")
        .long("keys-file")
        .help("Path to the file where DHT keys are stored")
        .takes_value(true)
        .required_unless("secret-key")
        .conflicts_with("secret-key")
}

fn app() -> App<'static, 'static> {
    App::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .setting(AppSettings::ColoredHelp)
        .setting(AppSettings::SubcommandsNegateReqs)
        .subcommand(SubCommand::with_name("config")
            .arg(Arg::with_name("cfg-file")
                .index(1)
                .help("Load settings from saved config file. \
                    Config file format is YAML")
                .takes_value(true)))
        .subcommand(SubCommand::with_name("derive-pk")
            .about("Derive PK from either --keys-file or from env:TOX_SECRET_KEY")
            .arg(create_sk_arg())
            .arg(create_keys_file_arg()))
        // here go args without subcommands
        .arg(create_sk_arg())
        .arg(create_keys_file_arg())
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
        .arg(Arg::with_name("tcp-connections-limit")
            .short("c")
            .long("tcp-connections-limit")
            .help("Maximum number of active TCP connections relay can hold. \
                   Defaults to 512 when tcp-address is specified")
            .requires("tcp-address")
            .takes_value(true)
            .default_value_if("tcp-address", None, "512"))
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
            .help("Message of the day. Must be no longer than 256 bytes. May \
                   contain next variables placed in {{ }}:\n\
                   - start_date: time when the node was started\n\
                   - uptime: uptime in the format 'XX days XX hours XX minutes'\n")
            .takes_value(true)
            .validator(|m| {
                if m.len() > BOOSTRAP_SERVER_MAX_MOTD_LENGTH {
                    Err(format!("Message of the day must not be longer than {} bytes", BOOSTRAP_SERVER_MAX_MOTD_LENGTH))
                } else {
                    Ok(())
                }
            })
            .default_value("This is tox-rs"))
        .arg(Arg::with_name("lan-discovery")
            .long("lan-discovery")
            .help("Enable LAN discovery (disabled by default)"))
}

/// Parse command line arguments.
pub fn cli_parse() -> NodeConfig {
    let matches = app().get_matches();

    match matches.subcommand() {
        ("derive-pk", Some(m)) => run_derive_pk(m),
        ("config", Some(m)) => run_config(m),
        _ => run_args(&matches),
    }
}

/// Parse settings from a saved file.
fn parse_config(config_path: &str) -> NodeConfig {
    let mut settings = Config::default();

    settings.set_default("log-type", "Stderr").expect("Can't set default value for `log-type`");
    settings.set_default("motd", "This is tox-rs").expect("Can't set default value for `motd`");
    settings.set_default("lan-discovery", "False").expect("Can't set default value for `lan-discovery`");
    settings.set_default("threads", "1").expect("Can't set default value for `threads`");
    settings.set_default("tcp-connections-limit", "512").expect("Can't set default value for `tcp-connections-limit`");

    let config_file = if !Path::new(config_path).exists() {
        panic!("Can't find config file {}", config_path);
    } else {
        CfgFile::with_name(config_path)
    };

    settings.merge(config_file).expect("Merging config file with default values failed");

    let config: NodeConfig = settings.try_into().expect("Can't deserialize config");

    if config.keys_file.is_none() {
        panic!("Can't deserialize config: 'keys-file' is not set");
    }

    config
}

fn run_derive_pk(matches: &ArgMatches) -> ! {
    let sk_passed_as_arg = matches.occurrences_of("secret-key") > 0;
    if sk_passed_as_arg {
        panic!("You should not pass the secret key via arguments due to \
               security reasons. Use the environment variable instead");
    }

    let pk_from_arg = matches.value_of("secret-key").map(|s| {
        let sk_bytes: [u8; 32] = FromHex::from_hex(s).expect("Invalid DHT secret key");
        SecretKey::from(sk_bytes).public_key()
    });
    let pk_from_file = matches.value_of("keys-file").map(|keys_file| {
        let mut file = std::fs::File::open(keys_file).expect("Failed to read the keys file");

        let mut buf = [0; crypto_box::KEY_SIZE * 2];
        use std::io::Read;
        file.read_exact(&mut buf).expect("Failed to read keys from the keys file");
        let pk_bytes: [u8; crypto_box::KEY_SIZE] = buf[..crypto_box::KEY_SIZE].try_into().expect("Failed to read public key from the keys file");
        let sk_bytes: [u8; crypto_box::KEY_SIZE] = buf[crypto_box::KEY_SIZE..].try_into().expect("Failed to read secret key from the keys file");
        let pk = PublicKey::from(pk_bytes);
        let sk = SecretKey::from(sk_bytes);
        assert!(pk == sk.public_key(), "The loaded public key does not correspond to the loaded secret key");
        pk
    });

    let pk = pk_from_arg.or(pk_from_file).unwrap();

    println!("{}", hex::encode(&pk).to_uppercase());

    // FIXME: use ExitCode::SUCCESS when stabilized
    // https://doc.rust-lang.org/std/process/struct.ExitCode.html
    std::process::exit(0)
}

fn run_config(matches: &ArgMatches) -> NodeConfig {
    let config_path = value_t!(matches.value_of("cfg-file"), String).unwrap_or_else(|e| e.exit());

    parse_config(&config_path)
}

fn run_args(matches: &ArgMatches) -> NodeConfig {
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

    let tcp_connections_limit = if matches.is_present("tcp-connections-limit") {
        value_t!(matches.value_of("tcp-connections-limit"), usize).unwrap_or_else(|e| e.exit())
    } else {
        512
    };

    let sk = matches.value_of("secret-key").map(|s| {
        let sk_bytes: [u8; 32] = FromHex::from_hex(s).expect("Invalid DHT secret key");
        SecretKey::from(sk_bytes)
    });

    let sk_passed_as_arg = matches.occurrences_of("secret-key") > 0;

    let keys_file = matches.value_of("keys-file").map(|s| s.to_owned());

    let bootstrap_nodes = matches
        .values_of("bootstrap-node")
        .into_iter()
        .flatten()
        .tuples()
        .map(|(pk, addr)| {
            // get PK bytes of the bootstrap node
            let bootstrap_pk_bytes: [u8; 32] = FromHex::from_hex(pk).expect("Invalid node key");
            // create PK from bytes
            let bootstrap_pk = PublicKey::from(bootstrap_pk_bytes);

            BootstrapNode {
                pk: bootstrap_pk,
                addr: addr.to_owned(),
            }
        })
        .collect();

    let threads = value_t!(matches.value_of("threads"), Threads).unwrap_or_else(|e| e.exit());

    let log_type = value_t!(matches.value_of("log-type"), LogType).unwrap_or_else(|e| e.exit());

    let motd = value_t!(matches.value_of("motd"), String).unwrap_or_else(|e| e.exit());

    let lan_discovery_enabled = matches.is_present("lan-discovery");

    NodeConfig {
        udp_addr,
        tcp_addrs,
        tcp_connections_limit,
        sk,
        sk_passed_as_arg,
        keys_file,
        bootstrap_nodes,
        threads,
        log_type,
        motd,
        lan_discovery_enabled,
        unused: HashMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_udp_only() {
        let saddr = "127.0.0.1:33445";
        let matches = app().get_matches_from(vec![
            "tox-node",
            "--keys-file",
            "./keys",
            "--udp-address",
            saddr,
        ]);
        let config = run_args(&matches);
        assert_eq!(config.keys_file.unwrap(), "./keys");
        assert_eq!(config.udp_addr.unwrap(), saddr.parse().unwrap());
        assert!(config.tcp_addrs.is_empty());
        assert!(!config.lan_discovery_enabled);
    }

    #[test]
    fn args_tcp_only() {
        let saddr_1 = "127.0.0.1:33445";
        let saddr_2 = "127.0.0.1:33446";
        let matches = app().get_matches_from(vec![
            "tox-node",
            "--keys-file",
            "./keys",
            "--tcp-address",
            saddr_1,
            "--tcp-address",
            saddr_2,
        ]);
        let config = run_args(&matches);
        assert_eq!(config.keys_file.unwrap(), "./keys");
        assert!(config.udp_addr.is_none());
        assert_eq!(config.tcp_addrs, vec![
            saddr_1.parse().unwrap(),
            saddr_2.parse().unwrap()
        ]);
        assert!(!config.lan_discovery_enabled);
    }

    #[test]
    fn args_udp_tcp() {
        let saddr_1 = "127.0.0.1:33445";
        let saddr_2 = "127.0.0.1:33446";
        let matches = app().get_matches_from(vec![
            "tox-node",
            "--keys-file",
            "./keys",
            "--udp-address",
            saddr_1,
            "--tcp-address",
            saddr_2,
        ]);
        let config = run_args(&matches);
        assert_eq!(config.keys_file.unwrap(), "./keys");
        assert_eq!(config.udp_addr.unwrap(), saddr_1.parse().unwrap());
        assert_eq!(config.tcp_addrs, vec![saddr_2.parse().unwrap()]);
        assert!(!config.lan_discovery_enabled);
    }

    #[test]
    fn args_udp_tcp_with_secret_key() {
        let saddr_1 = "127.0.0.1:33445";
        let saddr_2 = "127.0.0.1:33446";
        let sk = "d5ff9ceafe9e1145bc807dc94b4ee911a5878705b5f9ee68f6ccc51e498f313c";
        let matches = app().get_matches_from(vec![
            "tox-node",
            "--secret-key",
            sk,
            "--udp-address",
            saddr_1,
            "--tcp-address",
            saddr_2,
        ]);
        let config = run_args(&matches);
        assert!(config.sk_passed_as_arg);
        assert_eq!(config.udp_addr.unwrap(), saddr_1.parse().unwrap());
        assert_eq!(config.tcp_addrs, vec![saddr_2.parse().unwrap()]);
        assert!(!config.lan_discovery_enabled);
    }

    #[test]
    fn args_udp_or_tcp_required() {
        let matches = app().get_matches_from_safe(vec![
            "tox-node",
            "--keys-file",
            "./keys",
        ]);
        assert!(matches.is_err());
    }

    #[test]
    fn args_keys_file_or_secret_key_required() {
        let matches = app().get_matches_from_safe(vec![
            "tox-node",
            "--udp-address",
            "127.0.0.1:33445",
        ]);
        assert!(matches.is_err());
    }

    #[test]
    fn args_keys_file_and_secret_key_conflicts() {
        let matches = app().get_matches_from_safe(vec![
            "tox-node",
            "--keys-file",
            "./keys",
            "--secret-key",
            "d5ff9ceafe9e1145bc807dc94b4ee911a5878705b5f9ee68f6ccc51e498f313c",
            "--udp-address",
            "127.0.0.1:33445",
        ]);
        assert!(matches.is_err());
    }

    #[test]
    fn args_motd() {
        let motd = "abcdef";
        let matches = app().get_matches_from(vec![
            "tox-node",
            "--keys-file",
            "./keys",
            "--udp-address",
            "127.0.0.1:33445",
            "--motd",
            motd,
        ]);
        let config = run_args(&matches);
        assert_eq!(config.motd, motd);
    }

    #[test]
    fn args_lan_discovery() {
        let matches = app().get_matches_from(vec![
            "tox-node",
            "--keys-file",
            "./keys",
            "--udp-address",
            "127.0.0.1:33445",
            "--lan-discovery",
        ]);
        let config = run_args(&matches);
        assert!(config.lan_discovery_enabled);
    }

    #[test]
    fn args_bootstrap_nodes() {
        let pk_1 = "F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67";
        let addr_1 = "node.tox.biribiri.org:33445";
        let pk_2 = "8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832";
        let addr_2 = "85.172.30.117:33445";
        let matches = app().get_matches_from(vec![
            "tox-node",
            "--keys-file",
            "./keys",
            "--udp-address",
            "127.0.0.1:33445",
            "--bootstrap-node",
            pk_1,
            addr_1,
            "--bootstrap-node",
            pk_2,
            addr_2,
        ]);
        let config = run_args(&matches);
        let node_1 = BootstrapNode {
            pk: {
                let pk_bytes = <[u8; 32]>::from_hex(pk_1).unwrap();
                PublicKey::from(pk_bytes)
            },
            addr: addr_1.into(),
        };
        let node_2 = BootstrapNode {
            pk: {
                let pk_bytes = <[u8; 32]>::from_hex(pk_2).unwrap();
                PublicKey::from(pk_bytes)
            },
            addr: addr_2.into(),
        };
        assert_eq!(config.bootstrap_nodes, vec![node_1, node_2]);
    }

    #[test]
    fn args_log_type() {
        let matches = app().get_matches_from(vec![
            "tox-node",
            "--keys-file",
            "./keys",
            "--udp-address",
            "127.0.0.1:33445",
            "--log-type",
            "None"
        ]);
        let config = run_args(&matches);
        assert_eq!(config.log_type, LogType::None);
    }

    #[test]
    fn args_tcp_connections_limit() {
        let matches = app().get_matches_from(vec![
            "tox-node",
            "--keys-file",
            "./keys",
            "--tcp-address",
            "127.0.0.1:33445",
            "--tcp-connections-limit",
            "42"
        ]);
        let config = run_args(&matches);
        assert_eq!(config.tcp_connections_limit, 42);
    }

    #[test]
    fn args_tcp_connections_limit_requires_tcp_addr() {
        let matches = app().get_matches_from_safe(vec![
            "tox-node",
            "--keys-file",
            "./keys",
            "--udp-address",
            "127.0.0.1:33445",
            "--tcp-connections-limit",
            "42"
        ]);
        assert!(matches.is_err());
    }

    #[test]
    fn args_threads() {
        let matches = app().get_matches_from(vec![
            "tox-node",
            "--keys-file",
            "./keys",
            "--udp-address",
            "127.0.0.1:33445",
            "--threads",
            "42"
        ]);
        let config = run_args(&matches);
        assert_eq!(config.threads, Threads::N(42));
    }

    #[test]
    fn args_derive_pk_keys_file() {
        let matches = app().get_matches_from(vec![
            "tox-node",
            "derive-pk",
            "--keys-file",
            "./keys",
        ]);
        let matches = matches.subcommand_matches("derive-pk").unwrap();
        assert_eq!("./keys", matches.value_of("keys-file").unwrap());
    }

    #[test]
    fn args_derive_pk_secret_key() {
        let sk_str = "d7f04a6db2c12f1eae0229c72e6bc429ca894541acc5f292da0e4d9a47827774";
        let matches = app().get_matches_from(vec![
            "tox-node",
            "derive-pk",
            "--secret-key",
            sk_str
        ]);
        let matches = matches.subcommand_matches("derive-pk").unwrap();
        assert_eq!(sk_str, matches.value_of("secret-key").unwrap());
    }
}
