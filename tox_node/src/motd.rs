use std::borrow::Cow;
use regex::Regex;
use time::OffsetDateTime;

use tox::core::stats::Stats;

struct RegexMatches {
    regex: Regex,
    matches: bool,
}

impl RegexMatches {
    pub fn new(template: &str, regex: Regex) -> RegexMatches {
        RegexMatches {
            matches: regex.is_match(template),
            regex,
        }
    }

    pub fn replace<'a, F: FnOnce() -> String>(&self, template: &'a str, f: F) -> Cow<'a, str> {
        if self.matches {
            self.regex.replace_all(template, f().as_str())
        } else {
            Cow::from(template)
        }
    }
}

/// Packet counters for both tcp and udp.
pub struct Counters {
    tcp: Stats,
    udp: Stats,
}

impl Counters {
    pub fn new(tcp: Stats, udp: Stats) -> Self {
        Counters {
            tcp,
            udp,
        }
    }
}

pub struct Motd {
    start_date_regex: RegexMatches,
    uptime_regex: RegexMatches,
    tcp_packets_in_regex: RegexMatches,
    tcp_packets_out_regex: RegexMatches,
    udp_packets_in_regex: RegexMatches,
    udp_packets_out_regex: RegexMatches,
    start_date: OffsetDateTime,
    counters: Counters,
    template: String,
}

impl Motd {
    pub fn new(template: String, counters: Counters) -> Motd {
        let start_date_regex = Regex::new(r"(?i)\{\{\s*start_date\s*\}\}")
            .expect("Failed to compile start_date regex");
        let uptime_regex = Regex::new(r"(?i)\{\{\s*uptime\s*\}\}")
            .expect("Failed to compile uptime regex");
        let tcp_packets_in_regex = Regex::new(r"(?i)\{\{\s*tcp_packets_in\s*\}\}")
            .expect("Failed to compile tcp_in regex");
        let tcp_packets_out_regex = Regex::new(r"(?i)\{\{\s*tcp_packets_out\s*\}\}")
            .expect("Failed to compile tcp_out regex");
        let udp_packets_in_regex = Regex::new(r"(?i)\{\{\s*udp_packets_in\s*\}\}")
            .expect("Failed to compile udp_in regex");
        let udp_packets_out_regex = Regex::new(r"(?i)\{\{\s*udp_packets_out\s*\}\}")
            .expect("Failed to compile udp_out regex");
        Motd {
            start_date_regex: RegexMatches::new(&template, start_date_regex),
            uptime_regex: RegexMatches::new(&template, uptime_regex),
            tcp_packets_in_regex: RegexMatches::new(&template, tcp_packets_in_regex),
            tcp_packets_out_regex: RegexMatches::new(&template, tcp_packets_out_regex),
            udp_packets_in_regex: RegexMatches::new(&template, udp_packets_in_regex),
            udp_packets_out_regex: RegexMatches::new(&template, udp_packets_out_regex),
            start_date: OffsetDateTime::now_utc(),
            counters,
            template,
        }
    }

    fn summary(source: u64) -> String {
        match source {
            0..=999 => format!("{}",source),
            1_000..=999_999 => format!("{0:.1}K", source as f32 / 1_000.0),
            1_000_000..=999_999_999 => format!("{0:.1}M", source as f32 / 1_000_000.0),
            1_000_000_000..=999_999_999_999 => format!("{0:.1}G", source as f32 / 1_000_000_000.0),
            1_000_000_000_000..=u64::MAX => format!("{0:.1}T", source as f32 / 1_000_000_000_000.0),
        }
    }

    pub fn format(&self) -> String {
        let result = self.start_date_regex.replace(&self.template, || {
            let format = time::format_description::parse(
                "[year]-[month]-[day] [hour]:[minute]:[second]",
            ).unwrap();
            self.start_date.format(&format).unwrap()
        });
        let result = self.uptime_regex.replace(&result, || {
            let uptime = OffsetDateTime::now_utc() - self.start_date;
            let days = uptime.whole_days();
            let hours = uptime.whole_hours() - uptime.whole_days() * 24;
            let minutes = uptime.whole_minutes() / 60 - uptime.whole_hours() * 60;
            format!(
              "{:0>#2} days {:0>#2} hours {:0>#2} minutes",
              days,
              hours,
              minutes
            )
        });
        let result = self.tcp_packets_in_regex.replace(&result, || {
            let packets = self.counters.tcp.counters.incoming();
            Self::summary(packets)
        });
        let result = self.tcp_packets_out_regex.replace(&result, || {
            let packets = self.counters.tcp.counters.outgoing();
            Self::summary(packets)
        });
        let result = self.udp_packets_in_regex.replace(&result, || {
            let packets = self.counters.udp.counters.incoming();
            Self::summary(packets)
        });
        let result = self.udp_packets_out_regex.replace(&result, || {
            let packets = self.counters.udp.counters.outgoing();
            Self::summary(packets)
        });
        result.into_owned()
    }
}
