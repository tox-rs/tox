use time::OffsetDateTime;

use tox::core::stats::Stats;

/// Packet counters for both tcp and udp.
pub struct Counters {
    tcp: Stats,
    udp: Stats,
}

impl Counters {
    pub fn new(tcp: Stats, udp: Stats) -> Self {
        Counters { tcp, udp }
    }
}

pub struct Motd {
    start_date: OffsetDateTime,
    counters: Counters,
    template: String,
}

impl Motd {
    pub fn new(template: String, counters: Counters) -> Motd {
        Motd {
            start_date: OffsetDateTime::now_utc(),
            counters,
            template,
        }
    }

    fn format_n(source: u64) -> String {
        match source {
            0..=999 => format!("{}", source),
            1_000..=999_999 => format!("{0:.1}K", source as f32 / 1_000.0),
            1_000_000..=999_999_999 => format!("{0:.1}M", source as f32 / 1_000_000.0),
            1_000_000_000..=999_999_999_999 => format!("{0:.1}G", source as f32 / 1_000_000_000.0),
            1_000_000_000_000..=u64::MAX => format!("{0:.1}T", source as f32 / 1_000_000_000_000.0),
        }
    }

    pub fn format(&self) -> String {
        let start_date = {
            let format = time::format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second]").unwrap();
            self.start_date.format(&format).unwrap()
        };

        let uptime = {
            let uptime = OffsetDateTime::now_utc() - self.start_date;
            let days = uptime.whole_days();
            let hours = uptime.whole_hours() - uptime.whole_days() * 24;
            let minutes = uptime.whole_minutes() / 60 - uptime.whole_hours() * 60;
            format!("{:0>#2} days {:0>#2} hours {:0>#2} minutes", days, hours, minutes)
        };

        let tcp_packets_in = Self::format_n(self.counters.tcp.counters.incoming());
        let tcp_packets_out = Self::format_n(self.counters.tcp.counters.outgoing());
        let udp_packets_in = Self::format_n(self.counters.udp.counters.incoming());
        let udp_packets_out = Self::format_n(self.counters.udp.counters.outgoing());

        let result = self.template.clone();
        let result = result.replace("{{start_date}}", &start_date);
        let result = result.replace("{{uptime}}", &uptime);
        let result = result.replace("{{tcp_packets_in}}", &tcp_packets_in);
        let result = result.replace("{{tcp_packets_out}}", &tcp_packets_out);
        let result = result.replace("{{udp_packets_in}}", &udp_packets_in);
        result.replace("{{udp_packets_out}}", &udp_packets_out)
    }
}
