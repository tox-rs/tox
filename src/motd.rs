use std::borrow::Cow;
use chrono::DateTime;
use chrono::offset::Local;
use regex::Regex;

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

pub struct Motd {
    start_date_regex: RegexMatches,
    uptime_regex: RegexMatches,
    start_date: DateTime<Local>,
    template: String,
}

impl Motd {
    pub fn new(template: String) -> Motd {
        let start_date_regex = Regex::new(r"(?i)\{\{\s*start_date\s*\}\}")
            .expect("Failed to compile start_date regex");
        let uptime_regex = Regex::new(r"(?i)\{\{\s*uptime\s*\}\}")
            .expect("Failed to compile uptime regex");
        Motd {
            start_date_regex: RegexMatches::new(&template, start_date_regex),
            uptime_regex: RegexMatches::new(&template, uptime_regex),
            start_date: Local::now(),
            template,
        }
    }

    pub fn format(&self) -> String {
        let result = self.start_date_regex.replace(&self.template, ||
            self.start_date.format("%c").to_string()
        );
        let result = self.uptime_regex.replace(&result, || {
            let uptime = Local::now() - self.start_date;
            let days = uptime.num_days();
            let hours = uptime.num_hours() - uptime.num_days() * 24;
            let minutes = uptime.num_minutes() - uptime.num_hours() * 60;
            format!(
              "{:0>#2} days {:0>#2} hours {:0>#2} minutes",
              days,
              hours,
              minutes
            )
        });
        result.into_owned()
    }
}
