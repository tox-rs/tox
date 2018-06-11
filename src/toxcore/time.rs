/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2018 Evgeny Kurnevsky <kurnevsky@gmail.com>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

//! Functions to work with time

use std::time::{Duration, SystemTime, Instant, UNIX_EPOCH};

#[cfg(test)]
use tokio_timer::clock;
#[cfg(test)]
use tokio_timer::clock::Now;

/// Return number of seconds that have elapsed since Unix epoch.
pub fn unix_time(time: SystemTime) -> u64 {
    let since_the_epoch = time.duration_since(UNIX_EPOCH)
        .expect("Current time is earlier than Unix epoch");
    since_the_epoch.as_secs()
}

/// Returns an `Instant` corresponding to "now". Should be used instead of
/// `tokio_timer::clock::now()` to have zero cost mocked time.
#[cfg(test)]
pub fn clock_now() -> Instant {
    clock::now()
}

/// Returns an `Instant` corresponding to "now". Should be used instead of
/// `tokio_timer::clock::now()` to have zero cost mocked time.
#[cfg(not(test))]
pub fn clock_now() -> Instant {
    Instant::now()
}

/// Returns the amount of time elapsed since this instant was created. Should be
/// used instead of `Instant::elapsed` in order to work with mocked
/// `tokio_timer::clock::now()`.
pub fn clock_elapsed(time: Instant) -> Duration {
    clock_now() - time
}

/// Constant time mock for `tokio_timer::clock::now()`
#[cfg(test)]
pub struct ConstNow(pub Instant);

#[cfg(test)]
impl Now for ConstNow {
    fn now(&self) -> Instant {
        self.0
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use tokio_executor;
    use tokio_timer::clock::*;

    #[test]
    fn const_elapsed() {
        let now = clock_now();
        let duration = Duration::from_secs(42);

        let clock = Clock::new_with_now(ConstNow(now + duration));
        let mut enter = tokio_executor::enter().unwrap();

        with_default(&clock, &mut enter, |_| {
            let elapsed = clock_elapsed(now);
            assert_eq!(elapsed, duration);
        });
    }
}
