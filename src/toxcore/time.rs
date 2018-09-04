//! Functions to work with time

#[cfg(test)]
use std::sync::Arc;
use std::time::{Duration, SystemTime, Instant, UNIX_EPOCH};

#[cfg(test)]
use parking_lot::RwLock;
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

/// Mutable mock for `tokio_timer::clock::now()`
#[cfg(test)]
#[derive(Clone)]
pub struct MutNow {
    instant: Arc<RwLock<Instant>>,
}

#[cfg(test)]
impl MutNow {
    /// Create new `MutNow`.
    pub fn new(instant: Instant) -> MutNow {
        MutNow {
            instant: Arc::new(RwLock::new(instant)),
        }
    }

    /// Set new `Instant` to return.
    pub fn set(&self, instant: Instant) {
        *self.instant.write() = instant;
    }
}

#[cfg(test)]
impl Now for MutNow {
    fn now(&self) -> Instant {
        *self.instant.read()
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
