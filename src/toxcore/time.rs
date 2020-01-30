//! Functions to work with time

use std::time::{Duration, SystemTime, Instant, UNIX_EPOCH};

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
    tokio::time::Instant::now().into_std()
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

#[cfg(test)]
pub mod tests {
    use super::{clock_now, clock_elapsed};

    #[tokio::test]
    async fn const_elapsed() {
        tokio::time::pause();

        let now = clock_now();
        let duration = std::time::Duration::from_secs(42);

        tokio::time::advance(duration).await;

        let elapsed = clock_elapsed(now);
        assert_eq!(elapsed, duration);
    }
}
