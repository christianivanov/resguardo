//! Per-principal requests-per-minute limit, in memory (design document, section 5).
//!
//! GCRA (generic cell rate algorithm): each principal may send `requests_per_minute`
//! requests in a burst, then one more every `60 s / requests_per_minute`. It keeps one
//! instant per principal, and the set of principals is fixed at startup, so memory does not
//! grow with traffic and unauthenticated requests never create state.
//!
//! Limits are per Resguardo instance: two instances allow twice the rate.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use resguardo_core::{Principal, PrincipalId};

#[derive(Debug)]
struct Cell {
    /// Theoretical arrival time of the next request; `None` until the first one.
    tat: Option<Instant>,
    /// Time one request "costs": 60 s / requests_per_minute.
    interval: Duration,
    /// How far ahead of `now` the TAT may run: the burst size minus one request.
    tolerance: Duration,
}

/// `Mutex` (like `synchronized`) guards each cell; the lock is never held across an `.await`.
#[derive(Debug)]
pub struct RateLimiter {
    cells: BTreeMap<PrincipalId, Mutex<Cell>>,
}

impl RateLimiter {
    pub fn new<'a>(principals: impl IntoIterator<Item = &'a Principal>) -> Self {
        let minute = Duration::from_secs(60);
        let cells = principals
            .into_iter()
            .map(|p| {
                // Validated > 0 by the configuration.
                let rpm = p.limits.requests_per_minute.max(1);
                let interval = minute / rpm;
                let cell = Cell {
                    tat: None,
                    interval,
                    tolerance: minute.saturating_sub(interval),
                };
                (p.id.clone(), Mutex::new(cell))
            })
            .collect();
        Self { cells }
    }

    /// `Ok` if the request may go ahead; otherwise how long to wait before retrying.
    /// Fails closed: an unknown principal or a poisoned lock is treated as over the limit.
    pub fn check(&self, principal: &PrincipalId, now: Instant) -> Result<(), Duration> {
        const FALLBACK_RETRY: Duration = Duration::from_secs(1);
        let Some(cell) = self.cells.get(principal) else {
            return Err(FALLBACK_RETRY);
        };
        let Ok(mut cell) = cell.lock() else {
            return Err(FALLBACK_RETRY);
        };
        let tat = cell.tat.map_or(now, |tat| tat.max(now));
        let ahead = tat.saturating_duration_since(now);
        if ahead > cell.tolerance {
            return Err(ahead - cell.tolerance);
        }
        cell.tat = Some(tat + cell.interval);
        Ok(())
    }
}

/// `retry-after` takes whole seconds; round up so a client never retries too early.
pub fn retry_after_secs(wait: Duration) -> u64 {
    let secs = wait.as_secs();
    if wait.subsec_nanos() > 0 || secs == 0 {
        secs + 1
    } else {
        secs
    }
}

#[cfg(test)]
mod tests {
    use resguardo_core::Config;

    use super::*;

    fn limiter(rpm: u32) -> (RateLimiter, PrincipalId) {
        let source = format!(
            r#"
[audit]
path = "a"
signing_key = "k"
public_key = "p"
[policy.actions]
secret = "block"
secret_candidate = "flag"
es_id = "redact"
iban = "redact"
card = "block"
phone = "redact"
email = "redact"
invisible_text = "redact"
[[upstream]]
provider = "openai"
base_url = "https://api.openai.com"
credential_env = "K"
[[principal]]
id = "bot"
key_sha256 = "{}"
requests_per_minute = {rpm}
models.openai = ["m"]
"#,
            "a".repeat(64)
        );
        let config = Config::from_toml_str(&source).unwrap();
        let principal = &config.principals[0].principal;
        (RateLimiter::new([principal]), principal.id.clone())
    }

    #[test]
    fn allows_a_burst_of_rpm_then_one_per_interval() {
        let (limiter, bot) = limiter(2);
        let t0 = Instant::now();
        assert_eq!(limiter.check(&bot, t0), Ok(()));
        assert_eq!(limiter.check(&bot, t0), Ok(()));
        assert_eq!(limiter.check(&bot, t0), Err(Duration::from_secs(30)));
        // Half a minute later one request has been "earned" back, not two.
        let t30 = t0 + Duration::from_secs(30);
        assert_eq!(limiter.check(&bot, t30), Ok(()));
        assert!(limiter.check(&bot, t30).is_err());
    }

    #[test]
    fn rejected_requests_do_not_consume_quota() {
        let (limiter, bot) = limiter(1);
        let t0 = Instant::now();
        assert!(limiter.check(&bot, t0).is_ok());
        for _ in 0..10 {
            assert!(limiter.check(&bot, t0).is_err());
        }
        assert!(limiter.check(&bot, t0 + Duration::from_secs(60)).is_ok());
    }

    #[test]
    fn unknown_principals_are_rejected() {
        let (_, bot) = limiter(5);
        let empty = RateLimiter::new([]);
        assert!(empty.check(&bot, Instant::now()).is_err());
    }

    #[test]
    fn retry_after_rounds_up_to_whole_seconds() {
        assert_eq!(retry_after_secs(Duration::from_secs(30)), 30);
        assert_eq!(retry_after_secs(Duration::from_millis(29_001)), 30);
        assert_eq!(retry_after_secs(Duration::ZERO), 1);
    }
}
