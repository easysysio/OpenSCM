// =============================================================================
// rate_limit.rs — in-memory limits on repeated failures
//
// A Limiter counts events per key (an account, an address) inside a sliding
// window. When a key reaches the limit it is locked for a fixed period, and
// its count starts again from zero once the lock ends.
//
// State lives in this process only: a restart forgets every count and every
// lock. That is acceptable for its job, slowing down password guessing, and
// it needs no schema. One process serves a deployment (the planned HA is a
// warm standby, not a second active server), so nothing is split across
// servers.
//
// Memory: each key holds at most `max` timestamps, and a key with no recent
// event and no lock is dropped by the sweep that runs when the map grows past
// SWEEP_AT entries.
// =============================================================================

use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

const SWEEP_AT: usize = 10_000;

#[derive(Default)]
struct Entry {
    hits: VecDeque<Instant>,
    locked_until: Option<Instant>,
}

pub struct Limiter {
    max: usize,
    window: Duration,
    lockout: Duration,
    entries: Mutex<HashMap<String, Entry>>,
}

impl Limiter {
    // ─────────────────────────────────────────────────────────────────────────
    // Limiter::new
    // `max` events within `window` lock the key for `lockout`.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn new(max: usize, window: Duration, lockout: Duration) -> Self {
        Limiter { max, window, lockout, entries: Mutex::new(HashMap::new()) }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Limiter::locked
    // Time left on the key's lock, or None when it is not locked.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn locked(&self, key: &str) -> Option<Duration> {
        self.locked_at(key, Instant::now())
    }

    pub fn locked_at(&self, key: &str, now: Instant) -> Option<Duration> {
        let map = self.entries.lock().unwrap();
        map.get(key)
            .and_then(|e| e.locked_until)
            .and_then(|until| until.checked_duration_since(now))
            .filter(|left| !left.is_zero())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Limiter::record
    // Counts one event. Returns true when this event reached the limit and
    // locked the key, so the caller can log the lock once rather than every
    // refused attempt after it.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn record(&self, key: &str) -> bool {
        self.record_at(key, Instant::now())
    }

    pub fn record_at(&self, key: &str, now: Instant) -> bool {
        let mut map = self.entries.lock().unwrap();
        if map.len() >= SWEEP_AT {
            let window = self.window;
            map.retain(|_, e| {
                e.locked_until.is_some_and(|u| u > now)
                    || e.hits.back().is_some_and(|t| now.duration_since(*t) < window)
            });
        }
        let e = map.entry(key.to_string()).or_default();
        if e.locked_until.is_some_and(|u| u > now) {
            return false; // already locked; callers refuse before counting
        }
        e.locked_until = None;
        while e.hits.front().is_some_and(|t| now.duration_since(*t) >= self.window) {
            e.hits.pop_front();
        }
        e.hits.push_back(now);
        if e.hits.len() >= self.max {
            e.hits.clear();
            e.locked_until = Some(now + self.lockout);
            return true;
        }
        false
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Limiter::clear
    // Forgets the key: its count and any lock.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn clear(&self, key: &str) {
        self.entries.lock().unwrap().remove(key);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sign-in limits. Failed sign-ins only: a correct password never counts.
//   LOGIN_ACCOUNT — per organization + username, from any address. Stops a
//                   slow guess spread over many addresses. Someone who knows a
//                   username can lock that account for 15 minutes; that is the
//                   price of the protection.
//   LOGIN_ADDRESS — per client address, across accounts. Stops one source
//                   trying many usernames.
// ─────────────────────────────────────────────────────────────────────────────
pub const LOGIN_ACCOUNT_MAX: usize = 10;
pub const LOGIN_ADDRESS_MAX: usize = 30;
pub const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);
pub const LOGIN_LOCKOUT: Duration = Duration::from_secs(15 * 60);

pub static LOGIN_ACCOUNT: LazyLock<Limiter> =
    LazyLock::new(|| Limiter::new(LOGIN_ACCOUNT_MAX, LOGIN_WINDOW, LOGIN_LOCKOUT));
pub static LOGIN_ADDRESS: LazyLock<Limiter> =
    LazyLock::new(|| Limiter::new(LOGIN_ADDRESS_MAX, LOGIN_WINDOW, LOGIN_LOCKOUT));

// New agent registrations that land in the pending queue, per client address.
// A registration with a valid enrollment token is not counted. Generous,
// because a whole fleet behind one NAT address may enrol at once; the point
// is that nobody can fill the queue with thousands of fake systems.
pub const REGISTER_PENDING_MAX: usize = 100;
pub static REGISTER_PENDING: LazyLock<Limiter> = LazyLock::new(|| {
    Limiter::new(REGISTER_PENDING_MAX, Duration::from_secs(3600), Duration::from_secs(3600))
});

// ─────────────────────────────────────────────────────────────────────────────
// Helper: login_account_key
// The organization reduced to the tenant id it names, so spellings that reach
// the same organization ("Acme Inc", "acme-inc") share one count, and the
// username exactly, as the lookup matches it. The organization is empty when
// the form has none, as in CE.
// ─────────────────────────────────────────────────────────────────────────────
pub fn login_account_key(organization: Option<&str>, username: &str) -> String {
    let tenant = crate::auth::tenant_id_for_organization(organization.unwrap_or(""));
    format!("{}\u{0}{}", tenant, username)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: retry_message
// "Too many … Try again in N minutes." with N rounded up, never 0.
// ─────────────────────────────────────────────────────────────────────────────
pub fn retry_message(what: &str, left: Duration) -> String {
    let minutes = left.as_secs().div_ceil(60).max(1);
    format!(
        "Too many {what}. Try again in {minutes} minute{}.",
        if minutes == 1 { "" } else { "s" }
    )
}
