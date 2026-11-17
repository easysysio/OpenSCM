// =============================================================================
// clock.rs — the current time in UTC, as the server stores it
//
// Small helpers over jiff (which replaced chrono; chrono is
// unmaintained). The server keeps every time in UTC: as text in SQLite, and
// as a civil (zone-less) datetime where schedules are calculated.
// =============================================================================

use jiff::{civil, tz::TimeZone, Timestamp};

// ─────────────────────────────────────────────────────────────────────────────
// Helper: civil_utc
// A moment as a zone-less UTC datetime (what chrono called naive_utc()).
// ─────────────────────────────────────────────────────────────────────────────
pub fn civil_utc(t: Timestamp) -> civil::DateTime {
    t.to_zoned_datetime(TimeZone::UTC).datetime()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: utc_now
// The current time as a zone-less UTC datetime.
// ─────────────────────────────────────────────────────────────────────────────
pub fn utc_now() -> civil::DateTime {
    civil_utc(Timestamp::now())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: utc_now_fmt
// The current UTC time formatted with strftime, e.g. "%Y-%m-%d %H:%M:%S".
// ─────────────────────────────────────────────────────────────────────────────
pub fn utc_now_fmt(fmt: &str) -> String {
    Timestamp::now().strftime(fmt).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_are_utc_and_match_what_chrono_wrote() {
        let t: Timestamp = "2026-11-17T13:05:09.5Z".parse().unwrap();
        assert_eq!(t.strftime("%Y-%m-%d %H:%M:%S").to_string(), "2026-11-17 13:05:09");
        assert_eq!(t.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(), "2026-11-17T13:05:09Z");
        assert_eq!(civil_utc(t).strftime("%Y-%m-%dT%H:%M").to_string(), "2026-11-17T13:05");
        // Storage format with no seconds parses back.
        let d = civil::DateTime::strptime("%Y-%m-%dT%H:%M", "2026-11-17T13:05").unwrap();
        assert_eq!(d.second(), 0);
        // System.last_seen / created_date reach the pages and JSON as chrono
        // wrote them: RFC 3339 in UTC with a Z.
        let seen: Timestamp = "2026-11-17T13:05:09Z".parse().unwrap();
        assert_eq!(serde_json::to_string(&seen).unwrap(), "\"2026-11-17T13:05:09Z\"");
    }
}
