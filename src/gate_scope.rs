//! Job scope of the attack pattern gates.
//!
//! On a persistent CI runner the daemon and its finding history outlive the
//! job: a finding an earlier job left active (never triaged, never dismissed)
//! would fail every later job there. A gate therefore fails only on findings
//! first seen at or after its scope start; older active findings are reported
//! as warnings with their first-seen time and stay in the history untouched.
//!
//! - `attack-pattern-status --fail-on-findings --since <RFC 3339>`: the caller
//!   names the scope start (edamame_posture_action passes its job's setup
//!   time).
//! - The daemon's live gate (`--fail-on-findings --cancel-on-violation`):
//!   the job's setup time when the daemon inherited it
//!   ([`JOB_SETUP_TIME_ENV`], exported by edamame_posture_action to every
//!   later step of the job, hence to a daemon that job starts), otherwise the
//!   daemon's own start: a daemon never cancels a pipeline over a finding
//!   first seen before it ran.
//!
//! The first detection of a finding is the core's per-finding
//! `first_detected` (RFC 3339 UTC), reported since edamame_core 2.0.3. A
//! finding without a readable one counts: an undated finding is never assumed
//! to be old.

use serde_json::Value;

/// The start of the CI job's setup, RFC 3339 UTC. Exported by
/// edamame_posture_action (1.2.0 and later) to every later step of the job;
/// a daemon started by one of those steps inherits it.
pub const JOB_SETUP_TIME_ENV: &str = "EDAMAME_POSTURE_SETUP_TIME";

/// How far ahead of this host's clock a scope start may be. A later one
/// would let no finding fail the gate: it is refused, not trusted.
const MAX_FUTURE_SKEW_SECS: i64 = 300;

/// Parse a gate's `--since`: an RFC 3339 date-time that is not in the future.
pub fn parse_since(text: &str) -> Result<UtcTime, String> {
    let since = UtcTime::parse_rfc3339(text).ok_or_else(|| {
        format!(
            "--since '{}' is not an RFC 3339 date-time with an offset (for example 2026-09-29T08:00:00Z)",
            text
        )
    })?;
    if since > UtcTime::now().plus_secs(MAX_FUTURE_SKEW_SECS) {
        return Err(format!(
            "--since '{}' is in the future: no finding could fail the gate",
            text
        ));
    }
    Ok(since)
}

/// A UTC instant with nanosecond precision, ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UtcTime {
    secs: i64,
    nanos: u32,
}

impl UtcTime {
    pub fn now() -> Self {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => Self {
                secs: d.as_secs() as i64,
                nanos: d.subsec_nanos(),
            },
            Err(_) => Self { secs: 0, nanos: 0 },
        }
    }

    /// Parse an RFC 3339 date-time (`2026-09-29T08:00:00Z`,
    /// `2026-09-29T10:00:00.123+02:00`). `None` for anything else, including
    /// a date without a time or a time without an offset.
    pub fn parse_rfc3339(text: &str) -> Option<Self> {
        let b = text.trim().as_bytes();
        // YYYY-MM-DDTHH:MM:SS is 19 bytes, then an optional fraction, then
        // the offset (Z or +HH:MM / -HH:MM).
        if b.len() < 20 {
            return None;
        }
        let digits = |range: std::ops::Range<usize>| -> Option<u32> {
            let mut value = 0u32;
            for &c in &b[range] {
                if !c.is_ascii_digit() {
                    return None;
                }
                value = value * 10 + u32::from(c - b'0');
            }
            Some(value)
        };
        if b[4] != b'-' || b[7] != b'-' || b[13] != b':' || b[16] != b':' {
            return None;
        }
        if !matches!(b[10], b'T' | b't' | b' ') {
            return None;
        }
        let year = digits(0..4)? as i64;
        let month = digits(5..7)?;
        let day = digits(8..10)?;
        let hour = digits(11..13)?;
        let minute = digits(14..16)?;
        let second = digits(17..19)?;
        if !(1..=12).contains(&month)
            || day == 0
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 60
        {
            return None;
        }

        let mut i = 19;
        let mut nanos = 0u32;
        if b[i] == b'.' {
            i += 1;
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                if i - start < 9 {
                    nanos = nanos * 10 + u32::from(b[i] - b'0');
                }
                i += 1;
            }
            let fraction_digits = i - start;
            if fraction_digits == 0 {
                return None;
            }
            for _ in fraction_digits..9 {
                nanos *= 10;
            }
        }
        let offset_secs: i64 = match b.get(i..) {
            Some([b'Z' | b'z']) => 0,
            Some([sign @ (b'+' | b'-'), h1, h2, b':', m1, m2]) => {
                let pair = |hi: u8, lo: u8| -> Option<i64> {
                    if hi.is_ascii_digit() && lo.is_ascii_digit() {
                        Some(i64::from(hi - b'0') * 10 + i64::from(lo - b'0'))
                    } else {
                        None
                    }
                };
                let (oh, om) = (pair(*h1, *h2)?, pair(*m1, *m2)?);
                if oh > 23 || om > 59 {
                    return None;
                }
                let offset = oh * 3600 + om * 60;
                if *sign == b'+' {
                    offset
                } else {
                    -offset
                }
            }
            _ => return None,
        };

        let local = days_from_civil(year, month, day) * 86_400
            + i64::from(hour) * 3600
            + i64::from(minute) * 60
            + i64::from(second);
        Some(Self {
            secs: local - offset_secs,
            nanos,
        })
    }

    fn plus_secs(self, secs: i64) -> Self {
        Self {
            secs: self.secs + secs,
            nanos: self.nanos,
        }
    }

    /// RFC 3339 UTC to the second (`2026-09-29T08:00:00Z`).
    pub fn to_rfc3339(self) -> String {
        let days = self.secs.div_euclid(86_400);
        let rem = self.secs.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            year,
            month,
            day,
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60
        )
    }
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        _ => 28,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (i64::from(month) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Where a gate's scope starts, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateSince {
    pub since: UtcTime,
    /// What the time is, for the messages: "this job's setup" or "this
    /// daemon's start".
    pub origin: &'static str,
}

impl GateSince {
    /// The live gate's scope for this daemon: the job's setup time it
    /// inherited ([`JOB_SETUP_TIME_ENV`]) when valid and not in the future,
    /// otherwise now (the daemon's start). Read once, when the daemon starts.
    pub fn for_this_daemon() -> Self {
        Self::from_job_setup_time(std::env::var(JOB_SETUP_TIME_ENV).ok().as_deref())
    }

    fn from_job_setup_time(job_setup_time: Option<&str>) -> Self {
        let now = UtcTime::now();
        match job_setup_time.and_then(UtcTime::parse_rfc3339) {
            Some(since) if since <= now.plus_secs(MAX_FUTURE_SKEW_SECS) => Self {
                since,
                origin: "this job's setup",
            },
            _ => Self {
                since: now,
                origin: "this daemon's start",
            },
        }
    }
}

/// One active HIGH/CRITICAL finding of a scoped gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedFinding {
    pub finding_key: String,
    /// `SEVERITY check (key K)[, process P][, destination D]`.
    pub label: String,
    /// The finding's `first_detected` as reported, when readable.
    pub first_detected: Option<String>,
}

impl ScopedFinding {
    /// `label: first seen <time>` (or "first seen at an unknown time").
    pub fn describe(&self) -> String {
        match &self.first_detected {
            Some(first) => format!("{}: first seen {}", self.label, first),
            None => format!(
                "{}: first seen at an unknown time (the daemon does not report it)",
                self.label
            ),
        }
    }
}

/// The active HIGH/CRITICAL findings of a report, split at a scope start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopedFindings {
    /// First seen at or after the scope start, or undated: these fail the
    /// gate.
    pub current: Vec<ScopedFinding>,
    /// First seen before the scope start: warnings only.
    pub older: Vec<ScopedFinding>,
}

impl ScopedFindings {
    pub fn alertable(&self) -> usize {
        self.current.len() + self.older.len()
    }

    pub fn undated(&self) -> usize {
        self.current
            .iter()
            .filter(|f| f.first_detected.is_none())
            .count()
    }
}

/// Split the active HIGH/CRITICAL findings of a `get_attack_pattern_findings`
/// report at `since`. `None` when the text is not such a report (an error
/// document, unparseable JSON): the caller then counts every finding.
pub fn scope_findings(report_json: &str, since: UtcTime) -> Option<ScopedFindings> {
    let report: Value = serde_json::from_str(report_json).ok()?;
    let findings = match report.get("findings")? {
        Value::Null => return Some(ScopedFindings::default()),
        Value::Array(findings) => findings,
        _ => return None,
    };
    let text = |finding: &Value, field: &str| -> String {
        finding
            .get(field)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    };
    let mut scoped = ScopedFindings::default();
    for finding in findings {
        let dismissed = finding
            .get("dismissed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let severity = text(finding, "severity").to_ascii_uppercase();
        if dismissed || !(severity == "HIGH" || severity == "CRITICAL") {
            continue;
        }
        let finding_key = text(finding, "finding_key");
        let check = text(finding, "check");
        let mut label = format!(
            "{} {} (key {})",
            severity,
            if check.is_empty() { "?" } else { check.as_str() },
            if finding_key.is_empty() {
                "?"
            } else {
                finding_key.as_str()
            }
        );
        let process = text(finding, "process_name");
        if !process.is_empty() {
            label.push_str(&format!(", process {}", process));
        }
        let destination = Some(text(finding, "destination_domain"))
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| text(finding, "destination_ip"));
        if !destination.is_empty() {
            label.push_str(&format!(", destination {}", destination));
        }
        let first_text = text(finding, "first_detected");
        let first = UtcTime::parse_rfc3339(&first_text);
        let entry = ScopedFinding {
            finding_key,
            label,
            first_detected: first.map(|_| first_text),
        };
        match first {
            Some(first) if first < since => scoped.older.push(entry),
            _ => scoped.current.push(entry),
        }
    }
    Some(scoped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> UtcTime {
        UtcTime::parse_rfc3339(text).unwrap_or_else(|| panic!("{} should parse", text))
    }

    #[test]
    fn rfc3339_parses_offsets_and_fractions() {
        assert_eq!(at("1970-01-01T00:00:00Z"), UtcTime { secs: 0, nanos: 0 });
        assert_eq!(
            at("2026-09-29T08:00:00Z").to_rfc3339(),
            "2026-09-29T08:00:00Z"
        );
        // The same instant in three spellings.
        assert_eq!(at("2026-09-29T10:00:00+02:00"), at("2026-09-29T08:00:00Z"));
        assert_eq!(at("2026-09-29T03:30:00-04:30"), at("2026-09-29T08:00:00Z"));
        assert_eq!(at("2026-09-29T08:00:00+00:00"), at("2026-09-29T08:00:00z"));
        // Fractions: chrono serializes 0, 3, 6 or 9 digits.
        assert_eq!(
            at("2026-09-28T17:57:03.5Z"),
            UtcTime {
                secs: at("2026-09-28T17:57:03Z").secs,
                nanos: 500_000_000
            }
        );
        assert_eq!(at("2026-09-28T17:57:03.123456789Z").nanos, 123_456_789);
        assert_eq!(at("2026-09-28T17:57:03.1234567891Z").nanos, 123_456_789);
        assert!(at("2026-09-28T17:57:03.000001Z") > at("2026-09-28T17:57:03Z"));
        // Leap years and a pre-epoch date.
        assert_eq!(at("2024-02-29T00:00:00Z").to_rfc3339(), "2024-02-29T00:00:00Z");
        assert_eq!(at("1969-12-31T23:59:59Z").secs, -1);
        assert_eq!(
            at("2000-03-01T00:00:00Z").secs - at("2000-02-28T00:00:00Z").secs,
            2 * 86_400
        );
    }

    #[test]
    fn rfc3339_rejects_what_is_not_a_date_time_with_offset() {
        for bad in [
            "",
            "2026-09-29",
            "2026-09-29T08:00:00",
            "2026-09-29T08:00Z",
            "2026-09-29T08:00:00.Z",
            "2026-13-01T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2026-09-31T00:00:00Z",
            "2026-09-29T24:00:00Z",
            "2026-09-29T08:00:00+2:00",
            "2026-09-29T08:00:00+0200",
            "2026-09-29T08:00:00ZZ",
            "yesterday",
            "1790681588",
        ] {
            assert_eq!(UtcTime::parse_rfc3339(bad), None, "{:?}", bad);
        }
    }

    #[test]
    fn now_round_trips_to_the_second() {
        let now = UtcTime::now();
        let again = at(&now.to_rfc3339());
        assert_eq!(again.secs, now.secs);
    }

    #[test]
    fn job_setup_time_wins_over_the_daemon_start_when_valid() {
        let scope = GateSince::from_job_setup_time(Some("2026-09-29T08:00:00Z"));
        assert_eq!(scope.since, at("2026-09-29T08:00:00Z"));
        assert_eq!(scope.origin, "this job's setup");

        let tomorrow = UtcTime::now().plus_secs(86_400).to_rfc3339();
        for unusable in [None, Some(""), Some("not a time"), Some(tomorrow.as_str())] {
            let before = UtcTime::now();
            let scope = GateSince::from_job_setup_time(unusable);
            assert_eq!(scope.origin, "this daemon's start", "{:?}", unusable);
            assert!(scope.since >= before);
        }
    }

    #[test]
    fn since_must_be_a_date_time_that_is_not_in_the_future() {
        assert_eq!(
            parse_since("2026-09-29T08:00:00Z"),
            Ok(at("2026-09-29T08:00:00Z"))
        );
        assert!(parse_since(&UtcTime::now().to_rfc3339()).is_ok());
        // Clock skew within five minutes is tolerated.
        assert!(parse_since(&UtcTime::now().plus_secs(60).to_rfc3339()).is_ok());
        let err = parse_since(&UtcTime::now().plus_secs(3600).to_rfc3339()).unwrap_err();
        assert!(err.contains("in the future"), "{}", err);
        let err = parse_since("2026-09-29").unwrap_err();
        assert!(err.contains("not an RFC 3339 date-time"), "{}", err);
    }

    const REPORT: &str = r#"{
        "report_id": "r1",
        "timestamp": "2026-09-29T09:00:00Z",
        "findings": [
            {"finding_key": "vuln:old", "check": "credential_harvest", "severity": "HIGH",
             "dismissed": false, "process_name": "python3", "destination_domain": "evil.example",
             "first_detected": "2026-09-28T17:57:03.250Z"},
            {"finding_key": "vuln:new", "check": "token_exfiltration", "severity": "critical",
             "dismissed": false, "destination_ip": "203.0.113.7",
             "first_detected": "2026-09-29T08:00:00Z"},
            {"finding_key": "vuln:undated", "check": "sandbox_exploitation", "severity": "HIGH",
             "dismissed": false},
            {"finding_key": "vuln:low", "check": "file_system_tampering", "severity": "LOW",
             "dismissed": false, "first_detected": "2026-09-29T09:00:00Z"},
            {"finding_key": "vuln:dismissed", "check": "credential_harvest", "severity": "CRITICAL",
             "dismissed": true, "first_detected": "2026-09-29T09:00:00Z"}
        ]
    }"#;

    #[test]
    fn findings_split_at_the_scope_start() {
        let scoped = scope_findings(REPORT, at("2026-09-29T08:00:00Z")).unwrap();
        let keys = |list: &[ScopedFinding]| -> Vec<String> {
            list.iter().map(|f| f.finding_key.clone()).collect()
        };
        // At the scope start counts; an undated finding counts; LOW and
        // dismissed findings are not alertable.
        assert_eq!(keys(&scoped.current), ["vuln:new", "vuln:undated"]);
        assert_eq!(keys(&scoped.older), ["vuln:old"]);
        assert_eq!(scoped.alertable(), 3);
        assert_eq!(scoped.undated(), 1);
        assert_eq!(
            scoped.older[0].describe(),
            "HIGH credential_harvest (key vuln:old), process python3, destination evil.example: first seen 2026-09-28T17:57:03.250Z"
        );
        assert_eq!(
            scoped.current[0].label,
            "CRITICAL token_exfiltration (key vuln:new), destination 203.0.113.7"
        );
        assert!(scoped.current[1].describe().contains("unknown time"));

        // A scope that starts before everything: nothing is older.
        let scoped = scope_findings(REPORT, at("2026-01-01T00:00:00Z")).unwrap();
        assert!(scoped.older.is_empty());
        assert_eq!(scoped.current.len(), 3);
    }

    #[test]
    fn no_report_is_empty_and_an_error_document_is_unreadable() {
        let since = at("2026-09-29T08:00:00Z");
        assert_eq!(
            scope_findings(r#"{"findings": null}"#, since),
            Some(ScopedFindings::default())
        );
        assert_eq!(scope_findings(r#"{"error": "boom"}"#, since), None);
        assert_eq!(scope_findings("not json", since), None);
        assert_eq!(scope_findings(r#"{"findings": 3}"#, since), None);
    }
}
