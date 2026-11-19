//! Long-term traffic history, for the whole machine and per application.
//!
//! Two tiers of time buckets (UTC, unix seconds):
//! * minutes, kept for 24 hours;
//! * hours, kept for 90 days.
//!
//! Daily totals per app over a longer span live in the usage database. Each
//! bucket stores the machine's interface totals plus the apps that moved data
//! in it (sparse), so memory and storage follow actual activity.
//!
//! Views ([`Range`]) pick the tier and point size that suit their span, from
//! one-minute points over the last hour to daily points over 90 days, with
//! empty points filled in so charts get a regular time axis.

use crate::model::AppId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

const MINUTE: i64 = 60;
const HOUR: i64 = 3600;
const DAY: i64 = 86_400;
const MINUTES_KEPT: i64 = DAY;
const HOURS_KEPT: i64 = 90 * DAY;

/// Bytes `[up, down]`.
pub type Bytes = [u64; 2];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bucket {
    /// Interface totals (all traffic, including what no app is known for).
    pub system: Bytes,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub apps: BTreeMap<AppId, Bytes>,
}

impl Bucket {
    fn add(&mut self, other: &Bucket) {
        add(&mut self.system, other.system);
        for (app, b) in &other.apps {
            add(self.apps.entry(app.clone()).or_default(), *b);
        }
    }
}

fn add(to: &mut Bytes, b: Bytes) {
    to[0] = to[0].saturating_add(b[0]);
    to[1] = to[1].saturating_add(b[1]);
}

/// A time span to view, with its resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Range {
    /// Last hour, one point per minute.
    Hour,
    /// Last 24 hours, one point per 5 minutes.
    Day,
    /// Last 7 days, one point per hour.
    Week,
    /// Last 30 days, one point per 6 hours.
    Month,
    /// Last 90 days, one point per day.
    Quarter,
}

impl Range {
    pub const ALL: [Range; 5] = [Range::Hour, Range::Day, Range::Week, Range::Month, Range::Quarter];

    /// `(span, point size)` in seconds.
    pub fn geometry(self) -> (i64, i64) {
        match self {
            Range::Hour => (HOUR, MINUTE),
            Range::Day => (DAY, 5 * MINUTE),
            Range::Week => (7 * DAY, HOUR),
            Range::Month => (30 * DAY, 6 * HOUR),
            Range::Quarter => (90 * DAY, DAY),
        }
    }

    /// Parses `hour`, `1h`, `day`, `24h`, `week`, `7d`, `month`, `30d`, `quarter`, `90d`.
    pub fn parse(s: &str) -> Option<Range> {
        Some(match s.to_ascii_lowercase().as_str() {
            "hour" | "1h" => Range::Hour,
            "day" | "24h" | "1d" => Range::Day,
            "week" | "7d" => Range::Week,
            "month" | "30d" => Range::Month,
            "quarter" | "90d" => Range::Quarter,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            Range::Hour => "Last hour",
            Range::Day => "Last 24 hours",
            Range::Week => "Last 7 days",
            Range::Month => "Last 30 days",
            Range::Quarter => "Last 90 days",
        }
    }
}

/// One point of a series: the bytes moved in `[t, t + step)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Point {
    /// Start of the point, unix seconds.
    pub t: i64,
    pub up: u64,
    pub down: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficHistory {
    #[serde(default)]
    minutes: BTreeMap<i64, Bucket>,
    #[serde(default)]
    hours: BTreeMap<i64, Bucket>,
}

impl TrafficHistory {
    /// Adds traffic observed at `now` (unix seconds).
    pub fn record<'a>(
        &mut self,
        now: i64,
        system: Bytes,
        apps: impl IntoIterator<Item = (&'a AppId, Bytes)>,
    ) {
        let mut sample = Bucket { system, apps: BTreeMap::new() };
        for (app, b) in apps {
            if b != [0, 0] {
                add(sample.apps.entry(app.clone()).or_default(), b);
            }
        }
        if sample.system == [0, 0] && sample.apps.is_empty() {
            return;
        }
        self.minutes.entry(now.div_euclid(MINUTE) * MINUTE).or_default().add(&sample);
        self.hours.entry(now.div_euclid(HOUR) * HOUR).or_default().add(&sample);
        self.prune(now);
    }

    fn prune(&mut self, now: i64) {
        let minute_cutoff = now - MINUTES_KEPT;
        while self.minutes.first_key_value().is_some_and(|(t, _)| *t < minute_cutoff) {
            self.minutes.pop_first();
        }
        let hour_cutoff = now - HOURS_KEPT;
        while self.hours.first_key_value().is_some_and(|(t, _)| *t < hour_cutoff) {
            self.hours.pop_first();
        }
    }

    fn tier(&self, step: i64) -> &BTreeMap<i64, Bucket> {
        if step < HOUR {
            &self.minutes
        } else {
            &self.hours
        }
    }

    /// Point starts covering `range` up to `now`, oldest first.
    fn grid(range: Range, now: i64) -> impl Iterator<Item = i64> {
        let (span, step) = range.geometry();
        let last = now.div_euclid(step) * step;
        let n = span / step;
        (0..n).rev().map(move |i| last - i * step)
    }

    /// Buckets summed per point of `range` (every point present, possibly empty).
    pub fn aggregate(&self, range: Range, now: i64) -> Vec<(i64, Bucket)> {
        let (_, step) = range.geometry();
        let mut points: Vec<(i64, Bucket)> = Self::grid(range, now).map(|t| (t, Bucket::default())).collect();
        let Some(first) = points.first().map(|p| p.0) else { return points };
        for (t, bucket) in self.tier(step).range(first..) {
            let i = ((t - first) / step) as usize;
            if let Some((_, point)) = points.get_mut(i) {
                point.add(bucket);
            }
        }
        points
    }

    /// The traffic of the machine (`app: None`) or one app over `range`.
    pub fn series(&self, range: Range, app: Option<&AppId>, now: i64) -> Vec<Point> {
        self.aggregate(range, now)
            .into_iter()
            .map(|(t, b)| {
                let [up, down] = match app {
                    None => b.system,
                    Some(a) => b.apps.get(a).copied().unwrap_or_default(),
                };
                Point { t, up, down }
            })
            .collect()
    }

    /// Per-app totals over `range`, most traffic first.
    pub fn top_apps(&self, range: Range, now: i64) -> Vec<(AppId, Bytes)> {
        let mut totals: HashMap<AppId, Bytes> = HashMap::new();
        for (_, b) in self.aggregate(range, now) {
            for (app, bytes) in b.apps {
                add(totals.entry(app).or_default(), bytes);
            }
        }
        let mut out: Vec<_> = totals.into_iter().collect();
        out.sort_by_key(|(app, b)| (std::cmp::Reverse(b[0] + b[1]), app.clone()));
        out
    }
}

/// CSV text: one row per point and app with traffic (long format, easy to
/// pivot in a spreadsheet). The machine's totals use the app `(all traffic)`.
pub fn to_csv(points: &[(i64, Bucket)], only: Option<&AppId>) -> String {
    fn field(s: &str) -> String {
        if s.contains([',', '"', '\n']) {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    }
    let mut out = String::from("time_utc,unix_time,app,upload_bytes,download_bytes\n");
    for (t, b) in points {
        let time =
            chrono::DateTime::from_timestamp(*t, 0).map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string());
        let time = time.unwrap_or_default();
        let mut row = |app: &str, [up, down]: Bytes| {
            out += &format!("{time},{t},{},{up},{down}\n", field(app));
        };
        match only {
            None => {
                row("(all traffic)", b.system);
                for (app, bytes) in &b.apps {
                    row(&app.0, *bytes);
                }
            }
            Some(app) => row(&app.0, b.apps.get(app).copied().unwrap_or_default()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(s: &str) -> AppId {
        AppId(s.into())
    }

    const T0: i64 = 1_794_960_000; // a UTC midnight

    #[test]
    fn records_into_both_tiers_and_aggregates() {
        let mut h = TrafficHistory::default();
        let (ff, steam) = (app("/usr/bin/firefox"), app("/opt/steam"));
        // Two samples in the same minute, one 3 minutes later.
        h.record(T0 + 10, [100, 1000], [(&ff, [10, 900])]);
        h.record(T0 + 50, [1, 2], [(&ff, [1, 2]), (&steam, [0, 0])]);
        h.record(T0 + 190, [5, 5000], [(&steam, [5, 5000])]);

        let now = T0 + 200;
        let hour = h.series(Range::Hour, None, now);
        assert_eq!(hour.len(), 60);
        assert_eq!(hour.last().unwrap().t, T0 + 180);
        let at = |t: i64| hour.iter().find(|p| p.t == t).copied().unwrap();
        assert_eq!((at(T0).up, at(T0).down), (101, 1002));
        assert_eq!(at(T0 + 60).down, 0, "empty minutes are filled");
        assert_eq!(h.series(Range::Hour, Some(&ff), now).iter().map(|p| p.down).sum::<u64>(), 902);

        // The 5-minute view puts everything in one point; the week view in one hour.
        let day = h.series(Range::Day, None, now);
        assert_eq!(day.len(), 288);
        assert_eq!(day.last().unwrap().down, 6002);
        assert_eq!(h.series(Range::Week, None, now).last().unwrap().down, 6002);

        let top = h.top_apps(Range::Day, now);
        assert_eq!(top[0], (steam.clone(), [5, 5000]));
        assert_eq!(top[1], (ff, [11, 902]));
        assert_eq!(top.len(), 2, "apps with zero traffic are not stored");
    }

    #[test]
    fn prunes_old_buckets_and_views_follow_now() {
        let mut h = TrafficHistory::default();
        h.record(T0, [1, 1], []);
        h.record(T0 + 2 * DAY, [2, 2], []);
        assert_eq!(h.minutes.len(), 1, "minutes older than a day are dropped");
        assert_eq!(h.hours.len(), 2);
        h.record(T0 + 100 * DAY, [3, 3], []);
        assert_eq!(h.hours.len(), 1, "hours older than 90 days are dropped");
        let q = h.series(Range::Quarter, None, T0 + 100 * DAY);
        assert_eq!(q.len(), 90);
        assert_eq!(q.iter().map(|p| p.up).sum::<u64>(), 3);
    }

    #[test]
    fn csv_long_format() {
        let mut h = TrafficHistory::default();
        h.record(T0 + 5, [7, 8], [(&app("/bin/a,b"), [1, 2])]);
        let points: Vec<_> = h.aggregate(Range::Hour, T0 + 30).into_iter().rev().take(1).collect();
        let csv = to_csv(&points, None);
        assert_eq!(
            csv,
            "time_utc,unix_time,app,upload_bytes,download_bytes\n\
             2026-11-18T00:00:00Z,1794960000,(all traffic),7,8\n\
             2026-11-18T00:00:00Z,1794960000,\"/bin/a,b\",1,2\n"
        );
        let one = to_csv(&points, Some(&app("/none")));
        assert!(one.ends_with("1794960000,/none,0,0\n"));
        assert_eq!(Range::parse("7d"), Some(Range::Week));
        assert_eq!(Range::parse("nope"), None);
    }
}
