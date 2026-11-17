//! Traffic spike detection: "Dropbox is uploading at 8 MB/s" when an app
//! goes well above its own usual rate.
//!
//! Each app and direction keeps a running "usual" rate: the plain average
//! over its first few minutes, then an exponential average over about five
//! minutes. A spike is a rate that is both large in absolute terms and
//! several times the usual one, held for a few consecutive samples. After an
//! alert the same app and direction stays quiet for a cooldown, and a long
//! transfer gradually becomes "usual" and stops counting as a spike.

use crate::model::{AppId, Direction};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SpikeConfig {
    /// Ignore rates below this, in bytes/s.
    pub min_rate: u64,
    /// A spike is at least this many times the usual rate.
    pub factor: f64,
    /// Consecutive samples the rate must stay high.
    pub sustain: u32,
    /// Samples of history an app needs before it can spike.
    pub warmup: u32,
    /// Samples the "usual" rate averages over once warmed up.
    pub horizon: u32,
    /// Quiet time after an alert, per app and direction, in ms.
    pub cooldown_ms: u64,
}

impl Default for SpikeConfig {
    fn default() -> Self {
        Self {
            min_rate: 1_000_000,
            factor: 5.0,
            sustain: 3,
            warmup: 10,
            horizon: 300,
            cooldown_ms: 15 * 60 * 1000,
        }
    }
}

/// A detected spike.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spike {
    pub app: AppId,
    /// `In` for downloads, `Out` for uploads.
    pub direction: Direction,
    /// Current rate, bytes/s.
    pub rate: u64,
    /// The app's usual rate before the spike, bytes/s.
    pub usual: u64,
}

#[derive(Debug, Clone, Default)]
struct Track {
    usual: f64,
    samples: u32,
    over: u32,
    /// The usual rate when the current run of high samples began.
    usual_before: f64,
    last_alert_ms: Option<u64>,
}

impl Track {
    /// Feeds one sample; returns the usual rate if this sample completes a spike.
    fn observe(&mut self, rate: u64, now_ms: u64, cfg: &SpikeConfig) -> Option<u64> {
        let usual = self.usual;
        let high = self.samples >= cfg.warmup && rate >= cfg.min_rate && rate as f64 >= cfg.factor * usual;
        self.over = if high { self.over + 1 } else { 0 };
        if self.over == 1 {
            self.usual_before = usual;
        }
        let cooled = self.last_alert_ms.map_or(true, |t| now_ms.saturating_sub(t) >= cfg.cooldown_ms);
        let alert = self.over == cfg.sustain && cooled;
        if alert {
            self.last_alert_ms = Some(now_ms);
        }
        // Plain average while young, then exponential over `horizon`.
        self.samples = self.samples.saturating_add(1);
        let weight = 1.0 / self.samples.min(cfg.horizon) as f64;
        self.usual += (rate as f64 - self.usual) * weight;
        // Report the usual rate from before the spike began, not one already
        // raised by its first samples.
        alert.then_some(self.usual_before as u64)
    }
}

#[derive(Debug, Default)]
pub struct SpikeDetector {
    config: SpikeConfig,
    tracks: HashMap<(AppId, bool), Track>,
}

impl SpikeDetector {
    pub fn new(config: SpikeConfig) -> Self {
        Self { config, tracks: HashMap::new() }
    }

    /// Feeds one sample of an app's rates (bytes/s); returns any spikes.
    pub fn observe(&mut self, app: &AppId, rate_up: u64, rate_down: u64, now_ms: u64) -> Vec<Spike> {
        let mut out = Vec::new();
        for (upload, rate) in [(false, rate_down), (true, rate_up)] {
            let track = self.tracks.entry((app.clone(), upload)).or_default();
            if let Some(usual) = track.observe(rate, now_ms, &self.config) {
                let direction = if upload { Direction::Out } else { Direction::In };
                out.push(Spike { app: app.clone(), direction, rate, usual });
            }
        }
        out
    }

    /// Forgets apps that are no longer around.
    pub fn retain(&mut self, keep: impl Fn(&AppId) -> bool) {
        self.tracks.retain(|(app, _), _| keep(app));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MB: u64 = 1_000_000;

    fn run(d: &mut SpikeDetector, app: &AppId, start: u64, rates: &[(u64, u64)]) -> Vec<Spike> {
        rates
            .iter()
            .enumerate()
            .flat_map(|(i, &(up, down))| d.observe(app, up, down, (start + i as u64) * 1000))
            .collect()
    }

    #[test]
    fn steady_heavy_traffic_is_not_a_spike() {
        let mut d = SpikeDetector::default();
        let steam = AppId("steam".into());
        assert!(run(&mut d, &steam, 0, &[(20_000, 6 * MB); 120]).is_empty());
    }

    #[test]
    fn a_sustained_jump_alerts_once() {
        let mut d = SpikeDetector::default();
        let dropbox = AppId("dropbox".into());
        assert!(run(&mut d, &dropbox, 0, &[(5_000, 2_000); 60]).is_empty());
        // Two high samples are not enough...
        assert!(run(&mut d, &dropbox, 60, &[(8 * MB, 2_000); 2]).is_empty());
        // ...the third is, and only one alert follows while it stays high.
        let spikes = run(&mut d, &dropbox, 62, &[(8 * MB, 2_000); 30]);
        assert_eq!(spikes.len(), 1);
        assert_eq!(spikes[0].direction, Direction::Out);
        assert_eq!(spikes[0].rate, 8 * MB);
        assert_eq!(spikes[0].usual, 5_000, "usual is the rate from before the spike");
    }

    #[test]
    fn cooldown_and_small_rates() {
        let cfg = SpikeConfig { cooldown_ms: 60_000, ..Default::default() };
        let mut d = SpikeDetector::new(cfg);
        let app = AppId("x".into());
        run(&mut d, &app, 0, &[(0, 1_000); 20]);
        assert_eq!(run(&mut d, &app, 20, &[(0, 3 * MB); 3]).len(), 1);
        run(&mut d, &app, 23, &[(0, 1_000); 5]);
        // Within the cooldown: quiet.
        assert!(run(&mut d, &app, 28, &[(0, 3 * MB); 3]).is_empty());
        // Below the absolute minimum, even 100x the usual rate is fine.
        let mut d = SpikeDetector::default();
        let quiet = AppId("quiet".into());
        run(&mut d, &quiet, 0, &[(0, 100); 20]);
        assert!(run(&mut d, &quiet, 20, &[(0, 500_000); 10]).is_empty());
    }

    #[test]
    fn needs_history_before_alerting() {
        let mut d = SpikeDetector::default();
        let new = AppId("new".into());
        assert!(run(&mut d, &new, 0, &[(0, 9 * MB); 5]).is_empty(), "a brand-new app has no usual rate yet");
    }
}
