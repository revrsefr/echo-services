//! Sliding-window event counters — the shared primitive behind every rate-based
//! detector (Sigyn/ozone's `isBadOnChannel`: N events of a kind, keyed by K,
//! within a T-second window). `now` is passed in (unix secs) so tests drive a
//! fake clock and the windows never touch wall time themselves.

use std::collections::{HashMap, VecDeque};

// One key's recent event timestamps, oldest first.
#[derive(Default)]
struct Window {
    at: VecDeque<u64>,
}

// A set of named sliding windows. `hit` records an event under a key and returns
// how many events fall within the window (this one included); the caller trips
// when that exceeds a configured permit. Keys are opaque strings the detectors
// build (e.g. "cf|<ip>"), never event-logged.
#[derive(Default)]
pub(crate) struct Counters {
    windows: HashMap<String, Window>,
    ops: u32, // GC cadence
}

impl Counters {
    // Record an event under `key` and return the count within the last `life`
    // seconds. Expiring on access keeps each window bounded by its own rate.
    pub fn hit(&mut self, key: &str, now: u64, life: u64) -> u32 {
        let cutoff = now.saturating_sub(life);
        let w = self.windows.entry(key.to_string()).or_default();
        while w.at.front().is_some_and(|&t| t < cutoff) {
            w.at.pop_front();
        }
        w.at.push_back(now);
        let n = w.at.len() as u32;
        self.maybe_gc(now);
        n
    }

    // Peek a key's current count without recording an event.
    pub fn count(&mut self, key: &str, now: u64, life: u64) -> u32 {
        let cutoff = now.saturating_sub(life);
        match self.windows.get_mut(key) {
            Some(w) => {
                while w.at.front().is_some_and(|&t| t < cutoff) {
                    w.at.pop_front();
                }
                w.at.len() as u32
            }
            None => 0,
        }
    }

    // Every so often, drop windows with no event in the last hour, so a churn of
    // one-off keys (unique IPs) can't grow the map without bound. Detector windows
    // are all far shorter than an hour, so this never discards live state.
    fn maybe_gc(&mut self, now: u64) {
        self.ops = self.ops.wrapping_add(1);
        if self.ops & 0x3ff != 0 {
            return;
        }
        let cutoff = now.saturating_sub(3600);
        self.windows.retain(|_, w| w.at.back().is_some_and(|&t| t >= cutoff));
    }
}

#[cfg(test)]
mod tests {
    use super::Counters;

    #[test]
    fn trips_only_within_window() {
        let mut c = Counters::default();
        // Six hits at t=100 within a 10s window: the count climbs 1..=6.
        for i in 1..=6 {
            assert_eq!(c.hit("k", 100, 10), i);
        }
        // A hit 11s later has aged all six out; only itself remains.
        assert_eq!(c.hit("k", 111, 10), 1);
    }

    #[test]
    fn keys_are_independent() {
        let mut c = Counters::default();
        assert_eq!(c.hit("a", 0, 10), 1);
        assert_eq!(c.hit("b", 0, 10), 1);
        assert_eq!(c.count("a", 0, 10), 1);
    }
}
