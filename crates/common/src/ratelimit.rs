//! Sliding-window rate limiter for public requests.
//!
//! Counts are kept for the current whole minute and the one before it. A
//! request is measured against `previous * (60 - s) / 60 + current`, where `s`
//! is the seconds elapsed in the current minute, so the previous minute's use
//! fades out over the following minute instead of vanishing at the boundary.
//! A caller that spends its whole budget just before a boundary gets it back
//! gradually, not all at once: a burst across the boundary is capped at one
//! budget, and after that the budget returns at about `budget / 60` a second.
//!
//! The estimate assumes the previous minute's requests were spread evenly, so
//! it is not a strict "at most N in any 60 seconds"; a caller that spends its
//! budget early in one minute can spend most of it again late in the next.
//!
//! Memory is bounded by construction: a key only gets an entry when the global
//! budget still has room, so at most `global_per_min` keys exist per minute
//! and `2 * global_per_min` in all.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

#[derive(Default)]
struct Counts {
    global: u32,
    keys: HashMap<String, u32>,
}

struct Window {
    minute: u64,
    prev: Counts,
    cur: Counts,
}

impl Window {
    /// Move the window to `minute`. The current minute becomes the previous
    /// one when the clock moved on by exactly one minute; any other change
    /// (a gap, or the clock going backwards) starts again from nothing.
    fn advance(&mut self, minute: u64) {
        if self.minute == minute {
            return;
        }
        self.prev = if minute == self.minute + 1 {
            std::mem::take(&mut self.cur)
        } else {
            self.cur = Counts::default();
            Counts::default()
        };
        self.minute = minute;
    }
}

/// Whether `prev` weighted by the `rest` of 60 seconds still left, plus `cur`,
/// has reached `limit`, in integers.
fn spent(prev: u32, cur: u32, rest: u64, limit: u32) -> bool {
    u64::from(prev) * rest + u64::from(cur) * 60 >= u64::from(limit) * 60
}

/// Per-key and global request budget per minute.
pub struct RateLimiter {
    global_per_min: AtomicU32,
    per_key_per_min: AtomicU32,
    window: Mutex<Window>,
}

impl RateLimiter {
    pub fn new(global_per_min: u32, per_key_per_min: u32) -> Self {
        RateLimiter {
            global_per_min: AtomicU32::new(global_per_min),
            per_key_per_min: AtomicU32::new(per_key_per_min),
            window: Mutex::new(Window {
                minute: 0,
                prev: Counts::default(),
                cur: Counts::default(),
            }),
        }
    }

    /// Change both budgets; takes effect immediately.
    pub fn set_limits(&self, global_per_min: u32, per_key_per_min: u32) {
        self.global_per_min.store(global_per_min, Ordering::Relaxed);
        self.per_key_per_min.store(per_key_per_min, Ordering::Relaxed);
    }

    fn decide(&self, key: &str, now: u64, consume: bool) -> bool {
        let mut w = self.window.lock().unwrap_or_else(|p| p.into_inner());
        w.advance(now / 60);
        let rest = 60 - now % 60;
        if spent(
            w.prev.global,
            w.cur.global,
            rest,
            self.global_per_min.load(Ordering::Relaxed),
        ) {
            return false;
        }
        let before = w.prev.keys.get(key).copied().unwrap_or(0);
        let used = w.cur.keys.get(key).copied().unwrap_or(0);
        if spent(before, used, rest, self.per_key_per_min.load(Ordering::Relaxed)) {
            return false;
        }
        if consume {
            w.cur.keys.insert(key.to_string(), used + 1);
            w.cur.global += 1;
        }
        true
    }

    /// Consume one unit for `key` at unix time `now`. `false` means refuse.
    pub fn allow(&self, key: &str, now: u64) -> bool {
        self.decide(key, now, true)
    }

    /// Whether `allow` would currently succeed, without consuming anything.
    pub fn would_allow(&self, key: &str, now: u64) -> bool {
        self.decide(key, now, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(rl: &RateLimiter) -> usize {
        let w = rl.window.lock().unwrap();
        w.prev.keys.len() + w.cur.keys.len()
    }

    fn burst(rl: &RateLimiter, key: &str, now: u64, tries: u32) -> u32 {
        (0..tries).filter(|_| rl.allow(key, now)).count() as u32
    }

    #[test]
    fn per_key_and_global_budgets() {
        let rl = RateLimiter::new(5, 2);
        assert!(rl.would_allow("a", 60));
        assert!(rl.would_allow("a", 60), "checking consumes nothing");
        assert!(rl.allow("a", 60));
        assert!(rl.allow("a", 61));
        assert!(!rl.would_allow("a", 62));
        assert!(!rl.allow("a", 62), "key budget spent");
        assert!(rl.allow("b", 62));
        assert!(rl.allow("b", 63));
        assert!(rl.allow("c", 64));
        assert!(!rl.would_allow("d", 65));
        assert!(!rl.allow("d", 65), "global budget spent");
        assert_eq!(keys(&rl), 3, "refused keys take no memory");
        // Two minutes on, the old use has faded out entirely.
        assert!(rl.allow("a", 180));
        assert!(rl.allow("d", 181));
        assert_eq!(keys(&rl), 2);
    }

    #[test]
    fn no_double_budget_across_a_boundary() {
        // The burst from issue #92: a full budget in the last second of one
        // minute, then again in the first second of the next.
        let rl = RateLimiter::new(30, 30);
        let first = burst(&rl, "attacker", 59, 100);
        let second = burst(&rl, "attacker", 60, 100);
        assert_eq!(first, 30);
        assert_eq!(second, 0, "the previous minute still counts in full");
        assert_eq!(first + second, 30);
        // After that it comes back about one-sixtieth of the budget a second.
        assert_eq!(burst(&rl, "attacker", 61, 100), 1);
        assert_eq!(burst(&rl, "attacker", 62, 100), 0, "half a request a second");
        assert_eq!(burst(&rl, "attacker", 63, 100), 1);

        // The same holds for the global budget, spread over many keys.
        let rl = RateLimiter::new(30, 1);
        let first = (0..100).filter(|i| rl.allow(&format!("k{i}"), 119)).count();
        let second = (100..200).filter(|i| rl.allow(&format!("k{i}"), 120)).count();
        assert_eq!((first, second), (30, 0));
    }

    #[test]
    fn budget_comes_back_gradually() {
        let rl = RateLimiter::new(1000, 6);
        assert_eq!(burst(&rl, "a", 59, 10), 6);
        // Halfway through the next minute, half the old use still counts.
        assert_eq!(burst(&rl, "a", 90, 10), 3);
        // Near its end, almost all of the budget is back.
        let rl = RateLimiter::new(1000, 6);
        assert_eq!(burst(&rl, "a", 59, 10), 6);
        assert_eq!(burst(&rl, "a", 110, 10), 5);
        // A minute with no use at all forgets everything.
        let rl = RateLimiter::new(1000, 6);
        assert_eq!(burst(&rl, "a", 59, 10), 6);
        assert_eq!(burst(&rl, "a", 120, 10), 6);
    }

    #[test]
    fn clock_going_backwards_starts_over() {
        let rl = RateLimiter::new(5, 2);
        assert_eq!(burst(&rl, "a", 600, 5), 2);
        assert_eq!(burst(&rl, "a", 540, 5), 2);
        assert_eq!(keys(&rl), 1);
    }

    #[test]
    fn new_limits_take_effect_at_once() {
        let rl = RateLimiter::new(5, 1);
        assert!(rl.allow("a", 60));
        assert!(!rl.allow("a", 61), "key budget spent");
        rl.set_limits(5, 2);
        assert!(rl.allow("a", 62), "the key's budget grew");
        rl.set_limits(2, 2);
        assert!(!rl.allow("b", 63), "the global budget shrank");
    }

    #[test]
    fn survives_a_poisoned_lock() {
        let rl = std::sync::Arc::new(RateLimiter::new(5, 2));
        let r2 = rl.clone();
        let _ = std::thread::spawn(move || {
            let _held = r2.window.lock().unwrap();
            panic!("poison");
        })
        .join();
        assert!(rl.allow("a", 60));
    }
}
