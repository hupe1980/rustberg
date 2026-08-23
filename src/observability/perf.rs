//! Measuring the four numbers this project claims.
//!
//! # Why this exists in the library rather than in a test
//!
//! `rustberg bench` and the CI gate must measure the *same* thing. Two
//! implementations of "authorization overhead" would drift, and the one an
//! operator runs would stop corresponding to the one that fails the build —
//! which is how a performance claim quietly becomes untrue while everything
//! still passes.
//!
//! # What is measured, and what is not
//!
//! These are **latencies of the work Rustberg does**, not throughput and not a
//! load test. A catalog request is a policy decision plus a pointer lookup; if
//! either regresses by an order of magnitude, that is a bug worth failing a
//! build over. Requests per second on a particular machine is a different
//! question, answered by a load generator against a deployed server.
//!
//! # On thresholds
//!
//! [`Budget`] carries a *ceiling*, deliberately looser than the design target.
//! CI runners are shared and noisy, and a gate that flakes gets disabled, at
//! which point it protects nothing. The ceilings here catch order-of-magnitude
//! regressions — the kind that come from an accidental clone in a hot path or a
//! lock held across an await — while the reported measurement tells the truth
//! about where the number actually sits.

use std::time::{Duration, Instant};

/// One measured latency distribution.
#[derive(Debug, Clone)]
pub struct Measurement {
    /// What was measured.
    pub name: &'static str,
    /// How many samples were taken.
    pub samples: usize,
    /// Fastest observed.
    pub min: Duration,
    /// Median.
    pub p50: Duration,
    /// 99th percentile — the number that matters, because it is what a client
    /// waiting on a slow request actually experiences.
    pub p99: Duration,
    /// Slowest observed.
    pub max: Duration,
}

impl Measurement {
    /// Builds a measurement from raw samples.
    ///
    /// # Panics
    ///
    /// Panics when `samples` is empty; a measurement of nothing has no meaning
    /// and returning zeros would report a passing benchmark that ran nothing.
    pub fn from_samples(name: &'static str, mut samples: Vec<Duration>) -> Self {
        assert!(!samples.is_empty(), "{name}: no samples were taken");
        samples.sort_unstable();

        let count = samples.len();
        // Nearest-rank: the smallest value at or above the requested percentile.
        // Interpolating between samples would invent a latency nothing observed.
        let at = |percentile: f64| {
            let rank = ((percentile * count as f64).ceil() as usize).clamp(1, count);
            samples[rank - 1]
        };

        Self {
            name,
            samples: count,
            min: samples[0],
            p50: at(0.50),
            p99: at(0.99),
            max: samples[count - 1],
        }
    }

    /// One line, for a terminal.
    pub fn describe(&self) -> String {
        format!(
            "{:<28} n={:<6} min={:>10?}  p50={:>10?}  p99={:>10?}  max={:>10?}",
            self.name, self.samples, self.min, self.p50, self.p99, self.max
        )
    }
}

/// A ceiling a measurement must stay under.
///
/// Separate from the design target on purpose: see the module docs.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    /// The number the architecture is chosen to hit, for reporting.
    pub target: Duration,
    /// The number that fails the build.
    pub ceiling: Duration,
}

impl Budget {
    /// A budget with a target and a regression ceiling.
    pub const fn new(target: Duration, ceiling: Duration) -> Self {
        Self { target, ceiling }
    }

    /// Whether `measurement` is within the ceiling.
    pub fn admits(&self, measurement: &Measurement) -> bool {
        measurement.p99 <= self.ceiling
    }

    /// Why a measurement failed, phrased for whoever broke the build.
    pub fn explain(&self, measurement: &Measurement) -> String {
        format!(
            "{} regressed: p99 is {:?}, over the {:?} ceiling (design target {:?}). \
             This gate catches order-of-magnitude regressions, so exceeding it usually \
             means work was added to a hot path rather than that the machine is slow.",
            measurement.name, measurement.p99, self.ceiling, self.target
        )
    }
}

/// Times `iterations` runs of `operation`, discarding a warm-up.
///
/// The warm-up matters more than it looks: the first calls pay for lazily
/// initialised caches and cold branch predictors, and including them would make
/// p99 a measurement of start-up rather than of steady state.
pub fn measure<F>(name: &'static str, iterations: usize, mut operation: F) -> Measurement
where
    F: FnMut(),
{
    let warmup = (iterations / 10).max(1);
    for _ in 0..warmup {
        operation();
    }

    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        operation();
        samples.push(started.elapsed());
    }

    Measurement::from_samples(name, samples)
}

/// Times `iterations` runs of an async operation.
pub async fn measure_async<F, Fut>(
    name: &'static str,
    iterations: usize,
    mut operation: F,
) -> Measurement
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let warmup = (iterations / 10).max(1);
    for _ in 0..warmup {
        operation().await;
    }

    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        operation().await;
        samples.push(started.elapsed());
    }

    Measurement::from_samples(name, samples)
}

/// Resident set size of this process, in bytes.
///
/// `None` where it cannot be read without platform-specific unsafe code. macOS
/// needs `task_info`, which this crate will not carry for a diagnostic — so the
/// footprint number is reported on Linux, where CI runs, and omitted elsewhere
/// rather than guessed at.
pub fn resident_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        // `statm` is two integers: total pages, then resident pages.
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let resident_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        // 4 KiB is the page size on every architecture this ships for.
        Some(resident_pages * 4096)
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn percentiles_come_from_observed_samples() {
        let samples: Vec<Duration> = (1..=100).map(ms).collect();
        let measurement = Measurement::from_samples("test", samples);

        assert_eq!(measurement.min, ms(1));
        assert_eq!(measurement.max, ms(100));
        assert_eq!(measurement.p50, ms(50));
        assert_eq!(measurement.p99, ms(99));
    }

    /// Nearest-rank, so every reported figure is a latency something actually
    /// took. Interpolation would invent one.
    #[test]
    fn a_percentile_is_never_interpolated() {
        let measurement = Measurement::from_samples("test", vec![ms(1), ms(100)]);
        assert!(
            measurement.p50 == ms(1) || measurement.p50 == ms(100),
            "p50 must be an observed sample, got {:?}",
            measurement.p50
        );
    }

    #[test]
    fn a_single_sample_is_every_percentile() {
        let measurement = Measurement::from_samples("test", vec![ms(7)]);
        assert_eq!(measurement.p50, ms(7));
        assert_eq!(measurement.p99, ms(7));
        assert_eq!(measurement.min, ms(7));
        assert_eq!(measurement.max, ms(7));
    }

    #[test]
    #[should_panic(expected = "no samples")]
    fn measuring_nothing_is_an_error_not_a_zero() {
        // Reporting zeros here would be a benchmark that passes having run
        // nothing at all.
        Measurement::from_samples("test", Vec::new());
    }

    #[test]
    fn a_budget_admits_what_is_under_its_ceiling() {
        let budget = Budget::new(ms(1), ms(10));
        let fast = Measurement::from_samples("fast", vec![ms(2)]);
        let slow = Measurement::from_samples("slow", vec![ms(50)]);

        assert!(budget.admits(&fast));
        assert!(!budget.admits(&slow));
    }

    /// A failure message has to tell whoever broke the build what to look at.
    #[test]
    fn a_budget_failure_names_both_numbers() {
        let budget = Budget::new(ms(1), ms(10));
        let slow = Measurement::from_samples("authorization", vec![ms(50)]);
        let message = budget.explain(&slow);

        assert!(message.contains("authorization"));
        assert!(message.contains("50ms"), "{message}");
        assert!(message.contains("10ms"), "{message}");
        assert!(message.contains("hot path"), "points at the likely cause");
    }

    #[test]
    fn measure_discards_a_warmup_and_keeps_the_asked_for_count() {
        let mut calls = 0usize;
        let measurement = measure("counter", 50, || calls += 1);

        assert_eq!(
            measurement.samples, 50,
            "the reported count is the timed one"
        );
        assert!(calls > 50, "a warm-up ran before timing began");
    }

    #[tokio::test]
    async fn measure_async_times_the_future() {
        let measurement = measure_async("async", 20, || async {
            tokio::task::yield_now().await;
        })
        .await;
        assert_eq!(measurement.samples, 20);
    }

    #[test]
    fn a_description_is_one_readable_line() {
        let measurement = Measurement::from_samples("loadTable", vec![ms(1), ms(2), ms(3)]);
        let line = measurement.describe();

        assert!(line.contains("loadTable"));
        assert!(line.contains("p99"));
        assert!(!line.contains('\n'), "one line: {line}");
    }
}
