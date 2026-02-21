//! Statistical calculations for timing samples.

use crate::TimingStats;

/// Calculate statistics from timing samples.
///
/// # Arguments
/// * `samples` - Slice of timing samples in microseconds
///
/// # Returns
/// A TimingStats struct with mean, std, p50, and p90 values.
/// Returns empty stats if samples is empty.
pub fn calculate_stats(samples: &[f64]) -> TimingStats {
    if samples.is_empty() {
        return TimingStats::empty();
    }

    let m = mean(samples);
    let s = std_dev(samples, m);

    // Sort for percentile calculations
    let mut sorted: Vec<f64> = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let p50 = percentile(&sorted, 0.50);
    let p90 = percentile(&sorted, 0.90);

    TimingStats {
        mean: m,
        std: s,
        p50,
        p90,
    }
}

/// Calculate the mean of a slice of values.
pub fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

/// Calculate the population standard deviation of a slice of values.
pub fn std_dev(values: &[f64], mean: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64;
    variance.sqrt()
}

/// Calculate a percentile value from sorted samples using linear interpolation.
///
/// # Arguments
/// * `sorted_samples` - Samples sorted in ascending order
/// * `percentile` - Percentile to calculate (0.0 to 1.0)
pub fn percentile(sorted_samples: &[f64], p: f64) -> f64 {
    if sorted_samples.is_empty() {
        return 0.0;
    }
    if sorted_samples.len() == 1 {
        return sorted_samples[0];
    }

    let p = p.clamp(0.0, 1.0);
    let n = sorted_samples.len();

    // Use linear interpolation between closest ranks
    let rank = p * (n - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    let frac = rank - lower as f64;

    if lower == upper {
        sorted_samples[lower]
    } else {
        sorted_samples[lower] * (1.0 - frac) + sorted_samples[upper] * frac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mean_basic() {
        let values = [100.0, 200.0, 300.0, 400.0, 500.0];
        assert_eq!(mean(&values), 300.0);
    }

    #[test]
    fn test_mean_empty() {
        let values: [f64; 0] = [];
        assert_eq!(mean(&values), 0.0);
    }

    #[test]
    fn test_std_dev_basic() {
        let values = [100.0, 200.0, 300.0, 400.0, 500.0];
        let m = mean(&values);
        let s = std_dev(&values, m);
        // Population std dev of [100, 200, 300, 400, 500] = sqrt(20000) ≈ 141.42
        assert!((s - 141.42).abs() < 0.1);
    }

    #[test]
    fn test_std_dev_empty() {
        let values: [f64; 0] = [];
        assert_eq!(std_dev(&values, 0.0), 0.0);
    }

    #[test]
    fn test_percentile_median() {
        let sorted = [100.0, 200.0, 300.0, 400.0, 500.0];
        assert_eq!(percentile(&sorted, 0.5), 300.0);
    }

    #[test]
    fn test_percentile_p90() {
        let sorted = [100.0, 200.0, 300.0, 400.0, 500.0];
        // p90 with 5 elements: rank = 0.9 * 4 = 3.6
        // interpolate between index 3 (400) and 4 (500)
        // 400 * 0.4 + 500 * 0.6 = 160 + 300 = 460
        assert_eq!(percentile(&sorted, 0.9), 460.0);
    }

    #[test]
    fn test_percentile_single() {
        let sorted = [42.0];
        assert_eq!(percentile(&sorted, 0.5), 42.0);
        assert_eq!(percentile(&sorted, 0.9), 42.0);
    }

    #[test]
    fn test_percentile_empty() {
        let sorted: [f64; 0] = [];
        assert_eq!(percentile(&sorted, 0.5), 0.0);
    }

    #[test]
    fn test_calculate_stats_basic() {
        let samples = [100.0, 200.0, 300.0, 400.0, 500.0];
        let stats = calculate_stats(&samples);

        assert_eq!(stats.mean, 300.0);
        assert!((stats.std - 141.42).abs() < 0.1);
        assert_eq!(stats.p50, 300.0);
        assert_eq!(stats.p90, 460.0);
    }

    #[test]
    fn test_calculate_stats_empty() {
        let samples: [f64; 0] = [];
        let stats = calculate_stats(&samples);

        assert_eq!(stats.mean, 0.0);
        assert_eq!(stats.std, 0.0);
        assert_eq!(stats.p50, 0.0);
        assert_eq!(stats.p90, 0.0);
    }
}
