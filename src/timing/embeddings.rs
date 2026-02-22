//! NTE (Neural Timing Embeddings) feature extraction.
//!
//! Transforms raw timing samples into 64-dimensional embedding vectors
//! for similarity matching and pattern recognition.

use super::stats::{mean, percentile, std_dev};

/// Extracted features from timing samples.
#[derive(Debug, Clone)]
pub struct FeatureVector {
    // Statistical features (indices 0-9)
    pub mean: f64,
    pub std: f64,
    pub min: f64,
    pub max: f64,
    pub p10: f64,
    pub p25: f64,
    pub p50: f64,
    pub p75: f64,
    pub p90: f64,
    pub iqr: f64,

    // Sequential features (indices 10-19) - normalized inter-sample deltas
    deltas: [f64; 10],

    // Histogram features (indices 20-29) - normalized bin counts
    histogram: [f64; 10],

    // Higher moments (indices 30-32)
    pub skewness: f64,
    pub kurtosis: f64,
    pub cv: f64, // coefficient of variation
}

impl FeatureVector {
    /// Convert to 64-dimensional L2-normalized embedding.
    ///
    /// The embedding uses block-wise normalization to preserve relative
    /// differences within feature groups while ensuring overall unit length.
    pub fn to_embedding(&self) -> Vec<f64> {
        let mut vec = Vec::with_capacity(64);

        // 0-9: Statistical features (log-scaled and block-normalized)
        // Log scaling converts multiplicative timing differences to additive ones.
        // Block normalization preserves magnitude relationships.
        let mut stats_block = [
            safe_log(self.mean),
            safe_log(self.std),
            safe_log(self.min),
            safe_log(self.max),
            safe_log(self.p10),
            safe_log(self.p25),
            safe_log(self.p50),
            safe_log(self.p75),
            safe_log(self.p90),
            safe_log(self.iqr),
        ];
        normalize_block(&mut stats_block);
        vec.extend_from_slice(&stats_block);

        // 10-19: Deltas (already normalized per-sample)
        vec.extend_from_slice(&self.deltas);

        // 20-29: Histogram (already normalized to sum=1)
        vec.extend_from_slice(&self.histogram);

        // 30-39: Higher moments + 7 reserved zeros
        // Include CV prominently as it's a key pattern discriminator
        vec.extend_from_slice(&[self.skewness, self.kurtosis, self.cv]);
        vec.extend(std::iter::repeat_n(0.0, 7));

        // 40-63: Reserved for future expansion
        vec.extend(std::iter::repeat_n(0.0, 24));

        // Final L2 normalization for cosine similarity
        l2_normalize(&mut vec);

        vec
    }
}

/// Safe log transform for embedding features.
/// Uses log1p(x) = ln(1+x) to handle zero and small values gracefully.
fn safe_log(x: f64) -> f64 {
    if x <= 0.0 {
        0.0
    } else {
        (1.0 + x).ln()
    }
}

/// Normalize a feature block by subtracting mean and dividing by std.
/// This makes each block's contribution to cosine similarity based on
/// pattern shape rather than absolute values.
fn normalize_block(block: &mut [f64]) {
    if block.is_empty() {
        return;
    }

    let n = block.len() as f64;
    let mean: f64 = block.iter().sum::<f64>() / n;
    let variance: f64 = block.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    let std = variance.sqrt();

    if std > 0.0 {
        for x in block.iter_mut() {
            *x = (*x - mean) / std;
        }
    } else {
        // All values identical, set to zero
        for x in block.iter_mut() {
            *x = 0.0;
        }
    }
}

/// Extract features from timing samples.
///
/// # Arguments
/// * `samples` - Slice of timing samples in microseconds
///
/// # Returns
/// A FeatureVector containing extracted features, or an error if samples is empty.
pub fn extract_features(samples: &[f64]) -> Result<FeatureVector, String> {
    if samples.is_empty() {
        return Err("No samples provided".to_string());
    }

    // Sort samples for percentile calculations
    let mut sorted: Vec<f64> = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    // Statistical features
    let m = mean(samples);
    let s = std_dev(samples, m);
    let min_val = sorted.first().copied().unwrap_or(0.0);
    let max_val = sorted.last().copied().unwrap_or(0.0);
    let p10 = percentile(&sorted, 0.10);
    let p25 = percentile(&sorted, 0.25);
    let p50 = percentile(&sorted, 0.50);
    let p75 = percentile(&sorted, 0.75);
    let p90 = percentile(&sorted, 0.90);
    let iqr = p75 - p25;

    // Sequential features: inter-sample deltas (normalized)
    let deltas = compute_normalized_deltas(samples);

    // Histogram features: 10 normalized bins
    let histogram = compute_histogram(samples, min_val, max_val);

    // Higher moments
    let (skewness, kurtosis) = compute_moments(samples, m, s);
    let cv = if m > 0.0 { s / m } else { 0.0 };

    Ok(FeatureVector {
        mean: m,
        std: s,
        min: min_val,
        max: max_val,
        p10,
        p25,
        p50,
        p75,
        p90,
        iqr,
        deltas,
        histogram,
        skewness,
        kurtosis,
        cv,
    })
}

/// Compute cosine similarity between two embedding vectors.
///
/// Returns a value between -1 and 1, where 1 means identical direction.
pub fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }

    let dot_product: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let magnitude_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let magnitude_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();

    if magnitude_a == 0.0 || magnitude_b == 0.0 {
        return 0.0;
    }

    dot_product / (magnitude_a * magnitude_b)
}

/// L2-normalize a vector in place.
fn l2_normalize(vec: &mut [f64]) {
    let magnitude: f64 = vec.iter().map(|x| x * x).sum::<f64>().sqrt();

    if magnitude > 0.0 {
        for x in vec.iter_mut() {
            *x /= magnitude;
        }
    }
}

/// Compute normalized inter-sample deltas (first 10).
fn compute_normalized_deltas(samples: &[f64]) -> [f64; 10] {
    let mut deltas = [0.0; 10];

    if samples.len() < 2 {
        return deltas;
    }

    // Calculate raw deltas
    let mut raw_deltas: Vec<f64> = samples.windows(2).map(|w| w[1] - w[0]).take(10).collect();

    // Normalize deltas by max absolute value
    let max_abs = raw_deltas.iter().map(|d| d.abs()).fold(0.0, f64::max);

    if max_abs > 0.0 {
        for d in &mut raw_deltas {
            *d /= max_abs;
        }
    }

    // Copy to fixed array
    for (i, d) in raw_deltas.iter().enumerate() {
        deltas[i] = *d;
    }

    deltas
}

/// Compute histogram with 10 normalized bins.
fn compute_histogram(samples: &[f64], min_val: f64, max_val: f64) -> [f64; 10] {
    let mut histogram = [0.0; 10];

    if samples.is_empty() {
        return histogram;
    }

    let range = max_val - min_val;

    if range == 0.0 {
        // All samples are the same value, put all in first bin
        histogram[0] = 1.0;
        return histogram;
    }

    let bin_width = range / 10.0;

    for sample in samples {
        let bin = ((*sample - min_val) / bin_width).floor() as usize;
        let bin = bin.min(9); // Clamp to last bin
        histogram[bin] += 1.0;
    }

    // Normalize by sample count
    let n = samples.len() as f64;
    for h in &mut histogram {
        *h /= n;
    }

    histogram
}

/// Compute skewness and kurtosis (excess kurtosis, normal = 0).
fn compute_moments(samples: &[f64], mean_val: f64, std_val: f64) -> (f64, f64) {
    if samples.len() < 3 || std_val == 0.0 {
        return (0.0, 0.0);
    }

    let n = samples.len() as f64;

    // Standardized moments
    let m3: f64 = samples
        .iter()
        .map(|x| ((x - mean_val) / std_val).powi(3))
        .sum::<f64>()
        / n;
    let m4: f64 = samples
        .iter()
        .map(|x| ((x - mean_val) / std_val).powi(4))
        .sum::<f64>()
        / n;

    let skewness = m3;
    let kurtosis = m4 - 3.0; // Excess kurtosis (normal distribution = 0)

    (skewness, kurtosis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l2_normalize() {
        let mut vec = vec![3.0, 4.0];
        l2_normalize(&mut vec);

        let magnitude: f64 = vec.iter().map(|x| x * x).sum::<f64>().sqrt();
        assert!((magnitude - 1.0).abs() < 0.0001);
    }

    #[test]
    fn test_l2_normalize_zero_vector() {
        let mut vec = vec![0.0, 0.0, 0.0];
        l2_normalize(&mut vec);

        // Should remain zero vector
        assert!(vec.iter().all(|x| *x == 0.0));
    }

    #[test]
    fn test_compute_deltas_basic() {
        let samples = vec![100.0, 200.0, 150.0, 250.0];
        let deltas = compute_normalized_deltas(&samples);

        // Raw deltas: 100, -50, 100
        // Max abs = 100
        // Normalized: 1.0, -0.5, 1.0
        assert!((deltas[0] - 1.0).abs() < 0.001);
        assert!((deltas[1] - (-0.5)).abs() < 0.001);
        assert!((deltas[2] - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_compute_deltas_single_sample() {
        let samples = vec![100.0];
        let deltas = compute_normalized_deltas(&samples);

        // No deltas possible
        assert!(deltas.iter().all(|d| *d == 0.0));
    }

    #[test]
    fn test_histogram_uniform() {
        // 10 samples evenly distributed
        let samples: Vec<f64> = (0..10).map(|i| i as f64 * 10.0).collect();
        let histogram = compute_histogram(&samples, 0.0, 90.0);

        // Each bin should have 0.1 (1 sample / 10 samples)
        for h in &histogram {
            assert!(*h >= 0.0 && *h <= 0.2);
        }
    }

    #[test]
    fn test_histogram_single_value() {
        let samples = vec![100.0; 5];
        let histogram = compute_histogram(&samples, 100.0, 100.0);

        // All in first bin
        assert_eq!(histogram[0], 1.0);
        assert!(histogram[1..].iter().all(|h| *h == 0.0));
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![0.0, 1.0, 0.0];

        let sim = cosine_similarity(&a, &b);
        assert!(
            sim.abs() < 0.001,
            "Orthogonal vectors should have ~0 similarity"
        );
    }

    #[test]
    fn test_cosine_similarity_parallel() {
        let a = vec![1.0, 2.0, 3.0];
        let b = vec![2.0, 4.0, 6.0];

        let sim = cosine_similarity(&a, &b);
        assert!(
            (sim - 1.0).abs() < 0.001,
            "Parallel vectors should have ~1 similarity"
        );
    }
}
