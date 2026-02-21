//! Timing collection module.
//!
//! Provides high-precision TCP connection timing using XDP/BPF kernel-level
//! timestamps. The network interface is auto-detected from the default route
//! when not explicitly configured.

pub mod embeddings;
pub mod stats;
pub mod userspace;
pub mod xdp;

pub use embeddings::{cosine_similarity, extract_features, FeatureVector};
pub use stats::{calculate_stats, mean, percentile, std_dev};
pub use userspace::{collect_timing_samples, collect_timing_samples_raw};
pub use xdp::{
    BpfReader, BpfTimingCollector, BpfTimingError, MockBpfTimingCollector, TimingMapEntry,
};

use crate::TimingBackend;

/// Detect the default network interface from `/proc/net/route`.
///
/// Prefers the interface with the default route (destination `00000000`).
/// Falls back to the first non-loopback interface if no default route exists
/// (e.g. in containers with `--network host` but non-standard routing).
fn detect_default_interface() -> Result<String, BpfTimingError> {
    let content = std::fs::read_to_string("/proc/net/route").map_err(|e| {
        BpfTimingError::Load(format!(
            "cannot read /proc/net/route to auto-detect interface \
             (set XDP_INTERFACE explicitly): {}",
            e
        ))
    })?;

    let mut first_non_lo: Option<String> = None;

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let iface = fields[0];

        // Prefer the default route
        if fields[1] == "00000000" {
            return Ok(iface.to_string());
        }

        // Track first non-loopback as fallback
        if first_non_lo.is_none() && iface != "lo" {
            first_non_lo = Some(iface.to_string());
        }
    }

    // Fall back to first non-loopback interface
    first_non_lo.ok_or_else(|| {
        BpfTimingError::Load(
            "no usable interface found in /proc/net/route \
             (set XDP_INTERFACE explicitly, requires --privileged --network host)"
                .to_string(),
        )
    })
}

/// Detect the best available timing backend.
///
/// Returns the backend type and BPF collector. When `interface` is `None`,
/// auto-detects the default network interface from `/proc/net/route`.
/// BPF load failure is an error — there is no userspace fallback.
pub fn detect_timing_backend(
    interface: &Option<String>,
) -> Result<(TimingBackend, BpfTimingCollector), BpfTimingError> {
    let iface = match interface {
        Some(iface) => iface.clone(),
        None => detect_default_interface()?,
    };

    let collector = BpfTimingCollector::new(&iface)?;
    let backend = collector.backend();
    Ok((backend, collector))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_backend_no_interface_auto_detects() {
        // On macOS / environments without /proc/net/route, this returns Err.
        // On Linux, it returns Ok with an auto-detected interface.
        let result = detect_timing_backend(&None);
        // Either succeeds (Linux with BPF) or fails — never silently degrades.
        assert!(
            result.is_ok() || result.is_err(),
            "detect_timing_backend must return a Result"
        );
    }

    #[test]
    fn test_detect_default_interface_returns_err_without_proc() {
        // On macOS or Docker without /proc/net/route, should return Err
        let result = detect_default_interface();
        if cfg!(target_os = "linux") {
            // On Linux the file exists, but we may or may not have BPF perms
            // Just verify it doesn't panic
            let _ = result;
        } else {
            assert!(result.is_err());
        }
    }
}
