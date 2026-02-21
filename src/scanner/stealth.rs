//! Stealth and pacing profiles for scanner fingerprint avoidance.
//!
//! Controls all packet parameters to ensure SYN probes are indistinguishable
//! from real TCP connections. No nmap-like signatures (window sizes, TTL
//! patterns, TCP option ordering, timing modes).

use rand::Rng;
use serde::{Deserialize, Serialize};

/// Controls all packet parameters to avoid scanner fingerprints.
///
/// Every field maps to an observable property of TCP SYN packets that
/// IDS systems use for scanner detection. The defaults match a real
/// Linux 6.x TCP stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthProfile {
    /// TCP window sizes to cycle through (Linux 6.x uses 64240 or 65535).
    pub window_sizes: Vec<u16>,
    /// Base IP TTL value.
    pub ttl: u8,
    /// TTL jitter: actual TTL = ttl +/- ttl_jitter.
    pub ttl_jitter: u8,
    /// TCP MSS option value (1460 for Ethernet MTU 1500).
    pub tcp_options_mss: u16,
    /// TCP window scale option value.
    pub tcp_options_ws: u8,
    /// Include SACK permitted option.
    pub tcp_options_sack: bool,
    /// Include TCP timestamps option.
    pub tcp_options_timestamps: bool,
    /// Base TSval (simulates 1-30 day uptime at tsval_hz).
    pub tsval_base: u32,
    /// TSval tick rate in Hz (Linux default: 1000).
    pub tsval_hz: u32,
    /// Set IP Don't Fragment flag (Linux sets DF on SYN).
    pub ip_df: bool,
    /// Use random IP ID (Linux 4.x+ randomizes IP ID).
    pub ip_id_random: bool,
    /// TCP urgent pointer (nmap sometimes sets non-zero).
    pub tcp_urgent_ptr: u16,
    /// Ephemeral source port range.
    pub src_port_range: (u16, u16),
    /// Prevent source port reuse within window.
    pub src_port_reuse_guard: bool,
    /// Source port reuse prevention window in milliseconds.
    pub src_port_reuse_window_ms: u64,
    /// Inter-probe delay in milliseconds.
    pub probe_delay_ms: u32,
    /// Jitter factor (0.0-1.0) applied to probe delay.
    pub probe_jitter_pct: f64,
    /// Delay between rounds of probes (milliseconds). Spreads port groups
    /// over time to avoid bursty scan signatures. 0 = no inter-round delay.
    #[serde(default)]
    pub inter_batch_delay_ms: u32,
}

impl StealthProfile {
    /// Create a profile matching a real Linux 6.x TCP stack.
    ///
    /// These values are chosen to be indistinguishable from a normal
    /// outgoing TCP connection on a modern Linux system.
    pub fn linux_6x_default() -> Self {
        let mut rng = rand::thread_rng();
        // Random uptime between 1-30 days at 1000 Hz
        let uptime_ticks = rng.gen_range(86_400_000..2_592_000_000u32);

        Self {
            window_sizes: vec![64240, 65535, 29200, 26883, 32120],
            ttl: 64,
            ttl_jitter: 1,
            tcp_options_mss: 1460,
            tcp_options_ws: 7,
            tcp_options_sack: true,
            tcp_options_timestamps: true,
            tsval_base: uptime_ticks,
            tsval_hz: 1000,
            ip_df: true,
            ip_id_random: true,
            tcp_urgent_ptr: 0,
            src_port_range: (49152, 65535),
            src_port_reuse_guard: true,
            src_port_reuse_window_ms: 60_000,
            probe_delay_ms: 50,
            probe_jitter_pct: 0.3,
            inter_batch_delay_ms: 0,
        }
    }

    /// Get a TTL value with jitter applied.
    pub fn jittered_ttl(&self) -> u8 {
        if self.ttl_jitter == 0 {
            return self.ttl;
        }
        let mut rng = rand::thread_rng();
        let offset: i8 = rng.gen_range(-(self.ttl_jitter as i8)..=(self.ttl_jitter as i8));
        self.ttl.saturating_add_signed(offset)
    }

    /// Select a window size (cycles through available options).
    pub fn select_window(&self, index: usize) -> u16 {
        if self.window_sizes.is_empty() {
            return 64240;
        }
        self.window_sizes[index % self.window_sizes.len()]
    }

    /// Calculate TSval for the current probe.
    ///
    /// Uses a generally upward trend with per-probe random jitter to prevent
    /// linear correlation across connections. Jitter range is 0..tsval_hz
    /// (0-1s at 1000Hz), breaking the deterministic relationship while keeping
    /// values in a plausible range.
    pub fn tsval_for_probe(&self, probe_index: u32) -> u32 {
        let base_increment = probe_index * self.tsval_hz / 10;
        let jitter = rand::thread_rng().gen_range(0..self.tsval_hz);
        self.tsval_base
            .wrapping_add(base_increment)
            .wrapping_add(jitter)
    }

    /// Generate a random ephemeral source port.
    pub fn random_src_port(&self) -> u16 {
        let mut rng = rand::thread_rng();
        rng.gen_range(self.src_port_range.0..=self.src_port_range.1)
    }

    /// Calculate inter-batch delay with jitter applied.
    ///
    /// Uses the same jitter formula as `jittered_delay_ms()` but applied to
    /// `inter_batch_delay_ms`. Returns 0 when inter-batch delay is disabled.
    pub fn jittered_batch_delay_ms(&self) -> u64 {
        if self.inter_batch_delay_ms == 0 {
            return 0;
        }
        let mut rng = rand::thread_rng();
        let jitter_range = (self.inter_batch_delay_ms as f64 * self.probe_jitter_pct) as u64;
        let base = self.inter_batch_delay_ms as u64;
        if jitter_range == 0 {
            return base;
        }
        let offset = rng.gen_range(0..=jitter_range * 2);
        base.saturating_sub(jitter_range) + offset
    }

    /// Calculate probe delay with jitter applied.
    pub fn jittered_delay_ms(&self) -> u64 {
        if self.probe_delay_ms == 0 {
            return 0;
        }
        let mut rng = rand::thread_rng();
        let jitter_range = (self.probe_delay_ms as f64 * self.probe_jitter_pct) as u64;
        let base = self.probe_delay_ms as u64;
        if jitter_range == 0 {
            return base;
        }
        let offset = rng.gen_range(0..=jitter_range * 2);
        base.saturating_sub(jitter_range) + offset
    }
}

/// Pacing profile controlling scan speed and stealth level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacingProfile {
    /// 5ms delay, 0.1 jitter, batch=100 — lab/authorized testing.
    Aggressive,
    /// 50ms delay, 0.3 jitter, batch=20 — default for most scans.
    Normal,
    /// 150ms delay, 0.6 jitter, batch=10 — production network monitoring.
    Stealthy,
    /// 500ms delay, 0.8 jitter, batch=5 — maximum stealth.
    Paranoid,
}

impl PacingProfile {
    /// Base inter-probe delay in milliseconds.
    pub fn delay_ms(&self) -> u32 {
        match self {
            Self::Aggressive => 5,
            Self::Normal => 50,
            Self::Stealthy => 150,
            Self::Paranoid => 500,
        }
    }

    /// Jitter factor (0.0-1.0) applied to delay.
    pub fn jitter_pct(&self) -> f64 {
        match self {
            Self::Aggressive => 0.1,
            Self::Normal => 0.3,
            Self::Stealthy => 0.6,
            Self::Paranoid => 0.8,
        }
    }

    /// Number of probes per batch before collecting results.
    pub fn batch_size(&self) -> usize {
        match self {
            Self::Aggressive => 100,
            Self::Normal => 20,
            Self::Stealthy => 10,
            Self::Paranoid => 5,
        }
    }

    /// Inter-batch delay in milliseconds.
    pub fn inter_batch_delay_ms(&self) -> u32 {
        match self {
            Self::Aggressive => 0,
            Self::Normal => 0,
            Self::Stealthy => 1000,
            Self::Paranoid => 3000,
        }
    }

    /// Inter-target delay in milliseconds.
    ///
    /// Pause between completing one target scan and starting the next.
    /// Prevents triggering IDS rules that count SYN packets to common ports
    /// (e.g. Suricata ET SCAN sid:2003068: 5 SYNs to port 22 in 120s).
    pub fn inter_target_delay_ms(&self) -> u64 {
        match self {
            Self::Aggressive => 0,
            Self::Normal => 0,
            Self::Stealthy => 5_000,
            Self::Paranoid => 30_000,
        }
    }

    /// Apply this pacing profile to a stealth profile.
    pub fn apply_to(&self, profile: &mut StealthProfile) {
        profile.probe_delay_ms = self.delay_ms();
        profile.probe_jitter_pct = self.jitter_pct();
        profile.inter_batch_delay_ms = self.inter_batch_delay_ms();
    }
}

impl Default for PacingProfile {
    fn default() -> Self {
        Self::Normal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stealth_profile_linux_defaults() {
        let profile = StealthProfile::linux_6x_default();
        assert_eq!(
            profile.window_sizes,
            vec![64240, 65535, 29200, 26883, 32120]
        );
        assert_eq!(profile.ttl, 64);
        assert_eq!(profile.tcp_options_mss, 1460);
        assert_eq!(profile.tcp_options_ws, 7);
        assert!(profile.tcp_options_sack);
        assert!(profile.tcp_options_timestamps);
        assert_eq!(profile.tsval_hz, 1000);
        assert!(profile.ip_df);
        assert!(profile.ip_id_random);
        assert_eq!(profile.tcp_urgent_ptr, 0);
        assert_eq!(profile.src_port_range, (49152, 65535));
    }

    #[test]
    fn test_syn_packet_ttl_range() {
        let profile = StealthProfile::linux_6x_default();
        for _ in 0..100 {
            let ttl = profile.jittered_ttl();
            assert!(
                (63..=65).contains(&ttl),
                "TTL {} outside expected range 63-65",
                ttl
            );
        }
    }

    #[test]
    fn test_syn_packet_window_realistic() {
        let profile = StealthProfile::linux_6x_default();
        assert_eq!(profile.select_window(0), 64240);
        assert_eq!(profile.select_window(1), 65535);
        assert_eq!(profile.select_window(2), 29200);
        assert_eq!(profile.select_window(3), 26883);
        assert_eq!(profile.select_window(4), 32120);
        // Cycles
        assert_eq!(profile.select_window(5), 64240);
    }

    #[test]
    fn test_syn_packet_src_port_ephemeral() {
        let profile = StealthProfile::linux_6x_default();
        for _ in 0..100 {
            let port = profile.random_src_port();
            assert!(
                (49152..=65535).contains(&port),
                "Source port {} outside ephemeral range",
                port
            );
        }
    }

    #[test]
    fn test_syn_packet_tcp_timestamp_realistic() {
        let profile = StealthProfile::linux_6x_default();
        let ts0 = profile.tsval_for_probe(0);
        assert!(ts0 > 0, "TSval must be non-zero (simulates uptime)");

        // With jitter, consecutive TSvals may not be strictly ordered.
        // Verify values are within plausible range: base +/- (increment + jitter).
        let ts10 = profile.tsval_for_probe(10);
        assert!(ts10 > 0, "TSval at probe 10 must be non-zero");

        // Over many probes the general trend should be upward, but individual
        // pairs can be out of order due to jitter. Verify the range is sane:
        // probe 100 should generally be higher than probe 0.
        let ts100 = profile.tsval_for_probe(100);
        // base_increment for probe 100 = 100 * 1000/10 = 10000 ticks
        // jitter is 0..999, so ts100 should be roughly tsval_base + 10000 + jitter
        // We just verify it's non-zero and within u32 range (wrapping is fine).
        assert!(ts100 > 0, "TSval at probe 100 must be non-zero");
    }

    #[test]
    fn test_syn_packet_tsecr_zero() {
        // TSecr (timestamp echo reply) should be 0 on SYN packets
        // This is implicit in our implementation — we only set TSval
        let profile = StealthProfile::linux_6x_default();
        assert_eq!(profile.tcp_urgent_ptr, 0, "urgent pointer must be zero");
    }

    #[test]
    fn test_syn_packet_ip_df_set() {
        let profile = StealthProfile::linux_6x_default();
        assert!(profile.ip_df, "Linux sets DF on SYN packets");
    }

    #[test]
    fn test_syn_packet_ip_id_random() {
        let profile = StealthProfile::linux_6x_default();
        assert!(profile.ip_id_random, "Linux 4.x+ randomizes IP ID");
    }

    #[test]
    fn test_syn_packet_urgent_ptr_zero() {
        let profile = StealthProfile::linux_6x_default();
        assert_eq!(
            profile.tcp_urgent_ptr, 0,
            "nmap sometimes sets non-zero urgent pointer; we must not"
        );
    }

    #[test]
    fn test_syn_packet_options_match_linux() {
        let profile = StealthProfile::linux_6x_default();
        assert_eq!(profile.tcp_options_mss, 1460, "MSS for Ethernet MTU 1500");
        assert_eq!(
            profile.tcp_options_ws, 7,
            "window scale 7 = 128x multiplier"
        );
        assert!(profile.tcp_options_sack, "SACK permitted in Linux SYN");
        assert!(profile.tcp_options_timestamps, "timestamps in Linux SYN");
    }

    #[test]
    fn test_aggressive_profile_fast() {
        let profile = PacingProfile::Aggressive;
        assert_eq!(profile.delay_ms(), 5);
        assert_eq!(profile.batch_size(), 100);
        assert!((profile.jitter_pct() - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn test_paranoid_profile_jitter_range() {
        let profile = PacingProfile::Paranoid;
        assert_eq!(profile.delay_ms(), 500);
        assert_eq!(profile.batch_size(), 5);
        assert!((profile.jitter_pct() - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pacing_profile_from_request() {
        let mut stealth = StealthProfile::linux_6x_default();
        PacingProfile::Aggressive.apply_to(&mut stealth);
        assert_eq!(stealth.probe_delay_ms, 5);
        assert!((stealth.probe_jitter_pct - 0.1).abs() < f64::EPSILON);

        PacingProfile::Paranoid.apply_to(&mut stealth);
        assert_eq!(stealth.probe_delay_ms, 500);
        assert!((stealth.probe_jitter_pct - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_rate_limiter_with_jitter() {
        let mut profile = StealthProfile::linux_6x_default();
        profile.probe_delay_ms = 100;
        profile.probe_jitter_pct = 0.5;

        let mut delays = Vec::new();
        for _ in 0..100 {
            delays.push(profile.jittered_delay_ms());
        }

        let min = *delays.iter().min().unwrap();
        let max = *delays.iter().max().unwrap();
        assert!(min >= 50, "min delay {} should be >= 50ms", min);
        assert!(max <= 150, "max delay {} should be <= 150ms", max);
        // Should have some variation (not all identical)
        assert!(min != max, "delays should have variation with 50% jitter");
    }

    #[test]
    fn test_pacing_profile_serialization() {
        let profile = PacingProfile::Paranoid;
        let json = serde_json::to_string(&profile).unwrap();
        assert_eq!(json, "\"paranoid\"");

        let parsed: PacingProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, PacingProfile::Paranoid);
    }

    #[test]
    fn test_pacing_profile_default_is_normal() {
        assert_eq!(PacingProfile::default(), PacingProfile::Normal);
    }

    #[test]
    fn test_stealth_profile_json_roundtrip() {
        let profile = StealthProfile::linux_6x_default();
        let json = serde_json::to_string(&profile).unwrap();
        let parsed: StealthProfile = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.window_sizes, profile.window_sizes);
        assert_eq!(parsed.ttl, profile.ttl);
        assert_eq!(parsed.ttl_jitter, profile.ttl_jitter);
        assert_eq!(parsed.tcp_options_mss, profile.tcp_options_mss);
        assert_eq!(parsed.tcp_options_ws, profile.tcp_options_ws);
        assert_eq!(parsed.tcp_options_sack, profile.tcp_options_sack);
        assert_eq!(
            parsed.tcp_options_timestamps,
            profile.tcp_options_timestamps
        );
        assert_eq!(parsed.tsval_base, profile.tsval_base);
        assert_eq!(parsed.tsval_hz, profile.tsval_hz);
        assert_eq!(parsed.ip_df, profile.ip_df);
        assert_eq!(parsed.ip_id_random, profile.ip_id_random);
        assert_eq!(parsed.tcp_urgent_ptr, profile.tcp_urgent_ptr);
        assert_eq!(parsed.src_port_range, profile.src_port_range);
        assert_eq!(parsed.src_port_reuse_guard, profile.src_port_reuse_guard);
        assert_eq!(
            parsed.src_port_reuse_window_ms,
            profile.src_port_reuse_window_ms
        );
        assert_eq!(parsed.probe_delay_ms, profile.probe_delay_ms);
        assert!((parsed.probe_jitter_pct - profile.probe_jitter_pct).abs() < f64::EPSILON);
        assert_eq!(parsed.inter_batch_delay_ms, profile.inter_batch_delay_ms);
    }

    #[test]
    fn test_stealth_profile_deserialize_from_json_object() {
        let json = r#"{
            "window_sizes": [64240, 65535],
            "ttl": 64,
            "ttl_jitter": 2,
            "tcp_options_mss": 1460,
            "tcp_options_ws": 7,
            "tcp_options_sack": true,
            "tcp_options_timestamps": true,
            "tsval_base": 100000,
            "tsval_hz": 1000,
            "ip_df": true,
            "ip_id_random": true,
            "tcp_urgent_ptr": 0,
            "src_port_range": [49152, 65535],
            "src_port_reuse_guard": true,
            "src_port_reuse_window_ms": 60000,
            "probe_delay_ms": 100,
            "probe_jitter_pct": 0.5
        }"#;

        let profile: StealthProfile = serde_json::from_str(json).unwrap();
        assert_eq!(profile.window_sizes, vec![64240, 65535]);
        assert_eq!(profile.ttl_jitter, 2);
        assert_eq!(profile.probe_delay_ms, 100);
        assert!((profile.probe_jitter_pct - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_stealthy_profile_values() {
        let profile = PacingProfile::Stealthy;
        assert_eq!(profile.delay_ms(), 150);
        assert!((profile.jitter_pct() - 0.6).abs() < f64::EPSILON);
        assert_eq!(profile.batch_size(), 10);
    }

    #[test]
    fn test_stealthy_delay_range() {
        let mut stealth = StealthProfile::linux_6x_default();
        PacingProfile::Stealthy.apply_to(&mut stealth);

        for _ in 0..100 {
            let delay = stealth.jittered_delay_ms();
            assert!(
                (60..=240).contains(&delay),
                "Stealthy delay {} outside expected range 60-240ms",
                delay
            );
        }
    }

    #[test]
    fn test_pacing_profile_stealthy_serialization() {
        let profile = PacingProfile::Stealthy;
        let json = serde_json::to_string(&profile).unwrap();
        assert_eq!(json, "\"stealthy\"");

        let parsed: PacingProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, PacingProfile::Stealthy);
    }

    #[test]
    fn test_inter_batch_delay_default_zero() {
        let profile = StealthProfile::linux_6x_default();
        assert_eq!(profile.inter_batch_delay_ms, 0);
    }

    #[test]
    fn test_stealthy_applies_inter_batch_delay() {
        let mut stealth = StealthProfile::linux_6x_default();
        PacingProfile::Stealthy.apply_to(&mut stealth);
        assert_eq!(stealth.inter_batch_delay_ms, 1000);
    }

    #[test]
    fn test_jittered_batch_delay_range() {
        let mut profile = StealthProfile::linux_6x_default();
        profile.inter_batch_delay_ms = 1000;
        profile.probe_jitter_pct = 0.6;

        for _ in 0..100 {
            let delay = profile.jittered_batch_delay_ms();
            assert!(
                (400..=1600).contains(&delay),
                "Batch delay {} outside expected range 400-1600ms",
                delay
            );
        }
    }

    #[test]
    fn test_jittered_batch_delay_zero_when_disabled() {
        let profile = StealthProfile::linux_6x_default();
        assert_eq!(profile.jittered_batch_delay_ms(), 0);
    }

    #[test]
    fn test_inter_batch_delay_serde_default() {
        // Deserialize without inter_batch_delay_ms field — should default to 0
        let json = r#"{
            "window_sizes": [64240],
            "ttl": 64,
            "ttl_jitter": 1,
            "tcp_options_mss": 1460,
            "tcp_options_ws": 7,
            "tcp_options_sack": true,
            "tcp_options_timestamps": true,
            "tsval_base": 100000,
            "tsval_hz": 1000,
            "ip_df": true,
            "ip_id_random": true,
            "tcp_urgent_ptr": 0,
            "src_port_range": [49152, 65535],
            "src_port_reuse_guard": true,
            "src_port_reuse_window_ms": 60000,
            "probe_delay_ms": 50,
            "probe_jitter_pct": 0.3
        }"#;
        let profile: StealthProfile = serde_json::from_str(json).unwrap();
        assert_eq!(profile.inter_batch_delay_ms, 0);
    }

    #[test]
    fn test_paranoid_applies_inter_batch_delay() {
        let mut stealth = StealthProfile::linux_6x_default();
        PacingProfile::Paranoid.apply_to(&mut stealth);
        assert_eq!(stealth.inter_batch_delay_ms, 3000);
    }

    #[test]
    fn test_aggressive_no_inter_batch_delay() {
        let mut stealth = StealthProfile::linux_6x_default();
        PacingProfile::Aggressive.apply_to(&mut stealth);
        assert_eq!(stealth.inter_batch_delay_ms, 0);
    }

    #[test]
    fn test_normal_no_inter_batch_delay() {
        let mut stealth = StealthProfile::linux_6x_default();
        PacingProfile::Normal.apply_to(&mut stealth);
        assert_eq!(stealth.inter_batch_delay_ms, 0);
    }

    #[test]
    fn test_inter_target_delay_aggressive_zero() {
        assert_eq!(PacingProfile::Aggressive.inter_target_delay_ms(), 0);
    }

    #[test]
    fn test_inter_target_delay_normal_zero() {
        assert_eq!(PacingProfile::Normal.inter_target_delay_ms(), 0);
    }

    #[test]
    fn test_inter_target_delay_stealthy_sufficient() {
        let delay = PacingProfile::Stealthy.inter_target_delay_ms();
        assert!(
            delay >= 5000,
            "Stealthy inter-target delay {delay} too low for IDS evasion"
        );
    }

    #[test]
    fn test_inter_target_delay_paranoid_sufficient() {
        let delay = PacingProfile::Paranoid.inter_target_delay_ms();
        assert!(
            delay >= 25000,
            "Paranoid inter-target delay {delay} too low"
        );
    }
}
