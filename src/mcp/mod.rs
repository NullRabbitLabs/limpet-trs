//! MCP (Model Context Protocol) server for limpet.
//!
//! Exposes three tools over stdio transport:
//! - `scan_ports` — discover open ports on a host
//! - `time_port` — measure TCP RTT with nanosecond precision
//! - `get_timing_features` — extract ML feature vector from timing samples
//!
//! Start with: `limpet --mcp`
//! Compatible with Claude Desktop and any MCP client.

use rmcp::model::{Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo};
use rmcp::tool;
use rmcp::{Error as McpError, ServerHandler};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::timing::{collect_timing_samples, extract_features};
use crate::{PortSpec, TimingRequest};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Input schemas
// ─────────────────────────────────────────────────────────────────────────────

/// Input schema for `scan_ports`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScanPortsInput {
    /// Target IP address or hostname
    pub target: String,
    /// Port specification: "1-1024", "80,443", "1-65535" (default: "1-1024")
    #[serde(default = "default_ports")]
    pub ports: String,
    /// Pacing profile: aggressive | normal | stealthy | paranoid (default: normal)
    #[serde(default = "default_stealth")]
    pub stealth: String,
    /// Per-port timeout in milliseconds (default: 2000)
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u32,
}

fn default_ports() -> String {
    "1-1024".to_string()
}
fn default_stealth() -> String {
    "normal".to_string()
}
fn default_timeout_ms() -> u32 {
    2000
}

/// Input schema for `time_port`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TimePortInput {
    /// Target IP address or hostname
    pub target: String,
    /// Port to time
    pub port: u16,
    /// Number of RTT samples (default: 10)
    #[serde(default = "default_samples")]
    pub samples: u32,
    /// Timeout per sample in milliseconds (default: 2000)
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u32,
}

fn default_samples() -> u32 {
    10
}

/// Input schema for `get_timing_features`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetTimingFeaturesInput {
    /// Target IP address or hostname
    pub target: String,
    /// Port to analyse
    pub port: u16,
    /// Number of RTT samples for feature extraction (default: 20)
    #[serde(default = "default_feature_samples")]
    pub samples: u32,
}

fn default_feature_samples() -> u32 {
    20
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP handler
// ─────────────────────────────────────────────────────────────────────────────

/// The MCP server handler struct.
#[derive(Debug, Clone)]
pub struct LimpetMcpServer;

/// Implements the tool methods and creates the static toolbox.
#[tool(tool_box)]
impl LimpetMcpServer {
    /// Discover open ports on a target host using XDP kernel-bypass SYN scanning.
    #[tool(
        description = "Discover open ports on a target host using XDP kernel-bypass SYN scanning with nanosecond RTT precision. Returns port states (open/closed/filtered/firewalled) with timing data."
    )]
    async fn scan_ports(
        &self,
        #[tool(aggr)] input: ScanPortsInput,
    ) -> Result<rmcp::model::CallToolResult, McpError> {
        let port_spec =
            PortSpec::parse(&input.ports).map_err(|e| McpError::invalid_params(e, None))?;

        let pacing = parse_pacing(&input.stealth).map_err(|e| McpError::invalid_params(e, None))?;

        let result = crate::cli::run_scan(&input.target, port_spec, pacing, input.timeout_ms, None)
            .await
            .map_err(|e| McpError::internal_error(e, None))?;

        let json = crate::cli::format_json(&result);
        Ok(rmcp::model::CallToolResult::success(vec![Content::text(
            json,
        )]))
    }

    /// Measure TCP RTT to a specific port with nanosecond precision via eBPF timestamps.
    #[tool(
        description = "Measure TCP RTT to a specific port with nanosecond precision via eBPF kernel timestamps. Returns timing statistics and raw samples."
    )]
    async fn time_port(
        &self,
        #[tool(aggr)] input: TimePortInput,
    ) -> Result<rmcp::model::CallToolResult, McpError> {
        let request = TimingRequest {
            request_id: Uuid::new_v4(),
            scan_id: None,
            target_host: input.target.clone(),
            target_port: input.port,
            sample_count: input.samples,
            timeout_ms: input.timeout_ms,
            banner_timeout_ms: None,
        };

        let result = collect_timing_samples(&request, None).await;
        let json = serde_json::to_string_pretty(&result)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(rmcp::model::CallToolResult::success(vec![Content::text(
            json,
        )]))
    }

    /// Extract ML feature vector from timing samples for service fingerprinting.
    #[tool(
        description = "Extract a 64-dimensional ML feature vector from TCP RTT timing samples for service fingerprinting and similarity search via eBPF timestamps."
    )]
    async fn get_timing_features(
        &self,
        #[tool(aggr)] input: GetTimingFeaturesInput,
    ) -> Result<rmcp::model::CallToolResult, McpError> {
        let request = TimingRequest {
            request_id: Uuid::new_v4(),
            scan_id: None,
            target_host: input.target.clone(),
            target_port: input.port,
            sample_count: input.samples,
            timeout_ms: 2000,
            banner_timeout_ms: None,
        };

        let mut result = collect_timing_samples(&request, None).await;

        if result.error.is_none() && !result.samples.is_empty() {
            if let Ok(features) = extract_features(&result.samples) {
                result.embedding = Some(features.to_embedding());
            }
        }

        let json = serde_json::to_string_pretty(&result)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(rmcp::model::CallToolResult::success(vec![Content::text(
            json,
        )]))
    }
}

/// Implements call_tool and list_tools by querying the static toolbox.
/// get_info provides server metadata.
#[tool(tool_box)]
impl ServerHandler for LimpetMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "limpet".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            instructions: Some(
                "Limpet is a high-precision network scanner with XDP kernel-bypass timing. \
                Use scan_ports to discover open ports, time_port to measure RTT, and \
                get_timing_features for ML-ready feature extraction."
                    .to_string(),
            ),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a pacing profile string into a PacingProfile.
fn parse_pacing(s: &str) -> Result<crate::scanner::stealth::PacingProfile, String> {
    use crate::scanner::stealth::PacingProfile;
    match s.to_lowercase().as_str() {
        "aggressive" => Ok(PacingProfile::Aggressive),
        "normal" => Ok(PacingProfile::Normal),
        "stealthy" => Ok(PacingProfile::Stealthy),
        "paranoid" => Ok(PacingProfile::Paranoid),
        other => Err(format!(
            "unknown pacing profile '{}'; use aggressive, normal, stealthy, or paranoid",
            other
        )),
    }
}

/// Start the MCP server on stdio.
pub async fn run_mcp_server() -> Result<(), Box<dyn std::error::Error>> {
    use rmcp::{transport::stdio, ServiceExt};

    let service = LimpetMcpServer;
    let server = service.serve(stdio()).await?;
    server.waiting().await?;
    Ok(())
}
