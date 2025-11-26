use anyhow::{Context, Result};
use log::{debug, info};
use std::path::Path;
use std::process::Command;

use crate::cmd_utils::execute_with_streaming_output;

const SNOS_REPO_URL: &str = "https://github.com/keep-starknet-strange/snos";
// branch: dynamic_charge_fee_fix
const SNOS_REPO_REV: &str = "0d8f2846c25e2ee8da981fee7fcf36012fe86549";

/// Generate PIE using snos generate-pie binary
///
/// # Arguments
/// * `block_range` - Block numbers in comma-separated format (e.g.,
///   "100,101,102")
/// * `output_path` - Path where the PIE file should be saved
/// * `rpc_url` - RPC endpoint URL
/// * `network` - Network name (sepolia, mainnet, paradex-testnet,
///   paradex-mainnet)
/// * `strk_fee_token` - STRK fee token address
/// * `eth_fee_token` - ETH fee token address
/// * `verbose` - Whether to stream command output to terminal
///
/// # Returns
/// Result indicating success or failure
pub async fn generate_pie(
    block_range: &str,
    output_path: &Path,
    rpc_url: &str,
    network: &str,
    strk_fee_token: &str,
    eth_fee_token: &str,
    verbose: bool,
) -> Result<()> {
    info!("Calling generate-pie binary...");

    // Check if generate-pie is available
    if !is_generate_pie_available().await {
        return Err(anyhow::anyhow!(
            "generate-pie binary not found. Please install it first:\n\
            cargo install --git {} --rev {} generate-pie",
            SNOS_REPO_URL,
            SNOS_REPO_REV
        ));
    }

    debug!("Blocks: {}", block_range);
    debug!("RPC URL: {}", rpc_url);
    debug!("Network: {}", network);
    debug!("Output: {}", output_path.display());

    // Build the command with environment variables
    // Following the pattern from the Makefile
    let mut cmd = Command::new("generate-pie");
    cmd.env("RUST_LOG", "info")
        .env("RUST_LOG_STYLE", "always") // Force colored logs from env_logger
        .env("SNOS_LAYOUT", "all_cairo")
        .env("SNOS_IS_L3", "false")
        .env("SNOS_RPC_URL", rpc_url)
        .env("SNOS_NETWORK", network)
        .env("SNOS_BLOCKS", block_range)
        .env("SNOS_STRK_FEE_TOKEN_ADDRESS", strk_fee_token)
        .env("SNOS_ETH_FEE_TOKEN_ADDRESS", eth_fee_token)
        .env("SNOS_OUTPUT", output_path.to_string_lossy().as_ref());

    debug!("Running command: {:?}", cmd);

    let (elapsed, stderr_output) =
        execute_with_streaming_output(&mut cmd, "generate-pie", verbose)?;

    info!("generate-pie completed in {:.2}s", elapsed.as_secs_f64());
    if !stderr_output.is_empty() {
        debug!("Stderr: {}", stderr_output);
    }

    // Print PIE file size
    if let Ok(metadata) = std::fs::metadata(output_path) {
        let size_mb = metadata.len() as f64 / (1024.0 * 1024.0);
        info!("PIE size: {:.2} MB", size_mb);
    }

    Ok(())
}

/// Check if generate-pie binary is available
async fn is_generate_pie_available() -> bool {
    // Check if generate-pie is installed and accessible
    match Command::new("generate-pie").arg("--help").output() {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// Format block numbers from input string
/// Supports formats: "123" (single block) or "100-110" (continuous range)
/// Returns comma-separated format expected by generate-pie
pub fn format_block_numbers(input: &str) -> Result<String> {
    let input = input.trim();

    if input.contains('-') {
        // Range format: "100-110" -> expand to comma-separated
        let parts: Vec<&str> = input.split('-').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!(
                "Invalid range format. Expected: start-end (e.g., \"100-110\")"
            ));
        }
        let start: u64 = parts[0]
            .trim()
            .parse()
            .context("Invalid start block number")?;
        let end: u64 = parts[1]
            .trim()
            .parse()
            .context("Invalid end block number")?;

        if start > end {
            return Err(anyhow::anyhow!(
                "Invalid range: start block ({}) must be less than or equal to end block ({})",
                start,
                end
            ));
        }

        let blocks: Vec<String> =
            (start..=end).map(|n| n.to_string()).collect();
        Ok(blocks.join(","))
    } else {
        // Single block number
        let block: u64 = input.parse()
            .context("Invalid block number. Expected a single number (e.g., \"123\") or a range (e.g., \"100-110\")")?;
        Ok(block.to_string())
    }
}
