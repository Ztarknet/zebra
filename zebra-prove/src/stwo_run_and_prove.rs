use anyhow::{Context, Result};
use log::{debug, info};
use serde_json;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cmd_utils::execute_with_streaming_output;
use crate::proof_utils::{load_proof_from_file, serialize_proof_to_file};

const BOOTLOADER_HINTS_REPO_URL: &str =
    "ssh://git@github.com/starkware-libs/bootloader-hints.git";
const BOOTLOADER_HINTS_BRANCH: &str = "main";

/// Create proof using stwo_run_and_prove from bootloader-hints
///
/// # Arguments
/// * `program_path` - Path to the Cairo program
/// * `pie_path` - Path to the PIE ZIP file
/// * `prover_params_path` - Path to the prover parameters JSON
/// * `output_dir` - Directory for output files
/// * `network` - Network name (e.g., "sepolia", "mainnet")
/// * `block_range` - Block range string (e.g., "100", "100-110")
/// * `verbose` - Whether to stream command output to terminal
///
/// # Returns
/// Path to the generated proof file
pub async fn stwo_run_and_prove(
    program_path: &Path,
    pie_path: &Path,
    prover_params_path: &Path,
    output_dir: &Path,
    network: &str,
    block_range: &str,
    verbose: bool,
) -> Result<PathBuf> {
    info!("Creating proof for PIE: {}", pie_path.display());

    // Create program input JSON in the format expected by stwo_run_and_prove
    let program_input = serde_json::json!({
        "single_page": true,
        "tasks": [{
            "type": "CairoPiePath",
            "path": pie_path.to_string_lossy(),
            "program_hash_function": "blake"
        }]
    });

    let program_input_path = output_dir.join("program_input.json");
    std::fs::write(
        &program_input_path,
        serde_json::to_string_pretty(&program_input)?,
    )
    .context("Failed to write program input JSON")?;

    debug!(
        "Program input JSON created: {}",
        program_input_path.display()
    );

    // Create proofs directory
    let proofs_dir = output_dir.join("proofs");
    std::fs::create_dir_all(&proofs_dir)
        .context("Failed to create proofs directory")?;

    // Check if stwo_run_and_prove is available
    if let Err(_) = Command::new("stwo_run_and_prove").arg("--help").output() {
        return Err(anyhow::anyhow!(
            "stwo_run_and_prove not found. Please install it first:\n\
            cargo +nightly-2025-07-14 install --git {} --branch {} stwo_run_and_prove",
            BOOTLOADER_HINTS_REPO_URL,
            BOOTLOADER_HINTS_BRANCH
        ));
    }

    info!("Calling stwo_run_and_prove...");

    // Run stwo_run_and_prove via time to capture memory usage
    let mut cmd = Command::new("/usr/bin/time");
    cmd.arg("-v")
        .arg("stwo_run_and_prove")
        .arg("--program")
        .arg(program_path)
        .arg("--program_input")
        .arg(&program_input_path)
        .arg("--prover_params_json")
        .arg(prover_params_path)
        .arg("--proofs_dir")
        .arg(&proofs_dir)
        .arg("--proof-format")
        .arg("json")
        .arg("--verify");

    debug!("Program path: {:?}", program_path);
    debug!("Running command: {:?}", cmd);

    let (elapsed, stderr_output) =
        execute_with_streaming_output(&mut cmd, "stwo_run_and_prove", verbose)?;

    info!("Elapsed time: {:.2}s", elapsed.as_secs_f64());

    // Parse time command output and stwo_run_and_prove output
    parse_time_output(&stderr_output);

    // Find the generated proof file
    let proof_file = find_proof_file(&proofs_dir)?;

    // Load proof from file
    let proof = load_proof_from_file(&proof_file)?;

    // Serialize proof to file with network and block range in filename
    let compressed_proof_filename =
        format!("proof_{}_{}.bz", network, block_range);
    let compressed_proof_file = proofs_dir.join(compressed_proof_filename);
    serialize_proof_to_file(&proof, &compressed_proof_file)?;

    // Get file size for reporting
    if let Ok(metadata) = std::fs::metadata(&compressed_proof_file) {
        let size_mb = metadata.len() as f64 / (1024.0 * 1024.0);
        info!("Proof size: {:.2} MB", size_mb);
    }

    Ok(compressed_proof_file)
}

/// Parse output from the time command and stwo_run_and_prove
///
/// # Arguments
/// * `stderr` - stderr output containing time command statistics
fn parse_time_output(stderr: &str) {
    // Parse time command output from stderr for memory usage
    for line in stderr.lines() {
        if line.contains("Maximum resident set size") {
            // Extract memory in KB and convert to MB/GB
            if let Some(value) = line.split(':').nth(1) {
                if let Ok(kb) = value.trim().parse::<f64>() {
                    let mb = kb / 1024.0;
                    let gb = mb / 1024.0;
                    info!("Maximum memory usage: {:.2} MB ({:.2} GB)", mb, gb);
                }
            }
        } else if line.contains("Elapsed (wall clock) time") {
            info!("Time command: {}", line.trim());
        } else if line.contains("Percent of CPU") {
            info!("{}", line.trim());
        }
    }
}

/// Find the most recently created proof file in the proofs directory
///
/// # Arguments
/// * `proofs_dir` - Path to the directory containing proof files
///
/// # Returns
/// Path to the most recently created proof file
fn find_proof_file(proofs_dir: &Path) -> Result<PathBuf> {
    let mut proof_files: Vec<PathBuf> = std::fs::read_dir(proofs_dir)
        .context("Failed to read proofs directory")?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();

    if proof_files.is_empty() {
        return Err(anyhow::anyhow!(
            "No proof files found in {}",
            proofs_dir.display()
        ));
    }

    // Sort by modification time (newest first)
    proof_files.sort_by(|a, b| {
        let a_time = a
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .unwrap_or(std::time::UNIX_EPOCH);
        let b_time = b
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .unwrap_or(std::time::UNIX_EPOCH);
        b_time.cmp(&a_time)
    });

    let proof_file = proof_files[0].clone();

    Ok(proof_file)
}
