use anyhow::{Context, Result};
use bzip2::read::BzDecoder;
use bzip2::write::BzEncoder;
use bzip2::Compression;
use cairo_air::utils::get_verification_output;
use cairo_air::CairoProof;
use log::info;
use starknet_ff::FieldElement;
use std::io::{Read, Write};
use std::path::Path;
use stwo_cairo_serialize::CairoDeserialize;
use stwo_cairo_serialize::CairoSerialize;

use stwo::core::vcs::blake2_merkle::Blake2sMerkleHasher;

/// Bootloader output wrapper structure
/// Corresponds to Cairo struct:
/// ```cairo
/// struct BootloaderOutput {
///     n_tasks: usize,
///     task_output_size: usize,
///     task_program_hash: felt252,
/// }
/// ```
#[derive(Debug, Clone, CairoSerialize, CairoDeserialize)]
pub struct BootloaderOutput {
    pub n_tasks: usize,
    pub task_output_size: usize,
    pub task_program_hash: FieldElement,
}

/// OS Output Header structure
/// Corresponds to Cairo struct:
/// ```cairo
/// struct OsOutputHeader {
///     state_update_output: CommitmentUpdate*,
///     prev_block_number: felt,
///     new_block_number: felt,
///     prev_block_hash: felt,
///     new_block_hash: felt,
///     os_program_hash: felt,
///     starknet_os_config_hash: felt,
///     use_kzg_da: felt,
///     full_output: felt,
/// }
/// ```
#[derive(Debug, Clone, CairoSerialize, CairoDeserialize)]
pub struct OsOutputHeader {
    pub initial_root: FieldElement,
    pub final_root: FieldElement,
    pub prev_block_number: FieldElement,
    pub new_block_number: FieldElement,
    pub prev_block_hash: FieldElement,
    pub new_block_hash: FieldElement,
    pub os_program_hash: FieldElement,
    pub starknet_os_config_hash: FieldElement,
    pub use_kzg_da: FieldElement,
    pub full_output: FieldElement,
}

pub struct ProofPublicData {
    pub bootloader_program_hash: FieldElement,
    pub os_program_hash: FieldElement,
    pub initial_root: FieldElement,
    pub final_root: FieldElement,
}

pub fn get_proof_public_data(
    proof: &CairoProof<Blake2sMerkleHasher>,
) -> Result<ProofPublicData> {
    let verification =
        get_verification_output(&proof.claim.public_data.public_memory);
    let public_output = verification.output;

    // Deserialize OsOutputHeader (next 10 felts after bootloader wrapper)
    if public_output.len() < 3 + 10 {
        return Err(anyhow::anyhow!("Public output too short to contain bootloader wrapper and OS header (length: {}, needed: {})", public_output.len(), 3 + 10));
    }

    let mut iter = public_output.iter();
    let bootloader_output = BootloaderOutput::deserialize(&mut iter);
    let os_header = OsOutputHeader::deserialize(&mut iter);

    let proof_public_data = ProofPublicData {
        bootloader_program_hash: verification.program_hash,
        os_program_hash: bootloader_output.task_program_hash,
        initial_root: os_header.initial_root,
        final_root: os_header.final_root,
    };

    Ok(proof_public_data)
}

/// Print proof public data including bootloader wrapper and OS output header
pub fn print_proof_public_data(
    proof: &CairoProof<Blake2sMerkleHasher>,
) -> Result<ProofPublicData> {
    let proof_public_data = get_proof_public_data(proof)?;

    info!("=== Proof Public Data ===");
    info!(
        "  bootloader_program_hash: 0x{:x}",
        proof_public_data.bootloader_program_hash
    );
    info!(
        "  os_program_hash:         0x{:x}",
        proof_public_data.os_program_hash
    );
    info!(
        "  initial_root:            0x{:x}",
        proof_public_data.initial_root
    );
    info!(
        "  final_root:              0x{:x}",
        proof_public_data.final_root
    );
    info!("=== End Proof Public Data ===");

    Ok(proof_public_data)
}

/// Load proof from JSON file
pub fn load_proof_from_file(
    proof_file: &Path,
) -> Result<CairoProof<Blake2sMerkleHasher>> {
    let reader = std::fs::File::open(proof_file)?;
    let proof = serde_json::from_reader(reader)?;
    Ok(proof)
}

/// Serialize proof to compressed bincode file
pub fn serialize_proof_to_file(
    proof: &CairoProof<Blake2sMerkleHasher>,
    proof_file: &Path,
) -> Result<()> {
    let serialized_bytes =
        bincode::serialize(proof).map_err(std::io::Error::other)?;
    let file = std::fs::File::create(proof_file)?;
    let mut bz_encoder = BzEncoder::new(file, Compression::best());
    bz_encoder.write_all(&serialized_bytes)?;
    bz_encoder.finish()?;
    Ok(())
}

/// Load proof from compressed bincode file
///
/// # Arguments
/// * `proof_file` - Path to the compressed bincode proof file
pub fn load_proof_from_compressed_bincode(
    proof_file: &Path,
) -> Result<CairoProof<Blake2sMerkleHasher>> {
    let file = std::fs::File::open(proof_file)
        .context("Failed to open compressed proof file")?;
    let mut bz_decoder = BzDecoder::new(file);
    let mut decompressed_bytes = Vec::new();
    bz_decoder
        .read_to_end(&mut decompressed_bytes)
        .context("Failed to decompress proof file")?;

    let proof: CairoProof<Blake2sMerkleHasher> =
        bincode::deserialize(&decompressed_bytes).map_err(|e| {
            anyhow::anyhow!("Failed to deserialize proof: {}", e)
        })?;

    Ok(proof)
}

/// Load and print proof output from a file
///
/// # Arguments
/// * `proof_file` - Path to the proof file (either .json or .bz format)
///
/// Loads a proof from disk and prints its public output.
/// Supports both JSON format (from stwo_run_and_prove) and compressed bincode
/// format (.bz).
pub fn load_and_print_proof(proof_file: &Path) -> Result<ProofPublicData> {
    info!("Loading proof from: {}", proof_file.display());

    // Detect file format based on extension
    let proof = if proof_file.extension().and_then(|s| s.to_str()) == Some("bz")
    {
        info!("Detected compressed bincode format (.bz)");
        load_proof_from_compressed_bincode(proof_file)?
    } else if proof_file.extension().and_then(|s| s.to_str()) == Some("json") {
        info!("Detected JSON format (.json)");
        load_proof_from_file(proof_file)?
    } else {
        // Try JSON first, then compressed bincode
        info!("Unknown extension, trying JSON format first...");
        match load_proof_from_file(proof_file) {
            Ok(proof) => proof,
            Err(_) => {
                info!(
                    "JSON loading failed, trying compressed bincode format..."
                );
                load_proof_from_compressed_bincode(proof_file)?
            }
        }
    };

    info!("Proof loaded successfully!");
    print_proof_public_data(&proof)
}
