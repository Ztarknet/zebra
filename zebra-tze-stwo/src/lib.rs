//! Prototype STWO-Cairo Transparent Zcash Extension verifier.
//!
//! This crate exposes minimal constants and a stub verifier that always succeeds.

use cairo_air::verifier::verify_cairo;
use cairo_air::{CairoProof, PreProcessedTraceVariant};
use serde_json::Error as SerdeJsonError;
use stwo_cairo_prover::stwo_prover::core::fri::FriConfig;
use stwo_cairo_prover::stwo_prover::core::pcs::PcsConfig;
use stwo_cairo_prover::stwo_prover::core::vcs::blake2_merkle::{
    Blake2sMerkleChannel, Blake2sMerkleHasher,
};
use thiserror::Error;
use tracing::instrument;
use zebra_chain::tze;

/// Extension identifier allocated to the STWO Cairo verifier TZE.
///
/// The numeric value is provisional and chosen for ease of debugging (`"STWO"` in ASCII).
pub const STWO_CAIRO_EXTENSION_ID: u64 = 0x5354_574F;

/// Supported TZE modes for the prototype.
pub const STWO_CAIRO_SUPPORTED_MODES: &[u64] = &[0];

/// Errors that may be returned by the STWO verifier stub.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Returned when the caller tries to verify a mode that is not part of the prototype surface.
    #[error("unsupported STWO mode {mode}")]
    UnsupportedMode {
        /// The unsupported mode value.
        mode: u64,
    },
    /// Returned when the precondition payload is malformed.
    #[error("invalid precondition payload: {0}")]
    InvalidPrecondition(&'static str),
    /// Returned when witness data is not valid UTF-8.
    #[error("invalid witness encoding: {0}")]
    InvalidWitnessEncoding(&'static str),
    /// Returned when the proof JSON payload cannot be parsed.
    #[error("invalid proof payload: {0}")]
    InvalidProof(#[from] SerdeJsonError),
    /// Returned when the STWO verifier reports an error.
    #[error("proof verification failed: {0}")]
    VerificationFailed(String),
}

/// Prototype verifier entry point.
///
/// The current implementation does not execute a STARK verifier. It merely checks that the
/// requested `(extension_id, mode)` pair matches the stub configuration and returns success.
#[instrument(level = "debug", skip(precondition, witness))]
pub fn verify_stwo_cairo(
    extension_id: u64,
    mode: u64,
    precondition: &tze::Data,
    witness: &tze::Data,
) -> Result<(), VerifyError> {
    if extension_id != STWO_CAIRO_EXTENSION_ID
        || precondition.extension_id.0 != STWO_CAIRO_EXTENSION_ID
        || witness.extension_id.0 != STWO_CAIRO_EXTENSION_ID
    {
        tracing::debug!(
            "prototype verifier received mismatched extension ids: request={extension_id:#x}, precondition={}, witness={}",
            precondition.extension_id.0,
            witness.extension_id.0
        );
    }

    if !STWO_CAIRO_SUPPORTED_MODES.contains(&mode)
        || !STWO_CAIRO_SUPPORTED_MODES.contains(&precondition.mode.0)
        || !STWO_CAIRO_SUPPORTED_MODES.contains(&witness.mode.0)
    {
        return Err(VerifyError::UnsupportedMode { mode });
    }

    let (with_pedersen, proof_bytes) = extract_proof_bytes(precondition, witness)?;

    let proof_str = std::str::from_utf8(proof_bytes)
        .map_err(|_| VerifyError::InvalidWitnessEncoding("proof must be valid UTF-8"))?;
    let cairo_proof: CairoProof<Blake2sMerkleHasher> = serde_json::from_str(proof_str)?;

    let preprocessed_trace = if with_pedersen {
        PreProcessedTraceVariant::Canonical
    } else {
        PreProcessedTraceVariant::CanonicalWithoutPedersen
    };

    verify_cairo::<Blake2sMerkleChannel>(cairo_proof, secure_pcs_config(), preprocessed_trace)
        .map_err(|err| VerifyError::VerificationFailed(format!("{err:?}")))
}

fn extract_proof_bytes<'a>(
    precondition: &'a tze::Data,
    witness: &'a tze::Data,
) -> Result<(bool, &'a [u8]), VerifyError> {
    if let Some(flag) = precondition.payload.first() {
        let with_pedersen = *flag != 0;
        Ok((with_pedersen, &witness.payload))
    } else if let Some((flag, rest)) = witness.payload.split_first() {
        let with_pedersen = *flag != 0;
        Ok((with_pedersen, rest))
    } else {
        Err(VerifyError::InvalidPrecondition(
            "witness payload must contain at least one byte",
        ))
    }
}

fn secure_pcs_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 26,
        fri_config: FriConfig {
            log_last_layer_degree_bound: 0,
            log_blowup_factor: 1,
            n_queries: 70,
        },
    }
}
