//! Prototype STWO-Cairo Transparent Zcash Extension verifier.
//!
//! This crate exposes minimal constants and a stub verifier that always succeeds.

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

    Ok(())
}
