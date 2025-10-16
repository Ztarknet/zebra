//! Prototype STWO-Cairo verifier wiring for Zebra.
//!
//! This crate exposes a wrapper that feeds proofs into the STWO Cairo verifier.

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

/// Errors that may be returned by the STWO verifier stub.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Returned when witness data is not valid UTF-8.
    #[error("invalid proof encoding: {0}")]
    InvalidProofEncoding(&'static str),
    /// Returned when the proof JSON payload cannot be parsed.
    #[error("invalid proof payload: {0}")]
    InvalidProof(#[from] SerdeJsonError),
    /// Returned when the STWO verifier reports an error.
    #[error("proof verification failed: {0}")]
    VerificationFailed(String),
}

/// Prototype verifier entry point that validates a JSON-encoded proof.
#[instrument(level = "debug")]
pub fn verify_stwo_cairo(with_pedersen: bool, proof_bytes: &[u8]) -> Result<(), VerifyError> {
    let proof_str = std::str::from_utf8(proof_bytes)
        .map_err(|_| VerifyError::InvalidProofEncoding("proof must be valid UTF-8"))?;
    let cairo_proof: CairoProof<Blake2sMerkleHasher> = serde_json::from_str(proof_str)?;

    let preprocessed_trace = if with_pedersen {
        PreProcessedTraceVariant::Canonical
    } else {
        PreProcessedTraceVariant::CanonicalWithoutPedersen
    };

    verify_cairo::<Blake2sMerkleChannel>(cairo_proof, secure_pcs_config(), preprocessed_trace)
        .map_err(|err| VerifyError::VerificationFailed(format!("{err:?}")))
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

#[cfg(test)]
mod tests {
    use cairo_vm::Felt252;
    use num_bigint::BigInt;

    use super::*;
    use cairo_lang_runner::Arg;
    use cairo_prove::args::RunTarget;
    use cairo_prove::execute::execute;
    use cairo_prove::prove::{prove, prover_input_from_runner};
    use stwo_cairo_prover::stwo_prover::core::pcs::PcsConfig;

    fn execute_and_prove(target_path: &str, args: Vec<Arg>, pcs_config: PcsConfig) -> Vec<u8> {
        let executable = serde_json::from_reader(std::fs::File::open(target_path).unwrap())
            .expect("Failed to read executable");
        let runner = execute(executable, RunTarget::default(), args);
        let prover_input = prover_input_from_runner(&runner);
        let proof = prove(prover_input, pcs_config);
        serde_json::to_vec(&proof).expect("Failed to serialize proof to JSON")
    }

    #[test]
    fn test_e2e() {
        let target_path = "./example/target/release/example.executable.json";
        let args = vec![Arg::Value(Felt252::from(BigInt::from(100)))];
        let proof_bytes = execute_and_prove(target_path, args, PcsConfig::default());

        let result = verify_stwo_cairo(false, &proof_bytes);
        assert!(result.is_ok());
    }
}
