STWO_CAIRO_REV=f57087fe5ce57e6ffe5b9c42e08038f60b3b12f4
PROVING_UTILS_REV=efbaeebfdce3463aa61e16d7d8e6069f03df0994

install-stwo-run-and-prove:
	cargo +nightly-2025-07-14 install \
		--git ssh://git@github.com/m-kus/proving-utils.git \
		--rev $(PROVING_UTILS_REV) \
		stwo_run_and_prove --force

build:
	scarb --profile release build

execute:
	scarb execute --arguments-file tests/fixtures/ztarknet_proof.serde.json

ztarknet-proof-bin-to-cairo:
	cargo run --release --bin zebra-prove -- binary-to-cairo-serde \
		--proof-file tests/fixtures/ztarknet_proof.bz \
		--output-path tests/fixtures/ztarknet_proof.serde.json

prove-step-1:
	stwo_run_and_prove \
		--program ../bootloaders/simple_bootloader_compiled.json \
		--program_input program_input_step_1.json \
		--prover_params_json prover_params_step_1.json \
		--proofs_dir target \
		--proof-format cairo-serde \
		--verify

prove-step-2:
	stwo_run_and_prove \
		--program ../bootloaders/simple_bootloader_compiled.json \
		--program_input program_input_step_2.json \
		--prover_params_json prover_params_step_2.json \
		--proofs_dir target \
		--proof-format cairo-serde \
		--verify

prove-step-3:
	stwo_run_and_prove \
		--program ../bootloaders/simple_bootloader_compiled.json \
		--program_input program_input_step_3.json \
		--prover_params_json prover_params_step_3.json \
		--proofs_dir target \
		--proof-format cairo-serde \
		--verify
