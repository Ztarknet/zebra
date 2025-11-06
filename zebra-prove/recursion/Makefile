install-stwo-cairo-dev-utils:
	cargo +nightly-2025-07-14 install \
		--git https://github.com/starkware-libs/stwo-cairo.git \
		--rev f57087fe5ce57e6ffe5b9c42e08038f60b3b12f4 \
		dev-utils

install-stwo-run-and-prove:
	cargo +nightly-2025-07-14 install \
		--git https://github.com/starkware-libs/bootloader-hints.git \
		--branch main \
		stwo_run_and_prove

build:
	scarb --profile release build

execute:
	scarb execute --arguments-file tests/fixtures/proof.json

proof-bin-to-cairo:
	convert_proof_format \
		--input target/proof.bz \
		--input_format binary \
		--output tests/fixtures/proof.json \
		--output_format cairo-serde

prove:
	stwo_run_and_prove \
		--program-input program_input.json \
		--prover-params prover_params.json \
		--output-dir target \
		--network regtest \
		--block-range 0-1000000 \
		--verbose
