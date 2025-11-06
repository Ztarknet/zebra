# GPP - Generate PIE and Proof

A Rust CLI utility for generating PIE (Position Independent Executable) using snos and creating proofs using stwo_run_and_prove from bootloader-hints.

## Overview

This utility implements a sequential pipeline that:
1. Generates PIE using snos (at commit `44e82ff35277fdc102a5613975e02975a2b111e4`)
2. Creates a proof using `stwo_run_and_prove` from bootloader-hints (main branch)

## Prerequisites

### Required Files

Before running the utility, you need to have these files in your working directory:

1. **`bootloaders/simple_bootloader_compiled.json`** - The bootloader program file
2. **`prover_params.json`** - Prover parameters configuration

### Required Tools

- **`generate-pie` binary from snos** - Install at commit `44e82ff35277fdc102a5613975e02975a2b111e4`:
  ```bash
  cargo install --git https://github.com/keep-starknet-strange/snos --rev 44e82ff35277fdc102a5613975e02975a2b111e4 generate-pie
  ```

- **`stwo_run_and_prove`** - Install it using:
  ```bash
  cargo +nightly-2025-07-14 install --git ssh://git@github.com/starkware-libs/bootloader-hints.git --branch main stwo_run_and_prove
  ```

## Installation

```bash
# Clone or download this project
cd gpp

# Build the project
cargo build --release

# The binary will be available at ./target/release/gpp
```

## Usage

### Basic Usage

```bash
# Single block on Sepolia
./target/release/gpp --input "924015" --network sepolia

# Block range on Mainnet
./target/release/gpp --input "100-110" --network mainnet \
  --rpc-url "https://pathfinder-mainnet.d.karnot.xyz"
```

### Advanced Usage

```bash
./target/release/gpp \
  --input "block_123_network_mainnet" \
  --output-dir "./my_output" \
  --program "./my_bootloader.json" \
  --prover-params "./my_prover_params.json" \
  --verbose \
  --keep-intermediate
```

### Command Line Options

- `-i, --input <INPUT>` - Block number or range (e.g., "123" or "100-110")
- `-o, --output-dir <OUTPUT_DIR>` - Output directory for generated files [default: ./output]
- `--program <PROGRAM>` - Path to bootloader program JSON file [default: bootloaders/simple_bootloader_compiled.json]
- `--prover-params <PROVER_PARAMS>` - Path to prover parameters JSON file [default: prover_params.json]
- `--keep-intermediate` - Keep intermediate files after completion
- `-v, --verbose` - Enable verbose logging
- `-h, --help` - Print help
- `-V, --version` - Print version

## Workflow

1. **PIE Generation**: The utility generates a PIE file using the provided input data
2. **Program Input Creation**: Creates a JSON file in the format expected by `stwo_run_and_prove`
3. **Proof Generation**: Calls `stwo_run_and_prove` with the generated PIE and configuration files
4. **Result Processing**: Parses and displays timing, memory usage, and proof size information

## Output Files

The utility creates several files in the output directory:

- `pie_<timestamp>.json` - Generated PIE file (placeholder implementation)
- `program_input.json` - Input file for stwo_run_and_prove
- `proofs/` - Directory containing the generated proof files

## Current Implementation Status

### ✅ Implemented
- CLI interface with comprehensive argument parsing
- PIE generation module (placeholder implementation)
- Proof generation module with stwo_run_and_prove integration
- Sequential pipeline workflow
- Error handling and logging
- Timing and memory usage reporting

### 🚧 Placeholder/To Be Implemented
- **snos Integration**: The utility now attempts to call the `generate-pie` binary from snos. If not available, it falls back to a placeholder implementation.
- **PIE Format**: Currently generates ZIP files for PIE output, but the placeholder content may not be compatible with `stwo_run_and_prove`.

## Development Notes

### snos Integration

The utility now integrates with snos by calling the `generate-pie` binary as a subprocess. This approach:
- Avoids complex dependency conflicts
- Provides better error handling and fallback behavior
- Is more maintainable and reliable

To enable full snos integration:
1. Install the `generate-pie` binary: `cargo install --git https://github.com/keep-starknet-strange/snos generate-pie`
2. The utility will automatically detect and use the binary when available
3. If not available, it falls back to a placeholder implementation

### stwo_run_and_prove Integration

The utility correctly calls `stwo_run_and_prove` as a subprocess with the proper arguments:
- `--program`: Path to bootloader program JSON
- `--program_input`: JSON with PIE path and configuration
- `--prover_params_json`: Prover parameters file
- `--proofs_dir`: Output directory for proofs
- `--verify`: Enable proof verification

## Example Output

```
[2025-10-30T10:34:17Z INFO  gpp] Starting PIE generation and proof creation
[2025-10-30T10:34:17Z INFO  gpp] Input: test_block_123
[2025-10-30T10:34:17Z INFO  gpp] Output directory: ./output
[2025-10-30T10:34:17Z INFO  gpp] === Step 1: Generating PIE ===
[2025-10-30T10:34:17Z INFO  gpp::pie_generator] Generating PIE for input: test_block_123
[2025-10-30T10:34:17Z INFO  gpp::pie_generator] PIE generated successfully: ./output/pie_1761820457.json
[2025-10-30T10:34:17Z INFO  gpp] === Step 2: Creating proof ===
[2025-10-30T10:34:17Z INFO  gpp::prover] Creating proof for PIE: ./output/pie_1761820457.json
[2025-10-30T10:34:17Z INFO  gpp::prover] Calling stwo_run_and_prove...
[2025-10-30T10:34:17Z INFO  gpp::prover] Elapsed time: 2.34s
[2025-10-30T10:34:17Z INFO  gpp::prover] Proof size: 1.23 MB
[2025-10-30T10:34:17Z INFO  gpp] Pipeline completed successfully!
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is part of the gpp experiments with generating, proving and posting Madara blocks to Zcash.