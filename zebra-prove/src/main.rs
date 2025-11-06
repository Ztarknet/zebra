use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use hex::FromHex;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use starknet_ff::FieldElement;
use std::net::SocketAddr;
use std::path::PathBuf;
use zcash_primitives::transaction::TxId;
use zcash_protocol::value::Zatoshis;
use zebra_chain::transaction::{zip317, Hash};
use zebra_client::client::RpcClient;
use zebra_client::helpers::tx_convert_zebra_to_librustzcash;
use zebra_client::regtest::{RegtestNetwork, REGTEST_NETWORK};
use zebra_client::wallet::Wallet;
use zebra_node_services::rpc_client::RpcRequestClient;

mod cmd_utils;
mod generate_pie;
mod proof_utils;
mod stwo_run_and_prove;
mod transactions;

use proof_utils::load_and_print_proof;
use stwo_run_and_prove::stwo_run_and_prove;

use crate::generate_pie::{format_block_numbers, generate_pie};
use crate::proof_utils::{
    get_program_hash_bootloader_and_os_output,
    load_proof_from_compressed_bincode,
};

/// Wallet configuration from JSON file
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    pub mnemonic: String,
}

/// Load wallet from file or use default regtest wallet
fn load_wallet(path: PathBuf) -> Result<Wallet<RegtestNetwork>> {
    info!("Loading wallet from: {}", path.display());
    let wallet_json =
        std::fs::read_to_string(&path).context("Failed to read wallet file")?;
    let wallet_config: WalletConfig = serde_json::from_str(&wallet_json)
        .context("Failed to parse wallet JSON")?;

    let wallet =
        Wallet::from_mnemonic(&wallet_config.mnemonic, REGTEST_NETWORK);
    info!("Wallet loaded from file");
    Ok(wallet)
}

#[derive(Debug, Clone, ValueEnum)]
enum Network {
    Sepolia,
    Mainnet,
}

struct NetworkConfig {
    rpc_url: &'static str,
    strk_fee_token: &'static str,
    eth_fee_token: &'static str,
}

impl Network {
    fn config(&self) -> NetworkConfig {
        match self {
            Network::Sepolia => NetworkConfig {
                rpc_url: "https://pathfinder-sepolia.d.karnot.xyz",
                strk_fee_token:
                    "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
                eth_fee_token: "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
            },
            Network::Mainnet => NetworkConfig {
                rpc_url: "https://pathfinder-mainnet.d.karnot.xyz",
                strk_fee_token:
                    "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
                eth_fee_token: "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
            },
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Network::Sepolia => "sepolia",
            Network::Mainnet => "mainnet",
        }
    }
}

#[derive(Parser)]
#[command(name = "gpp")]
#[command(
    about = "Generate PIE and Proof - A CLI utility for generating PIE using snos and creating proofs using stwo_run_and_prove"
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate PIE and create proof (full pipeline)
    Generate {
        /// Block number or range (e.g., "123" or "100-110")
        #[arg(short, long)]
        block_numbers: String,

        /// Output directory for generated files
        #[arg(short, long, default_value = "./output")]
        output_dir: PathBuf,

        /// Path to bootloader program JSON file
        #[arg(
            long,
            default_value = "bootloaders/simple_bootloader_compiled.json"
        )]
        program: PathBuf,

        /// Path to prover parameters JSON file
        #[arg(long, default_value = "prover_params.json")]
        prover_params: PathBuf,

        /// Keep intermediate files after completion
        #[arg(long)]
        keep_intermediate: bool,

        /// Network (sepolia or mainnet)
        #[arg(short, long, default_value = "sepolia")]
        network: Network,
    },
    /// Load a proof file and print its output
    ProofOutput {
        /// Path to the proof file (either .json or .bz format)
        #[arg(short, long)]
        proof_file: PathBuf,
    },
    /// Initialize the state on Zebra node
    Initialize {
        /// Path to wallet file (JSON with mnemonic)
        #[arg(short, long, default_value = "wallet.json")]
        wallet_path: PathBuf,

        /// Bootloader program hash (hex string)
        #[arg(long)]
        bootloader_program_hash: String,

        /// Program hash (hex string)
        #[arg(long)]
        os_program_hash: String,

        /// Initial root (hex string)
        #[arg(long)]
        root: String,

        /// Zebra node RPC address (IP:port)
        #[arg(long, default_value = "35.232.122.237:18232")]
        zebra_address: String,

        /// Zcash network (mainnet, testnet, regtest)
        #[arg(long, default_value = "regtest")]
        zcash_network: String,

        /// Dry run - build transaction but don't send it
        #[arg(long)]
        dry_run: bool,

        /// Transaction fee in zatoshis
        #[arg(long, default_value = "10000")]
        fee: u64,
    },
    /// Send a transaction with proof to Zebra node
    SendStateUpdate {
        /// Path to wallet file (JSON with mnemonic)
        #[arg(short, long, default_value = "wallet.json")]
        wallet_path: PathBuf,

        /// Path to the proof file (.bz format)
        #[arg(short, long)]
        proof_file: PathBuf,

        /// Previous TZE output to spend (format: txid:vout)
        #[arg(long)]
        previous_txid: String,

        /// Zebra node RPC address (IP:port)
        #[arg(long, default_value = "35.232.122.237:18232")]
        zebra_address: String,

        /// Zcash network (mainnet, testnet, regtest)
        #[arg(long, default_value = "regtest")]
        zcash_network: String,

        /// Dry run - build transaction but don't send it
        #[arg(long)]
        dry_run: bool,

        /// Transaction fee in zatoshis
        #[arg(long, default_value = "10000")]
        fee: u64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    env_logger::Builder::from_default_env()
        .filter_level(if cli.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .init();

    match cli.command {
        Commands::Generate {
            block_numbers,
            output_dir,
            program,
            prover_params,
            keep_intermediate,
            network,
        } => {
            // Get network configuration
            let network_config = network.config();
            let network_name = network.as_str();

            info!("Starting PIE generation and proof creation");
            info!("Network: {}", network_name);
            info!("Block numbers: {}", block_numbers);
            info!("Output directory: {}", output_dir.display());
            info!("RPC URL: {}", network_config.rpc_url);

            // Create output directory if it doesn't exist
            std::fs::create_dir_all(&output_dir)?;

            // Step 1: Generate PIE
            info!("=== Step 1: Generating PIE ===");

            // Format block numbers to comma-separated format
            let block_range = format_block_numbers(&block_numbers)?;

            // Create output path for PIE file
            let pie_filename =
                format!("pie_{}_{}.zip", network_name, block_numbers);
            let pie_path = output_dir.join(pie_filename);

            // Call generate-pie binary
            generate_pie(
                &block_range,
                &pie_path,
                network_config.rpc_url,
                network_name,
                network_config.strk_fee_token,
                network_config.eth_fee_token,
                cli.verbose,
            )
            .await?;

            info!("PIE generated successfully: {}", pie_path.display());

            // Step 2: Create proof
            info!("=== Step 2: Creating proof ===");
            let proof_result = stwo_run_and_prove(
                &program,
                &pie_path,
                &prover_params,
                &output_dir,
                network_name,
                &block_numbers,
                cli.verbose,
            )
            .await?;
            info!("Proof created successfully: {}", proof_result.display());

            info!("=== Step 3: Print proof output ===");
            load_and_print_proof(&proof_result)?;

            // move proof_result to current directory
            let current_dir = std::env::current_dir()?;
            let proof_result_path = current_dir.join(proof_result.file_name().unwrap());
            std::fs::rename(&proof_result, &proof_result_path)?;
            info!("Proof moved to current directory: {}", proof_result_path.display());

            // Clean up intermediate files if requested
            if !keep_intermediate {
                info!("Cleaning up intermediate files...: {}", output_dir.display());
                std::fs::remove_dir_all(&output_dir)?;
            }

            info!("Pipeline completed successfully!");
        }
        Commands::ProofOutput { proof_file } => {
            info!("Loading proof from: {}", proof_file.display());
            load_and_print_proof(&proof_file)?;
        }
        Commands::Initialize {
            wallet_path,
            bootloader_program_hash,
            os_program_hash,
            root,
            zebra_address,
            zcash_network: _,
            dry_run,
            fee,
        } => {
            info!("=== Initialize State on Zebra Node ===");
            let wallet = load_wallet(wallet_path)?;

            // Inline send_initialize_transaction logic
            // Display wallet address
            let key = wallet.derive_key(0, 0);
            info!("Wallet address: {}", key.address().encode());

            // Parse bootloader program hash, program hash and root from hex strings
            let bootloader_program_hash_fe = FieldElement::from_hex_be(&bootloader_program_hash)
                .context("Failed to parse bootloader_program_hash hex")?;
            let os_program_hash_fe = FieldElement::from_hex_be(&os_program_hash)
                .context("Failed to parse program_hash hex")?;
            let root_fe = FieldElement::from_hex_be(&root)
                .context("Failed to parse root hex")?;

            info!("Bootloader Program Hash: 0x{:x}", bootloader_program_hash_fe);
            info!("Program Hash:            0x{:x}", os_program_hash_fe);
            info!("Initial Root:            0x{:x}", root_fe);

            // Parse socket address and create RPC client
            let socket_addr: std::net::SocketAddr = zebra_address
                .parse()
                .context("Invalid Zebra address format (expected IP:port)")?;
            let rpc_client = RpcRequestClient::new(socket_addr);

            let target_height = rpc_client.get_block_count().await? + 1;
            info!("Target height: {}", target_height);

            // Find spendable fee outpoint for wallet address
            let (fee_outpoint, fee_output) = transactions::get_fee_outpoint(
                &rpc_client,
                key.address().encode(),
            )
            .await?;

            let fee_zatoshis =
                Zatoshis::from_u64(fee).context("Invalid fee amount")?;

            // Build the initialize transaction
            info!("Building initialize transaction...");
            let tx = transactions::build_initialize_tx(
                1,
                &wallet,
                target_height,
                fee_outpoint,
                fee_output,
                bootloader_program_hash_fe,
                os_program_hash_fe,
                root_fe,
                fee_zatoshis,
            )
            .await
            .context("Failed to build initialize transaction")?;

            info!("Transaction built successfully!");

            let conventional_fee = zip317::conventional_fee(&tx);
            let conventional_fee_u64: u64 = conventional_fee.into();
            if fee < conventional_fee_u64 {
                warn!(
                    "ZIP-317 conventional fee is {}, but supplied fee is {}. Increase --fee to avoid mempool rejection.",
                    conventional_fee_u64, fee
                );
            }

            // Send transaction if not dry run
            if !dry_run {
                info!("Sending transaction to Zebra node...");
                let tx_librustzcash = tx_convert_zebra_to_librustzcash(&tx);
                let send_result = rpc_client
                    .send_raw_transaction(&tx_librustzcash)
                    .await
                    .context("Failed to send transaction")?;
                info!("✓ Transaction sent successfully: {}", send_result.hash());
            }

            info!("Command completed successfully!");
        }
        Commands::SendStateUpdate {
            proof_file,
            wallet_path,
            previous_txid,
            zebra_address,
            zcash_network: _,
            dry_run,
            fee,
        } => {
            info!("=== Send Transaction to Zebra Node ===");
            let wallet = load_wallet(wallet_path)?;

            let previous_tx_id =
                TxId::from_bytes(Hash::from_hex(previous_txid)?.into());

            // Inline send_transaction logic
            // Display wallet address
            let key = wallet.derive_key(0, 0);
            info!("Wallet address: {}", key.address().encode());

            // Load proof file (assumes it's already compressed)
            info!("Loading proof file...");
            let proof_data = std::fs::read(&proof_file)
                .context("Failed to read proof file")?;
            info!("Proof loaded: {} bytes", proof_data.len());

            // Load and extract proof info
            let proof = load_proof_from_compressed_bincode(&proof_file)?;
            let (bootloader_program_hash, bootloader_output, os_header) =
                get_program_hash_bootloader_and_os_output(&proof);
            let os_program_hash = bootloader_output.task_program_hash;

            // Parse socket address and create RPC client
            let socket_addr: SocketAddr = zebra_address
                .parse()
                .context("Invalid Zebra address format (expected IP:port)")?;
            let rpc_client = RpcRequestClient::new(socket_addr);

            let target_height = rpc_client.get_block_count().await? + 1;
            info!("Target height: {}", target_height);

            // Step 2: Find spendable fee outpoint for wallet address
            let fee_prevout = transactions::get_fee_outpoint(
                &rpc_client,
                key.address().encode(),
            )
            .await?;

            // Step 3: Get previous TZE output
            let tze_prevout =
                transactions::get_previous_prevout(&rpc_client, previous_tx_id)
                    .await?;

            let fee_zatoshis =
                Zatoshis::from_u64(fee).context("Invalid fee amount")?;

            // Step 4: Build the transaction
            info!("Building transaction...");
            let tx = transactions::build_state_update_tx(
                1,
                &wallet,
                target_height,
                tze_prevout,
                fee_prevout,
                proof_data,
                bootloader_program_hash,
                os_program_hash,
                os_header.initial_root,
                os_header.final_root,
                fee_zatoshis,
            )
            .await
            .context("Failed to build transaction")?;

            info!("Transaction built successfully");

            let conventional_fee = zip317::conventional_fee(&tx);
            let conventional_fee_u64: u64 = conventional_fee.into();
            if fee < conventional_fee_u64 {
                warn!(
                    "ZIP-317 conventional fee is {}, but supplied fee is {}. Increase --fee to avoid mempool rejection.",
                    conventional_fee_u64, fee
                );
            }

            // Step 6: Send transaction if not dry run
            if !dry_run {
                let tx_librustzcash = tx_convert_zebra_to_librustzcash(&tx);
                let send_result = rpc_client
                    .send_raw_transaction(&tx_librustzcash)
                    .await
                    .context("Failed to send transaction")?;

                    info!("✓ Transaction sent successfully: {}", send_result.hash());
            }

            info!("Command completed successfully!");
        }
    }

    Ok(())
}
