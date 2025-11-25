use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use hex::FromHex;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use starknet_ff::FieldElement;
use starknet_providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_providers::Provider;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
    get_proof_public_data, load_proof_from_compressed_bincode,
};

/// Wallet configuration from JSON file
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    pub mnemonic: String,
}

/// Sync state stored in JSON file
#[derive(Debug, Serialize, Deserialize)]
pub struct SyncState {
    /// Last block number that was synced
    pub last_synced_block: u64,
    /// Transaction ID of the last state update (empty string for first sync)
    #[serde(default)]
    pub previous_txid: String,
    /// History of all transactions sent during sync
    #[serde(default)]
    pub transaction_history: Vec<String>,
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

/// Create Starknet Provider client from RPC URL
fn create_starknet_provider(
    rpc_url: &str,
) -> Result<JsonRpcClient<HttpTransport>> {
    let url =
        url::Url::parse(rpc_url).context("Failed to parse Starknet RPC URL")?;
    Ok(JsonRpcClient::new(HttpTransport::new(url)))
}

/// Load sync state from JSON file
fn load_sync_state(path: &Path) -> Result<Option<SyncState>> {
    if path.exists() {
        let content = std::fs::read_to_string(path)
            .context("Failed to read sync state file")?;
        let state: SyncState = serde_json::from_str(&content)
            .context("Failed to parse sync state JSON")?;
        Ok(Some(state))
    } else {
        Ok(None)
    }
}

/// Save sync state to JSON file
fn save_sync_state(path: &Path, state: &SyncState) -> Result<()> {
    let content = serde_json::to_string_pretty(state)
        .context("Failed to serialize sync state")?;
    std::fs::write(path, content).context("Failed to write sync state file")?;
    Ok(())
}

/// Execute the generate command: generate PIE and create proof
async fn execute_generate(
    block_numbers: String,
    output_dir: PathBuf,
    program: PathBuf,
    prover_params: PathBuf,
    keep_intermediate: bool,
    network: Network,
    verbose: bool,
) -> Result<PathBuf> {
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
    let pie_filename = format!("pie_{}_{}.zip", network_name, block_numbers);
    let pie_path = output_dir.join(pie_filename);

    // Call generate-pie binary
    generate_pie(
        &block_range,
        &pie_path,
        network_config.rpc_url,
        network_name,
        network_config.strk_fee_token,
        network_config.eth_fee_token,
        verbose,
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
        verbose,
    )
    .await?;
    info!("Proof created successfully: {}", proof_result.display());

    info!("=== Step 3: Print proof output ===");
    load_and_print_proof(&proof_result)?;

    // move proof_result to current directory
    let current_dir = std::env::current_dir()?;
    let proof_result_path = current_dir.join(proof_result.file_name().unwrap());
    std::fs::rename(&proof_result, &proof_result_path)?;
    info!(
        "Proof moved to current directory: {}",
        proof_result_path.display()
    );

    // Clean up intermediate files if requested
    if !keep_intermediate {
        info!(
            "Cleaning up intermediate files...: {}",
            output_dir.display()
        );
        std::fs::remove_dir_all(&output_dir)?;
    }

    info!("Pipeline completed successfully!");
    Ok(proof_result_path)
}

/// Execute the proof-output command: load and print proof
fn execute_proof_output(proof_file: PathBuf) -> Result<()> {
    info!("Loading proof from: {}", proof_file.display());
    load_and_print_proof(&proof_file)?;
    Ok(())
}

/// Execute the initialize command: initialize state on Zebra node
async fn execute_initialize(
    wallet_path: PathBuf,
    bootloader_program_hash: String,
    os_program_hash: String,
    root: String,
    zebra_address: String,
    dry_run: bool,
    fee: u64,
) -> Result<Hash> {
    info!("=== Initialize State on Zebra Node ===");
    let wallet = load_wallet(wallet_path)?;

    // Display wallet address
    let key = wallet.derive_key(0, 0);
    info!("Wallet address: {}", key.address().encode());

    // Parse bootloader program hash, program hash and root from hex
    // strings
    let bootloader_program_hash_fe =
        FieldElement::from_hex_be(&bootloader_program_hash)
            .context("Failed to parse bootloader_program_hash hex")?;
    let os_program_hash_fe = FieldElement::from_hex_be(&os_program_hash)
        .context("Failed to parse program_hash hex")?;
    let root_fe =
        FieldElement::from_hex_be(&root).context("Failed to parse root hex")?;

    info!(
        "Bootloader Program Hash: 0x{:x}",
        bootloader_program_hash_fe
    );
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
    let (fee_outpoint, fee_output) =
        transactions::get_fee_outpoint(&rpc_client, key.address().encode())
            .await?;

    let fee_zatoshis = Zatoshis::from_u64(fee).context("Invalid fee amount")?;

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
        info!("Command completed successfully!");
    }

    return Ok(tx.hash());
}

/// Execute the send-state-update command: send transaction with proof
async fn execute_send_state_update(
    wallet_path: PathBuf,
    proof_file: PathBuf,
    previous_txid: String,
    zebra_address: String,
    dry_run: bool,
    fee: u64,
) -> Result<Hash> {
    info!("=== Send Transaction to Zebra Node ===");
    let wallet = load_wallet(wallet_path)?;

    // Strip "0x" prefix if present
    let txid_hex = previous_txid.strip_prefix("0x").unwrap_or(&previous_txid);
    let previous_tx_id = TxId::from_bytes(Hash::from_hex(txid_hex)?.into());

    // Display wallet address
    let key = wallet.derive_key(0, 0);
    info!("Wallet address: {}", key.address().encode());

    // Load proof file (assumes it's already compressed)
    info!("Loading proof file...");
    let proof_data =
        std::fs::read(&proof_file).context("Failed to read proof file")?;
    info!("Proof loaded: {} bytes", proof_data.len());

    // Load and extract proof info
    let proof = load_proof_from_compressed_bincode(&proof_file)?;

    let proof_public_data = get_proof_public_data(&proof)?;

    // Parse socket address and create RPC client
    let socket_addr: SocketAddr = zebra_address
        .parse()
        .context("Invalid Zebra address format (expected IP:port)")?;
    let rpc_client = RpcRequestClient::new(socket_addr);

    let target_height = rpc_client.get_block_count().await? + 1;
    info!("Target height: {}", target_height);

    // Find spendable fee outpoint for wallet address
    let fee_prevout =
        transactions::get_fee_outpoint(&rpc_client, key.address().encode())
            .await?;

    // Get previous TZE output
    let tze_prevout =
        transactions::get_previous_prevout(&rpc_client, previous_tx_id).await?;

    let fee_zatoshis = Zatoshis::from_u64(fee).context("Invalid fee amount")?;

    // Build the transaction
    info!("Building transaction...");
    let tx = transactions::build_state_update_tx(
        1,
        &wallet,
        target_height,
        tze_prevout,
        fee_prevout,
        proof_data,
        proof_public_data.bootloader_program_hash,
        proof_public_data.os_program_hash,
        proof_public_data.initial_root,
        proof_public_data.final_root,
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

    // Send transaction if not dry run
    if !dry_run {
        let tx_librustzcash = tx_convert_zebra_to_librustzcash(&tx);
        let send_result = rpc_client
            .send_raw_transaction(&tx_librustzcash)
            .await
            .context("Failed to send transaction")?;

        info!("✓ Transaction sent successfully: {}", send_result.hash());
    }

    info!("Command completed successfully!");

    Ok(tx.hash())
}

/// Check if a previous transaction is included in a block
/// Returns Ok(true) if the transaction is in a block, Ok(false) if it's still
/// in mempool
async fn check_previous_transaction_in_block(
    zebra_address: &str,
    previous_txid: &str,
) -> Result<bool> {
    // Parse socket address and create RPC client
    let socket_addr: SocketAddr = zebra_address
        .parse()
        .context("Invalid Zebra address format (expected IP:port)")?;
    let rpc_client = RpcRequestClient::new(socket_addr);

    // Parse previous transaction ID
    let txid_hex = previous_txid.strip_prefix("0x").unwrap_or(previous_txid);
    let previous_tx_id = TxId::from_bytes(Hash::from_hex(txid_hex)?.into());

    // Get transaction with verbose=1 to check if it's in a block
    match rpc_client.get_raw_transaction(&previous_tx_id).await {
        Ok(zebra_rpc::methods::GetRawTransactionResponse::Object(tx_obj)) => {
            // Transaction exists, check if it's in a block
            Ok(tx_obj.height().is_some())
        }
        Ok(zebra_rpc::methods::GetRawTransactionResponse::Raw(_)) => {
            // Raw format doesn't have height info - this is unexpected
            Err(anyhow::anyhow!(
                "Received raw transaction format for {}, cannot check block inclusion. Expected verbose format.",
                previous_txid
            ))
        }
        Err(e) => {
            // Transaction not found or error fetching - return error
            Err(anyhow::anyhow!(
                "Failed to get previous transaction {}: {}",
                previous_txid,
                e
            ))
        }
    }
}

/// Execute the sync command: sync Starknet state updates to Zebra
async fn execute_sync(
    wallet_path: PathBuf,
    zebra_address: String,
    network: Network,
    state_file: PathBuf,
    init_block: Option<u64>,
    max_blocks: u64,
    output_dir: PathBuf,
    program: PathBuf,
    prover_params: PathBuf,
    fee: u64,
    verbose: bool,
) -> Result<()> {
    info!("=== Sync Starknet State Updates to Zebra ===");

    // Get network configuration
    let network_config = network.config();

    // Step 1: Create Starknet Provider client
    info!("Connecting to Starknet RPC: {}", network_config.rpc_url);
    let provider = create_starknet_provider(network_config.rpc_url)?;

    // Step 2: Get current block number
    info!("Getting current block number from Starknet...");
    let current_block = provider
        .block_number()
        .await
        .context("Failed to get block number from Starknet provider")?;
    info!("Current Starknet block: {}", current_block);

    // Step 3: Load sync state
    info!("Loading sync state from: {}", state_file.display());
    let mut sync_state = if let Some(state) = load_sync_state(&state_file)? {
        // State exists, use it
        state
    } else {
        // Step 4: Initialize state (no state file exists)
        info!("=== Initialization Required ===");

        // Determine initialization block
        let init_block_num = init_block.unwrap_or(current_block);
        info!("Using initialization block: {}", init_block_num);

        // Generate proof for initialization block
        info!(
            "Generating proof for initialization block {}...",
            init_block_num
        );
        let init_proof_path = execute_generate(
            init_block_num.to_string(),
            output_dir.clone(),
            program.clone(),
            prover_params.clone(),
            false, // don't keep intermediate files
            network.clone(),
            verbose,
        )
        .await
        .context("Failed to generate initialization proof")?;

        // Load proof and extract public data
        info!("Extracting initialization data from proof...");
        let proof = load_proof_from_compressed_bincode(&init_proof_path)?;
        let proof_public_data = get_proof_public_data(&proof)?;

        // Convert FieldElements to hex strings
        let bootloader_program_hash =
            format!("0x{:x}", proof_public_data.bootloader_program_hash);
        let os_program_hash =
            format!("0x{:x}", proof_public_data.os_program_hash);
        let initial_root = format!("0x{:x}", proof_public_data.final_root);

        info!("Bootloader Program Hash: {}", bootloader_program_hash);
        info!("OS Program Hash: {}", os_program_hash);
        info!("Initial Root: {}", initial_root);

        // Call execute_initialize
        info!("Initializing state on Zebra node...");
        let init_tx_hash = execute_initialize(
            wallet_path.clone(),
            bootloader_program_hash,
            os_program_hash,
            initial_root,
            zebra_address.clone(),
            false, // always execute, never dry run
            fee,
        )
        .await
        .context("Failed to initialize state on Zebra node")?;

        // Create initial sync state
        let state = SyncState {
            last_synced_block: init_block_num,
            previous_txid: format!("0x{}", init_tx_hash),
            transaction_history: vec![format!("0x{}", init_tx_hash)],
        };

        save_sync_state(&state_file, &state)
            .context("Failed to save sync state after initialization")?;

        info!(
            "✓ Initialization completed. Transaction hash: 0x{}",
            init_tx_hash
        );

        state
    };

    // Step 4.5: Check if previous transaction is already included in a block
    if !sync_state.previous_txid.is_empty() {
        info!("Checking if previous transaction is included in a block...");

        // Check if previous transaction is in a block
        let is_in_block = check_previous_transaction_in_block(
            &zebra_address,
            &sync_state.previous_txid,
        )
        .await?;

        if !is_in_block {
            info!(
                "Previous transaction {} is not yet included in a block (still in mempool). Exiting.",
                sync_state.previous_txid
            );
            return Ok(());
        }
    }

    // Step 5: Calculate block range to sync
    let start_block = sync_state.last_synced_block + 1;
    let end_block =
        std::cmp::min(current_block, sync_state.last_synced_block + max_blocks);

    if start_block > end_block {
        info!(
            "No new blocks to sync. Last synced: {}, Current: {}",
            sync_state.last_synced_block, current_block
        );
        return Ok(());
    }

    info!(
        "Syncing blocks {} to {} ({} blocks)",
        start_block,
        end_block,
        end_block - start_block + 1
    );

    // Step 6: Generate proof for block range
    let block_range_str = format!("{}-{}", start_block, end_block);
    info!("Generating proof for block range: {}", block_range_str);
    let proof_path = execute_generate(
        block_range_str.clone(),
        output_dir.clone(),
        program.clone(),
        prover_params.clone(),
        false, // don't keep intermediate files
        network.clone(),
        verbose,
    )
    .await
    .context("Failed to generate proof for block range")?;

    // Step 7: Send state update
    let previous_txid = sync_state.previous_txid.clone();

    info!("Sending state update transaction...");
    let proof_path_clone = proof_path.clone();
    let update_tx_hash = execute_send_state_update(
        wallet_path.clone(),
        proof_path,
        previous_txid,
        zebra_address.clone(),
        false, // always execute, never dry run
        fee,
    )
    .await
    .context("Failed to send state update transaction")?;

    // Step 8: Update sync state
    sync_state.last_synced_block = end_block;
    sync_state.previous_txid = format!("0x{}", update_tx_hash);

    // Add to transaction history
    sync_state
        .transaction_history
        .push(format!("0x{}", update_tx_hash));

    // Limit transaction history to 100 entries (keep most recent)
    const MAX_HISTORY: usize = 100;
    if sync_state.transaction_history.len() > MAX_HISTORY {
        sync_state.transaction_history = sync_state
            .transaction_history
            .split_off(sync_state.transaction_history.len() - MAX_HISTORY);
    }

    save_sync_state(&state_file, &sync_state)
        .context("Failed to save sync state after update")?;

    // Remove proof file after successful state update
    if proof_path_clone.exists() {
        std::fs::remove_file(&proof_path_clone).context(
            "Failed to remove proof file after successful state update",
        )?;
    }

    info!("✓ Sync completed successfully!");
    info!("  Synced blocks: {} to {}", start_block, end_block);
    info!("  Transaction hash: 0x{}", update_tx_hash);
    info!("  Last synced block: {}", sync_state.last_synced_block);

    Ok(())
}

#[derive(Debug, Clone, ValueEnum)]
enum Network {
    Sepolia,
    Mainnet,
    Ztarknet,
}

struct NetworkConfig {
    rpc_url: &'static str,
    strk_fee_token: &'static str,
    eth_fee_token: &'static str,
    madara_chain_id: &'static str,
}

impl Network {
    fn config(&self) -> NetworkConfig {
        match self {
            Network::Sepolia => NetworkConfig {
                rpc_url: "https://pathfinder-sepolia.d.karnot.xyz",
                strk_fee_token:
                    "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
                eth_fee_token: "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
                madara_chain_id: "SN_MAINNET",
            },
            Network::Mainnet => NetworkConfig {
                rpc_url: "https://pathfinder-mainnet.d.karnot.xyz",
                strk_fee_token:
                    "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
                eth_fee_token: "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
                madara_chain_id: "SN_SEPOLIA",
            },
            Network::Ztarknet => NetworkConfig {
                rpc_url: "https://ztarknet-pathfinder.d.karnot.xyz",
                strk_fee_token:
                    "0x1ad102b4c4b3e40a51b6fb8a446275d600555bd63a95cdceed3e5cef8a6bc1d",
                eth_fee_token: "0x1ad102b4c4b3e40a51b6fb8a446275d600555bd63a95cdceed3e5cef8a6bc1d",
                madara_chain_id: "SN_SEPOLIA",
            },
        }
    }

    fn as_str(&self) -> &'static str {
        self.config().madara_chain_id
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
    /// Sync Starknet state updates to Zebra node
    Sync {
        /// Path to wallet file (JSON with mnemonic)
        #[arg(short, long, default_value = "wallet.json")]
        wallet_path: PathBuf,

        /// Zebra node RPC address (IP:port)
        #[arg(long, default_value = "35.232.122.237:18232")]
        zebra_address: String,

        /// Network (sepolia or mainnet)
        #[arg(short, long, default_value = "sepolia")]
        network: Network,

        /// Path to sync state JSON file
        #[arg(long, default_value = "sync-state.json")]
        state_file: PathBuf,

        /// Block number to initialize with if state file doesn't exist
        #[arg(long)]
        init_block: Option<u64>,

        /// Maximum blocks to sync per run
        #[arg(long, default_value = "5")]
        max_blocks: u64,

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
            execute_generate(
                block_numbers,
                output_dir,
                program,
                prover_params,
                keep_intermediate,
                network,
                cli.verbose,
            )
            .await?;
        }
        Commands::ProofOutput { proof_file } => {
            execute_proof_output(proof_file)?;
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
            execute_initialize(
                wallet_path,
                bootloader_program_hash,
                os_program_hash,
                root,
                zebra_address,
                dry_run,
                fee,
            )
            .await?;
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
            execute_send_state_update(
                wallet_path,
                proof_file,
                previous_txid,
                zebra_address,
                dry_run,
                fee,
            )
            .await?;
        }
        Commands::Sync {
            wallet_path,
            zebra_address,
            network,
            state_file,
            init_block,
            max_blocks,
            output_dir,
            program,
            prover_params,
            fee,
        } => {
            execute_sync(
                wallet_path,
                zebra_address,
                network,
                state_file,
                init_block,
                max_blocks,
                output_dir,
                program,
                prover_params,
                fee,
                cli.verbose,
            )
            .await?;
        }
    }

    Ok(())
}
