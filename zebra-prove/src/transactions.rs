use anyhow::{Context, Result};
use log::{info, warn};
use rand_core::OsRng;
use starknet_ff::FieldElement;
use zcash_extensions::transparent::stark_verify::stark_verify::ProofFormat;
use zcash_extensions::transparent::stark_verify::StarkVerifyBuilder;
use zcash_primitives::transaction::components::{tze, TzeOut};
use zcash_primitives::transaction::fees::fixed::FeeRule;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::consensus::Parameters;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::TxId;
use zcash_transparent::builder::TransparentSigningSet;
use zcash_transparent::bundle::{OutPoint, TxOut};
use zebra_chain::transaction::Transaction;
use zebra_client::client::RpcClient;
use zebra_client::helpers::tx_convert_librustzcash_to_zebra;
use zebra_client::wallet::Wallet;
use zebra_node_services::rpc_client::RpcRequestClient;

/// Find spendable fee outpoint for a wallet address using get_address_utxos
pub async fn get_fee_outpoint(
    rpc_client: &RpcRequestClient,
    wallet_address: String,
) -> Result<(OutPoint, TxOut)> {
    info!("Finding spendable fee outpoint...");

    let utxos = rpc_client
        .get_address_utxos(wallet_address)
        .await
        .context("Failed to get address UTXOs")?;

    if utxos.is_empty() {
        return Err(anyhow::anyhow!("No UTXOs found for wallet address"));
    }

    // Filter out UTXOs that might be immature (coinbase outputs need 100
    // confirmations)
    let current_height = rpc_client.get_block_count().await?;

    let mature_utxos: Vec<_> = utxos
        .iter()
        .filter(|u| {
            let confirmations = current_height as i64 - u.height().0 as i64 + 1;
            confirmations >= 100
        })
        .collect();

    let utxo = if mature_utxos.is_empty() {
        info!("Warning: No mature UTXOs found (need 100 confirmations), using first UTXO anyway");
        utxos.first().unwrap()
    } else {
        info!(
            "Using mature UTXO with {} confirmations",
            current_height as i64 - mature_utxos[0].height().0 as i64 + 1
        );
        mature_utxos[0]
    };

    // Convert zebra transaction hash to TxId (reverse byte order)
    let fee_txid_bytes: Vec<u8> = utxo.txid().0.iter().copied().collect();
    let fee_txid = TxId::read(&fee_txid_bytes[..])
        .context("Failed to parse TxId from UTXO")?;

    let fee_outpoint =
        OutPoint::new(fee_txid.into(), utxo.output_index().index());
    let fee_output = TxOut::new(
        Zatoshis::from_u64(utxo.satoshis())
            .context("Invalid satoshi value in UTXO")?,
        utxo.script().clone().into(),
    );

    Ok((fee_outpoint, fee_output))
}

/// Find previous TZE output from a transaction
pub async fn get_previous_prevout(
    rpc_client: &RpcRequestClient,
    previous_tx_id: TxId,
) -> Result<(tze::OutPoint, tze::TzeOut)> {
    const TZE_VOUT_INDEX: u32 = 0;

    let tze_txid = previous_tx_id;

    // Get the TZE transaction to retrieve the output
    let tze_tx = rpc_client
        .get_transaction(
            &tze_txid,
            zcash_protocol::consensus::BranchId::ZFuture,
        )
        .await
        .context("Failed to get TZE transaction")?;

    let tze_output = tze_tx
        .tze_bundle()
        .ok_or_else(|| anyhow::anyhow!("TZE transaction has no TZE bundle"))?
        .vout
        .get(TZE_VOUT_INDEX as usize)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "TZE transaction output {} not found",
                TZE_VOUT_INDEX
            )
        })?
        .clone();

    let tze_prevout =
        (tze::OutPoint::new(tze_txid, TZE_VOUT_INDEX), tze_output);

    Ok(tze_prevout)
}

/// Build transaction with StarkVerifyBuilder
pub async fn build_initialize_tx<P: Parameters>(
    tze_id: u32,
    wallet: &Wallet<P>,
    target_height: u32,
    fee_outpoint: OutPoint,
    fee_output: TxOut,
    bootloader_program_hash: FieldElement,
    os_program_hash: FieldElement,
    root: FieldElement,
    fee: Zatoshis,
) -> Result<Transaction> {
    // Derive key from wallet
    let key = wallet.derive_key(0, 0);
    let pubkey = key.public_key();

    // Create StarkVerifyBuilder
    let mut builder = StarkVerifyBuilder {
        txn_builder: wallet.tx_builder(target_height),
        extension_id: tze_id,
    };

    let fee_rule = FeeRule::non_standard(fee);
    let prover = LocalTxProver::bundled();

    // Add transparent input for fee
    builder
        .add_transparent_input(pubkey, fee_outpoint, fee_output.clone())
        .map_err(|e| {
            anyhow::anyhow!("Failed to add fee transparent input: {:?}", e)
        })?;

    // Convert FieldElement to [u8; 32] for root and program_hash
    let root_bytes = field_element_to_bytes(root);
    let os_program_hash_bytes = field_element_to_bytes(os_program_hash);
    let bootloader_program_hash_bytes = field_element_to_bytes(bootloader_program_hash);

    // Add TZE output with the proof
    builder
        .add_stark_verify_output(
            Zatoshis::ZERO,
            root_bytes,
            os_program_hash_bytes,
            bootloader_program_hash_bytes,
        )
        .map_err(|e| {
            anyhow::anyhow!("Failed to add stark verify output: {:?}", e)
        })?;

    // Calculate change output value
    let value = (fee_output.value() - fee_rule.fixed_fee())
        .context("Insufficient funds for fee")?;

    // Add transparent output (change) - send back to the same wallet
    let change_address = key.transparent_address();
    builder
        .add_transparent_output(&change_address, value)
        .map_err(|e| {
            anyhow::anyhow!("Failed to add transparent output: {:?}", e)
        })?;

    // Set up signing
    let mut transparent_signing_set = TransparentSigningSet::new();
    transparent_signing_set.add_key(key.secret_key());

    // Build transaction
    let res = builder
        .txn_builder
        .build_zfuture(
            &transparent_signing_set,
            &[], // No sapling spends
            &[], // No sapling outputs
            OsRng,
            &prover,
            &prover,
            &fee_rule,
        )
        .context("Failed to build transaction")?;

    Ok(tx_convert_librustzcash_to_zebra(res.transaction()))
}

/// Build transaction with StarkVerifyBuilder
pub async fn build_state_update_tx<P: Parameters>(
    tze_id: u32,
    wallet: &Wallet<P>,
    target_height: u32,
    tze_prevout: (tze::OutPoint, TzeOut),
    fee_prevout: (OutPoint, TxOut),
    proof_data: Vec<u8>,
    bootloader_program_hash: FieldElement,
    os_program_hash: FieldElement,
    _initial_root: FieldElement,
    final_root: FieldElement,
    fee: Zatoshis,
) -> Result<Transaction> {
    // Derive key from wallet
    let key = wallet.derive_key(0, 0);
    let pubkey = key.public_key();

    // Create StarkVerifyBuilder
    let mut builder = StarkVerifyBuilder {
        txn_builder: wallet.tx_builder(target_height),
        extension_id: tze_id,
    };

    let fee_rule = FeeRule::non_standard(fee);
    let prover = LocalTxProver::bundled();


    // TODO: Seems like ugly hack, but it works.
    warn!("Overriding TZE output index from {} to {}", tze_prevout.0.n(), 1);
    let tze_prevout = (
        tze::OutPoint::new(tze_prevout.0.txid().clone(), 1),
        tze_prevout.1,
    );

    builder
        .add_stark_verify_input(
            tze_prevout,
            proof_data.to_vec(),
            true,
            ProofFormat::BinEnc,
        )
        .map_err(|e| {
            anyhow::anyhow!("Failed to add stark verify input: {:?}", e)
        })?;

    // Add transparent input for fee
    builder
        .add_transparent_input(pubkey, fee_prevout.0, fee_prevout.1.clone())
        .map_err(|e| {
            anyhow::anyhow!("Failed to add fee transparent input: {:?}", e)
        })?;

    // Convert FieldElement to [u8; 32] for root and program_hash
    let final_root_bytes = field_element_to_bytes(final_root);
    let os_program_hash_bytes = field_element_to_bytes(os_program_hash);
    let bootloader_program_hash_bytes = field_element_to_bytes(bootloader_program_hash);


    // Add TZE output with the proof
    builder
        .add_stark_verify_output(
            Zatoshis::ZERO,
            final_root_bytes,
            os_program_hash_bytes,
            bootloader_program_hash_bytes,
        )
        .map_err(|e| {
            anyhow::anyhow!("Failed to add stark verify output: {:?}", e)
        })?;

    // Calculate change output value
    let change = (fee_prevout.1.value() - fee_rule.fixed_fee())
        .context("Insufficient funds for fee")?;

    // Add transparent output (change) - send back to the same wallet
    let change_address = key.transparent_address();
    builder
        .add_transparent_output(&change_address, change)
        .map_err(|e| {
            anyhow::anyhow!("Failed to add transparent output: {:?}", e)
        })?;

    // Set up signing
    let mut transparent_signing_set = TransparentSigningSet::new();
    transparent_signing_set.add_key(key.secret_key());

    // Build transaction
    let res = builder
        .txn_builder
        .build_zfuture(
            &transparent_signing_set,
            &[], // No sapling spends
            &[], // No sapling outputs
            OsRng,
            &prover,
            &prover,
            &fee_rule,
        )
        .context("Failed to build transaction")?;

    info!("Transaction built successfully");

    Ok(tx_convert_librustzcash_to_zebra(res.transaction()))
}

/// Convert FieldElement to [u8; 32] (big-endian)
fn field_element_to_bytes(fe: FieldElement) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&fe.to_bytes_be());
    bytes
}
