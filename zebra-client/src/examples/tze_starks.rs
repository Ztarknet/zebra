use crate::regtest::RegtestNetwork;
use crate::{client::RpcClient, wallet::regtest_default_wallet};
use rand_core::OsRng;
use zcash_extensions::transparent::stark_verify;
use zcash_primitives::transaction::components::tze::{self, TzeOut};
use zcash_primitives::transaction::fees::fixed::FeeRule;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::TxId;
use zcash_protocol::{consensus::BranchId, value::Zatoshis};
use zcash_transparent::bundle::TxOut;
use zcash_transparent::{builder::TransparentSigningSet, bundle::OutPoint};
use zebra_chain::transaction::{self, zip317};
use zebra_node_services::rpc_client::RpcRequestClient;

use crate::helpers::{
    spendable_coinbase_txid, tx_convert_librustzcash_to_zebra, tx_convert_zebra_to_librustzcash,
};
use crate::wallet::Wallet;

#[tokio::test]
async fn test_tze_starks() {
    let client = RpcRequestClient::with_base_url("https://rpc.regtest.ztarknet.cash");
    let block_count = client.get_block_count().await.unwrap();
    let target_height = block_count + 1;
    let wallet = regtest_default_wallet();

    // [coinbase utxo] -> [tze output 1]
    let (tx_0, tze_output_0) = send_tx_0(&client, &wallet, target_height).await;
    println!("[tze starks] tx_0: {}", tx_0);

    // [tze utxo 1] -> [tze output 2]
    let (tx_1, _) = send_tx_1(&client, &wallet, target_height, tx_0, tze_output_0).await;
    println!("[tze starks] tx_1: {}", tx_1);
}

fn build_tx_0(
    wallet: &Wallet<RegtestNetwork>,
    target_height: u32,
    prev_txid: TxId,
    prev_output: TxOut,
    fee: Zatoshis,
) -> zebra_chain::transaction::Transaction {
    let miner_key = wallet.derive_key(0, 0);
    let mut builder = stark_verify::StarkVerifyBuilder {
        txn_builder: wallet.tx_builder(target_height),
        extension_id: 1,
    };

    let fee_rule = FeeRule::non_standard(fee);
    let prover = LocalTxProver::bundled();

    builder
        .add_transparent_input(
            miner_key.public_key(),
            OutPoint::new(prev_txid.into(), 0),
            prev_output.clone(),
        )
        .unwrap();

    let (_, initial_root, _, program_hash) = proof_data();

    let value = (prev_output.value() - fee_rule.fixed_fee()).expect("value is positive");
    builder
        .add_stark_verify_output(value, initial_root, program_hash)
        .map_err(|e| format!("open failure: {:?}", e))
        .unwrap();

    let mut transparent_signing_set = TransparentSigningSet::new();
    transparent_signing_set.add_key(miner_key.secret_key());

    let res = builder
        .txn_builder
        .build_zfuture(
            &transparent_signing_set,
            &[],
            &[],
            OsRng,
            &prover,
            &prover,
            &fee_rule,
        )
        .map_err(|e| format!("build failure: {:?}", e))
        .unwrap();

    tx_convert_librustzcash_to_zebra(res.transaction())
}

async fn send_tx_0(
    client: &RpcRequestClient,
    wallet: &Wallet<RegtestNetwork>,
    target_height: u32,
) -> (transaction::Hash, TzeOut) {
    let coinbase_txid = spendable_coinbase_txid(client, target_height)
        .await
        .unwrap();

    let prev_tx = client
        .get_transaction(&coinbase_txid, BranchId::ZFuture)
        .await
        .unwrap();

    let prev_output = prev_tx.transparent_bundle().unwrap().vout[0].clone();

    let tx = build_tx_0(
        wallet,
        target_height,
        coinbase_txid,
        prev_output.clone(),
        Zatoshis::const_from_u64(10000),
    );

    let conventional_fee = zip317::conventional_fee(&tx).try_into().unwrap();
    println!("conventional_fee: {conventional_fee:?}");

    let tx = build_tx_0(
        wallet,
        target_height,
        coinbase_txid,
        prev_output,
        conventional_fee,
    );
    let tx = tx_convert_zebra_to_librustzcash(&tx);

    let tze_output = tx.tze_bundle().unwrap().vout[0].clone();
    let txid = client.send_raw_transaction(&tx).await.unwrap().hash();

    (txid, tze_output)
}

fn build_tx_1(
    wallet: &Wallet<RegtestNetwork>,
    target_height: u32,
    prev_tx_hash: transaction::Hash,
    prev_tze_output: TzeOut,
    fee: Zatoshis,
) -> zebra_chain::transaction::Transaction {
    let mut builder = stark_verify::StarkVerifyBuilder {
        txn_builder: wallet.tx_builder(target_height),
        extension_id: 1,
    };

    let fee_rule = FeeRule::non_standard(fee);
    let prover = LocalTxProver::bundled();
    let prevout = tze::OutPoint::new(TxId::from_bytes(prev_tx_hash.0), 0);
    let value_xfr = (prev_tze_output.value - fee_rule.fixed_fee()).unwrap();

    let (proof_data, _, final_root, program_hash) = proof_data();

    builder
        .add_stark_verify_input(
            (prevout, prev_tze_output),
            proof_data.to_vec(),
            true,
            stark_verify::stark_verify::ProofFormat::BinEnc,
        )
        .unwrap();

    builder
        .add_stark_verify_output(value_xfr, final_root, program_hash)
        .map_err(|e| format!("open failure: {:?}", e))
        .unwrap();

    let res = builder
        .txn_builder
        .build_zfuture(
            &TransparentSigningSet::new(),
            &[],
            &[],
            OsRng,
            &prover,
            &prover,
            &fee_rule,
        )
        .map_err(|e| format!("build failure: {:?}", e))
        .unwrap();

    tx_convert_librustzcash_to_zebra(res.transaction())
}

async fn send_tx_1(
    client: &RpcRequestClient,
    wallet: &Wallet<RegtestNetwork>,
    target_height: u32,
    prev_tx_hash: transaction::Hash,
    prev_tze_output: TzeOut,
) -> (transaction::Hash, TzeOut) {
    let tx = build_tx_1(
        wallet,
        target_height,
        prev_tx_hash,
        prev_tze_output.clone(),
        Zatoshis::const_from_u64(10000),
    );

    let conventional_fee = zip317::conventional_fee(&tx).try_into().unwrap();
    println!("conventional_fee: {conventional_fee:?}");

    let tx = build_tx_1(
        wallet,
        target_height,
        prev_tx_hash,
        prev_tze_output,
        conventional_fee,
    );
    let tx = tx_convert_zebra_to_librustzcash(&tx);

    let tze_output = tx.tze_bundle().unwrap().vout[0].clone();
    let txid = client.send_raw_transaction(&tx).await.unwrap().hash();

    (txid, tze_output)
}

fn proof_data() -> (Vec<u8>, [u8; 32], [u8; 32], [u8; 32]) {
    let initial_root: [u8; 32] =
        hex::decode("07bea7a967f1c40fedf5dd92e8415facc2175e3e72a80f609901c33d2b2c1973")
            .unwrap()
            .try_into()
            .unwrap();
    let final_root: [u8; 32] =
        hex::decode("051306f206bd001c17189d0ca0894c2f9aaaacc701e5122390f463655dccd613")
            .unwrap()
            .try_into()
            .unwrap();
    let program_hash: [u8; 32] = [0; 32];
    let proof_data = include_bytes!("../../tests/fixtures/proof-sepolia-2725346.bz");
    (proof_data.to_vec(), initial_root, final_root, program_hash)
}
