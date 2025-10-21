use crate::regtest::RegtestNetwork;
use crate::{client::RpcClient, wallet::regtest_default_wallet};
use blake2b_simd::Params;
use rand_core::OsRng;
use zcash_extensions::transparent::demo;
use zcash_primitives::transaction::components::tze::{self, TzeOut};
use zcash_primitives::transaction::fees::fixed::FeeRule;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::TxId;
use zcash_protocol::{consensus::BranchId, value::Zatoshis};
use zcash_transparent::{builder::TransparentSigningSet, bundle::OutPoint};
use zebra_chain::transaction;
use zebra_node_services::rpc_client::RpcRequestClient;

use crate::helpers::spendable_coinbase_txid;
use crate::wallet::Wallet;

#[tokio::test]
async fn test_tze_output() {
    let client = RpcRequestClient::new("127.0.0.1:18232".parse().unwrap());
    let block_count = client.get_block_count().await.unwrap();
    let target_height = block_count + 1;
    let wallet = regtest_default_wallet();

    // [coinbase utxo] -> [tze output 1]
    let (tx_0, tze_output_0) = send_tx_0(&client, &wallet, target_height).await;
    println!("[tze demo] tx_0: {}", tx_0);

    // [tze utxo 1] -> [tze output 2]
    let (tx_1, tze_output_1) = send_tx_1(&client, &wallet, target_height, tx_0, tze_output_0).await;
    println!("[tze demo] tx_1: {}", tx_1);

    // [tze utxo 2] -> [transparent output]
    let tx_2 = send_tx_2(&client, &wallet, target_height, tx_1, tze_output_1).await;
    println!("[tze demo] tx_2: {}", tx_2);
}

async fn send_tx_0(
    client: &RpcRequestClient,
    wallet: &Wallet<RegtestNetwork>,
    target_height: u32,
) -> (transaction::Hash, TzeOut) {
    let miner_key = wallet.derive_key(0, 0);
    let mut builder = demo::DemoBuilder {
        txn_builder: wallet.tx_builder(target_height),
        extension_id: 0,
    };

    let coinbase_txid = spendable_coinbase_txid(client, target_height)
        .await
        .unwrap();

    let prev_tx = client
        .get_transaction(&coinbase_txid, BranchId::ZFuture)
        .await
        .unwrap();

    let coin = prev_tx.transparent_bundle().unwrap().vout[0].clone();

    builder
        .add_transparent_input(
            miner_key.public_key(),
            OutPoint::new(coinbase_txid.into(), 0),
            coin.clone(),
        )
        .unwrap();

    let (_, _, h1, _) = demo_data();
    let value = coin.value() - Zatoshis::const_from_u64(10000);
    builder
        .demo_open(value.unwrap(), h1)
        .map_err(|e| format!("open failure: {:?}", e))
        .unwrap();

    let mut transparent_signing_set = TransparentSigningSet::new();
    transparent_signing_set.add_key(miner_key.secret_key());

    let fee_rule = FeeRule::non_standard(Zatoshis::const_from_u64(10000));
    let prover = LocalTxProver::bundled();

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

    let tx = res.transaction();

    let tze_output = tx.tze_bundle().unwrap().vout[0].clone();
    let txid = client.send_raw_transaction(tx).await.unwrap().hash();

    (txid, tze_output)
}

async fn send_tx_1(
    client: &RpcRequestClient,
    wallet: &Wallet<RegtestNetwork>,
    target_height: u32,
    prev_tx_hash: transaction::Hash,
    prev_tze_output: TzeOut,
) -> (transaction::Hash, TzeOut) {
    let mut builder = demo::DemoBuilder {
        txn_builder: wallet.tx_builder(target_height),
        extension_id: 0,
    };
    let prover = LocalTxProver::bundled();
    let fee_rule = FeeRule::non_standard(Zatoshis::const_from_u64(10000));

    let prevout = tze::OutPoint::new(TxId::from_bytes(prev_tx_hash.0), 0);
    let (preimage_1, _, _, h2) = demo_data();
    let value_xfr = (prev_tze_output.value - fee_rule.fixed_fee()).unwrap();

    builder
        .demo_transfer_to_close((prevout, prev_tze_output), value_xfr, preimage_1, h2)
        .map_err(|e| format!("transfer failure: {:?}", e))
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

    let tx = res.transaction();

    let tze_output = tx.tze_bundle().unwrap().vout[0].clone();
    let txid = client.send_raw_transaction(tx).await.unwrap().hash();

    (txid, tze_output)
}

async fn send_tx_2(
    client: &RpcRequestClient,
    wallet: &Wallet<RegtestNetwork>,
    target_height: u32,
    prev_tx_hash: transaction::Hash,
    prev_tze_output: TzeOut,
) -> transaction::Hash {
    let mut builder = demo::DemoBuilder {
        txn_builder: wallet.tx_builder(target_height),
        extension_id: 0,
    };
    let prover = LocalTxProver::bundled();
    let fee_rule = FeeRule::non_standard(Zatoshis::const_from_u64(10000));

    let prevout = tze::OutPoint::new(TxId::from_bytes(prev_tx_hash.0), 0);
    let (_, preimage_2, _, _) = demo_data();
    let value_xfr = (prev_tze_output.value - fee_rule.fixed_fee()).unwrap();

    builder
        .demo_close((prevout, prev_tze_output), preimage_2)
        .map_err(|e| format!("close failure: {:?}", e))
        .unwrap();

    builder
        .add_transparent_output(&wallet.derive_key(0, 1).transparent_address(), value_xfr)
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

    let tx = res.transaction();

    let txid = client.send_raw_transaction(tx).await.unwrap().hash();
    txid
}

fn demo_data() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    let preimage_1 = [1; 32];
    let preimage_2 = [2; 32];
    let (h1, h2) = demo_hashes(&preimage_1, &preimage_2);
    (preimage_1, preimage_2, h1, h2)
}

fn hash_1(preimage_1: &[u8; 32], hash_2: &[u8; 32]) -> [u8; 32] {
    let mut hash = [0; 32];
    hash.copy_from_slice(
        Params::new()
            .hash_length(32)
            .personal(b"demo_pc_h1_perso")
            .to_state()
            .update(preimage_1)
            .update(hash_2)
            .finalize()
            .as_bytes(),
    );
    hash
}

fn demo_hashes(preimage_1: &[u8; 32], preimage_2: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hash_2 = {
        let mut hash = [0; 32];
        hash.copy_from_slice(
            Params::new()
                .hash_length(32)
                .personal(b"demo_pc_h2_perso")
                .hash(preimage_2)
                .as_bytes(),
        );
        hash
    };

    (hash_1(preimage_1, &hash_2), hash_2)
}
