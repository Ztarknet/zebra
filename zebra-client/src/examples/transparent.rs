use rand_core::OsRng;
use zcash_primitives::transaction::{fees::zip317::FeeRule, TxVersion};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{consensus::BranchId, value::Zatoshis};
use zcash_transparent::{builder::TransparentSigningSet, bundle::OutPoint};
use zebra_node_services::rpc_client::RpcRequestClient;

use crate::helpers::spendable_coinbase_txid;
use crate::{client::RpcClient, wallet::regtest_default_wallet};

#[tokio::test]
async fn test_transparent_spend() {
    let client = RpcRequestClient::new("127.0.0.1:18232".parse().unwrap());

    let block_count = client.get_block_count().await.unwrap();
    let target_height = block_count + 1;

    let wallet = regtest_default_wallet();
    let miner_key = wallet.derive_key(0, 0);
    let mut builder = wallet.tx_builder(target_height);

    let coinbase_txid = spendable_coinbase_txid(&client, target_height)
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

    let to = wallet.derive_key(0, 1).transparent_address();
    let value = coin.value() - Zatoshis::const_from_u64(10000);
    builder.add_transparent_output(&to, value.unwrap()).unwrap();

    let mut transparent_signing_set = TransparentSigningSet::new();
    transparent_signing_set.add_key(miner_key.secret_key());

    let fee_rule = FeeRule::standard();
    let prover = LocalTxProver::bundled();
    let res = builder
        .build(
            &transparent_signing_set,
            &[],
            &[],
            OsRng,
            &prover,
            &prover,
            &fee_rule,
        )
        .unwrap();

    let tx = res.transaction();
    assert_eq!(tx.version(), TxVersion::ZFuture);

    let txid = client.send_raw_transaction(tx).await.unwrap().hash();
    println!("[transparent] txid: {}", txid);
}
