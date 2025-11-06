use async_trait::async_trait;
use zcash_primitives::{
    block::BlockHash,
    transaction::{Transaction, TxId},
};
use zcash_protocol::consensus::BranchId;
use zebra_node_services::rpc_client::RpcRequestClient;
use zebra_rpc::methods::{
    GetAddressUtxosRequest, GetAddressUtxosResponse, GetBlockHashResponse, GetBlockResponse,
    GetRawTransactionResponse, SendRawTransactionResponse, Utxo,
};

#[async_trait]
pub trait RpcClient {
    async fn send_raw_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<SendRawTransactionResponse, anyhow::Error>;

    async fn get_raw_transaction(
        &self,
        txid: &TxId,
    ) -> Result<GetRawTransactionResponse, anyhow::Error>;

    async fn get_transaction(
        &self,
        txid: &TxId,
        branch_id: BranchId,
    ) -> Result<Transaction, anyhow::Error> {
        let tx = self.get_raw_transaction(txid).await?;
        match tx {
            GetRawTransactionResponse::Raw(tx) => Ok(Transaction::read(tx.as_ref(), branch_id)?),
            GetRawTransactionResponse::Object(tx) => {
                Ok(Transaction::read(tx.hex().as_ref(), branch_id)?)
            }
        }
    }

    async fn get_block_count(&self) -> Result<u32, anyhow::Error>;
    async fn get_block_hash(&self, height: u32) -> Result<GetBlockHashResponse, anyhow::Error>;
    async fn get_block(&self, hash: &BlockHash) -> Result<GetBlockResponse, anyhow::Error>;
    async fn get_address_utxos(&self, address: String) -> Result<Vec<Utxo>, anyhow::Error>;
}

#[async_trait]
impl RpcClient for RpcRequestClient {
    async fn send_raw_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<zebra_rpc::methods::SendRawTransactionResponse, anyhow::Error> {
        let mut tx_data = Vec::new();
        transaction.write(&mut tx_data)?;
        let tx_data_hex = hex::encode(tx_data);
        self.json_result_from_call("sendrawtransaction", format!(r#"["{tx_data_hex}"]"#))
            .await
            .map_err(|e| anyhow::anyhow!("failed to send transaction: {:?}", e))
    }

    async fn get_raw_transaction(
        &self,
        txid: &TxId,
    ) -> Result<zebra_rpc::methods::GetRawTransactionResponse, anyhow::Error> {
        let txid_hex = txid.to_string();
        self.json_result_from_call("getrawtransaction", format!(r#"["{txid_hex}", 0]"#))
            .await
            .map_err(|e| anyhow::anyhow!("failed to get transaction: {}", e))
    }

    async fn get_block_count(&self) -> Result<u32, anyhow::Error> {
        self.json_result_from_call("getblockcount", "[]".to_string())
            .await
            .map_err(|e| anyhow::anyhow!("failed to get block count: {}", e))
    }

    async fn get_block_hash(&self, height: u32) -> Result<GetBlockHashResponse, anyhow::Error> {
        self.json_result_from_call("getblockhash", format!(r#"[{height}]"#))
            .await
            .map_err(|e| anyhow::anyhow!("failed to get block hash: {}", e))
    }

    async fn get_block(&self, hash: &BlockHash) -> Result<GetBlockResponse, anyhow::Error> {
        let block_hash_hex = hash.to_string();
        self.json_result_from_call("getblock", format!(r#"["{block_hash_hex}", 0]"#))
            .await
            .map_err(|e| anyhow::anyhow!("failed to get block: {}", e))
    }

    async fn get_address_utxos(&self, address: String) -> Result<Vec<Utxo>, anyhow::Error> {
        let request = GetAddressUtxosRequest::new(vec![address], false);
        let request_json = serde_json::to_string(&request)
            .map_err(|e| anyhow::anyhow!("failed to serialize request: {}", e))?;
        let params = format!("[{}]", request_json);
        let response: GetAddressUtxosResponse = self
            .json_result_from_call("getaddressutxos", params)
            .await
            .map_err(|e| anyhow::anyhow!("failed to get address utxos: {}", e))?;

        let utxos = match response {
            GetAddressUtxosResponse::Utxos(utxos) => utxos,
            GetAddressUtxosResponse::UtxosAndChainInfo(response) => response.utxos().clone(),
        };

        Ok(utxos)
    }
}
