const SERDE_ANNOTATION: &str = "#[derive(serde::Serialize, serde::Deserialize)]";
const BYTES_ANNOTATION: &str = "#[serde(with = \"serde_bytes\")]";

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let mut config = prost_build::Config::new();
	config
		.type_attribute("AccountState", SERDE_ANNOTATION)
		.type_attribute("AccountType", SERDE_ANNOTATION)
		.type_attribute("GetAccountStateRequest", SERDE_ANNOTATION)
		.type_attribute("GetAccountStateResponse", SERDE_ANNOTATION)
		.type_attribute("NativeTokenTransfer", SERDE_ANNOTATION)
		.type_attribute("SmartContractDeployment", SERDE_ANNOTATION)
		.type_attribute("SmartContractInit", SERDE_ANNOTATION)
		.type_attribute("SmartContractFunctionCall", SERDE_ANNOTATION)
		.type_attribute("SmartContractDeploymentV2", SERDE_ANNOTATION)
		.type_attribute("SmartContractInitV2", SERDE_ANNOTATION)
		.type_attribute("SmartContractFunctionCallV2", SERDE_ANNOTATION)
		.type_attribute("CreateStakingPool", SERDE_ANNOTATION)
		.type_attribute("Stake", SERDE_ANNOTATION)
		.type_attribute("UnStake", SERDE_ANNOTATION)
		.type_attribute("GetCurrentNonceRequest", SERDE_ANNOTATION)
		.type_attribute("GetCurrentNonceResponse", SERDE_ANNOTATION)
		.type_attribute("GetEventsRequest", SERDE_ANNOTATION)
		.type_attribute("GetEventsResponse", SERDE_ANNOTATION)
		.type_attribute("TransactionType", SERDE_ANNOTATION)
		.type_attribute("TransactionTypeV2", SERDE_ANNOTATION)
		.type_attribute("AccessType", SERDE_ANNOTATION)
		.type_attribute("ContractType", SERDE_ANNOTATION)
		.type_attribute("TransactionStatus", SERDE_ANNOTATION)
		.type_attribute("Transaction.transaction", SERDE_ANNOTATION)
		.type_attribute("Transaction", SERDE_ANNOTATION)
		.type_attribute("TransactionV2.transaction", SERDE_ANNOTATION)
		.type_attribute("TransactionV2", SERDE_ANNOTATION)
		.type_attribute("TransactionV3.transaction", SERDE_ANNOTATION)
		.type_attribute("TransactionV3", SERDE_ANNOTATION)
		.type_attribute("SubmitTransactionRequest.transaction_type", SERDE_ANNOTATION)
		.field_attribute("SubmitTransactionRequest.signature", BYTES_ANNOTATION)
		.field_attribute("SubmitTransactionRequest.verifying_key", BYTES_ANNOTATION)
		.type_attribute("SubmitTransactionRequest", SERDE_ANNOTATION)
		.type_attribute("SubmitTransactionRequestV2.transaction_type", SERDE_ANNOTATION)
		.field_attribute("SubmitTransactionRequestV2.signature", BYTES_ANNOTATION)
		.field_attribute("SubmitTransactionRequestV2.verifying_key", BYTES_ANNOTATION)
		.type_attribute("SubmitTransactionRequestV2", SERDE_ANNOTATION)
		.type_attribute("SubmitTransactionResponse", SERDE_ANNOTATION)
		.type_attribute("EstimateFeeRequest", SERDE_ANNOTATION)
		.type_attribute("EstimateFeeRequest.transaction_type", SERDE_ANNOTATION)
		.type_attribute("EstimateFeeResponse", SERDE_ANNOTATION)
		.type_attribute("GetTransactionReceiptRequest", SERDE_ANNOTATION)
		.type_attribute("GetTransactionReceiptResponse", SERDE_ANNOTATION)
		.type_attribute("GetTransactionsByAccountRequest", SERDE_ANNOTATION)
		.type_attribute("GetTransactionsByAccountResponse", SERDE_ANNOTATION)
		.type_attribute("GetChainStateRequest", SERDE_ANNOTATION)
		.type_attribute("GetChainStateResponse", SERDE_ANNOTATION)
		.type_attribute("GetLatestBlocksRequest", SERDE_ANNOTATION)
		.type_attribute("GetLatestBlocksResponse", SERDE_ANNOTATION)
		.type_attribute("GetLatestSnapshotRequest", SERDE_ANNOTATION)
		.type_attribute("GetLatestSnapshotResponse", SERDE_ANNOTATION)
		.type_attribute("GetSnapshotRangeRequest", SERDE_ANNOTATION)
		.type_attribute("GetSnapshotRangeResponse", SERDE_ANNOTATION)
		.type_attribute("GetProtocolVersionRequest", SERDE_ANNOTATION)
		.type_attribute("GetProtocolVersionResponse", SERDE_ANNOTATION)
		.type_attribute("Block", SERDE_ANNOTATION)
		.type_attribute("BlockV2", SERDE_ANNOTATION)
		.type_attribute("BlockV3", SERDE_ANNOTATION)
		.type_attribute("BlockType", SERDE_ANNOTATION)
		.type_attribute("GetBlockByNumberRequest", SERDE_ANNOTATION)
		.type_attribute("GetBlockByNumberResponse", SERDE_ANNOTATION)
		.type_attribute("GetBlockV2ByNumberResponse", SERDE_ANNOTATION)
		.type_attribute("GetBlockV3ByNumberResponse", SERDE_ANNOTATION)
		.type_attribute("GetLatestBlockHeadersRequest", SERDE_ANNOTATION)
		.type_attribute("GetLatestBlockHeadersResponse", SERDE_ANNOTATION)
		.type_attribute("GetLatestBlockHeadersRequestV3", SERDE_ANNOTATION)
		.type_attribute("GetLatestBlockHeadersResponseV3", SERDE_ANNOTATION)
		.type_attribute("GetLatestTransactionsRequest", SERDE_ANNOTATION)
		.type_attribute("GetLatestTransactionsResponse", SERDE_ANNOTATION)
		.type_attribute("TransactionResponse", SERDE_ANNOTATION)
		.type_attribute("TransactionV2Response", SERDE_ANNOTATION)
		.type_attribute("TransactionV3Response", SERDE_ANNOTATION)
		.type_attribute("BlockHeader", SERDE_ANNOTATION)
		.type_attribute("BlockHeaderV3", SERDE_ANNOTATION)
		.type_attribute("SmartContractReadOnlyCallStatus", SERDE_ANNOTATION)
		.type_attribute("SmartContractReadOnlyCallRequest", SERDE_ANNOTATION)
		.type_attribute("SmartContractReadOnlyCallResponse", SERDE_ANNOTATION)
		.type_attribute("GetStakeRequest", SERDE_ANNOTATION)
		.type_attribute("GetStakeResponse", SERDE_ANNOTATION)
		.type_attribute("Account", SERDE_ANNOTATION)
		.type_attribute("CreateAccountRequest", SERDE_ANNOTATION)
		.type_attribute("CreateAccountResponse", SERDE_ANNOTATION)
		.type_attribute("ImportAccountRequest", SERDE_ANNOTATION)
		.type_attribute("ImportAccountResponse", SERDE_ANNOTATION)
		.protoc_arg("--experimental_allow_proto3_optional");
	tonic_build::configure().compile_with_config(config, &["l1x_rpc_model.proto"], &["proto"])?;

	Ok(())
}
