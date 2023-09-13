use crate::primitives::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    pub nonce: Nonce,
    pub transaction_type: TransactionType,
    pub fee_limit: Balance,
    #[serde(with = "serde_bytes")]
    pub signature: SignatureBytes,
    #[serde(with = "serde_bytes")]
    pub verifying_key: VerifyingKeyBytes,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionType {
    NativeTokenTransfer(Address, Balance),
    SmartContractDeployment {
        access_type: AccessType,
        contract_type: ContractType,
        contract_code: ContractCode,
    },
    SmartContractInit(Address, ContractArgument),
    SmartContractFunctionCall {
        contract_instance_address: Address,
        function: ContractFunction,
        arguments: ContractArgument,
    },
    CreateStakingPool {
        contract_instance_address: Option<Address>,
        min_stake: Option<Balance>,
        max_stake: Option<Balance>,
        min_pool_balance: Option<Balance>,
        max_pool_balance: Option<Balance>,
        staking_period: Option<BlockNumber>,
    },
    Stake {
        pool_address: Address,
        amount: Balance,
    },
    UnStake {
        pool_address: Address,
        amount: Balance,
    },
    StakingPoolContract {
        pool_address: Address,
        contract_instance_address: Address,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TXSignPayload {
    pub nonce: Nonce,
    pub transaction_type: TransactionType,
    pub fee_limit: Balance,
}
