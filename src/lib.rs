pub mod json;
pub mod primitives;
pub mod transaction;
use crate::{primitives::*, transaction::TransactionType};
use anyhow::{anyhow, Result};
use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey as K256PublicKey};
use secp256k1::{hashes::sha256, Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use transaction::TransactionTypeV2;

pub mod rpc_model {
	tonic::include_proto!("rpc_model");
	use anyhow::anyhow;
	use std::str::FromStr;

	impl From<SubmitTransactionRequest> for SubmitTransactionRequestV2 {
		fn from(value: SubmitTransactionRequest) -> Self {
			Self {
				nonce: value.nonce,
				fee_limit: value.fee_limit,
				transaction_type: value.transaction_type.and_then(|v| Some(v.into())),
				verifying_key: value.verifying_key,
				signature: value.signature,
			}
		}
	}

	impl From<submit_transaction_request::TransactionType> for submit_transaction_request_v2::TransactionType {
		fn from(value: submit_transaction_request::TransactionType) -> Self {
			match value {
				submit_transaction_request::TransactionType::CreateStakingPool(v) => Self::CreateStakingPool(v),
				submit_transaction_request::TransactionType::NativeTokenTransfer(v) => Self::NativeTokenTransfer(v),
				submit_transaction_request::TransactionType::SmartContractDeployment(v) => {
					Self::SmartContractDeployment(
						SmartContractDeploymentV2 {
							access_type: v.access_type,
							contract_type: v.contract_type,
							contract_code: v.contract_code,
							deposit: v.value.to_string(),
							salt: v.salt
						}
					)
				},
				submit_transaction_request::TransactionType::SmartContractFunctionCall(v) => {
					Self::SmartContractFunctionCall(
						SmartContractFunctionCallV2 {
							contract_instance_address: v.contract_address,
							function_name: v.function_name,
							arguments: v.arguments,
							deposit: "0".to_owned(),
						}
					)
				},
				submit_transaction_request::TransactionType::SmartContractInit(v) => {
					Self::SmartContractInit(
						SmartContractInitV2 {
							contract_code_address: v.address,
							arguments: v.arguments,
							deposit: "0".to_owned() }
					)
				},
				submit_transaction_request::TransactionType::Stake(v) => Self::Stake(v),
				submit_transaction_request::TransactionType::Unstake(v) => Self::Unstake(v),
			}
		}
	}

	impl TryFrom<submit_transaction_request::TransactionType> for super::transaction::TransactionType {
		type Error = anyhow::Error;

		fn try_from(
			value: submit_transaction_request::TransactionType,
		) -> Result<Self, Self::Error> {
			let result_txn_type = match value {
				submit_transaction_request::TransactionType::NativeTokenTransfer(
					NativeTokenTransfer { address, amount },
				) => super::transaction::TransactionType::NativeTokenTransfer(
					address.try_into().map_err(|_| anyhow!("Failed to convert address bytes"))?,
					u128::from_str(&amount)
						.map_err(|_| anyhow!("Failed to convert string to u128"))?,
				),
				submit_transaction_request::TransactionType::SmartContractDeployment(
					SmartContractDeployment {
						access_type,
						contract_type,
						contract_code,
						value,
						salt,
					},
				) => super::transaction::TransactionType::SmartContractDeployment {
					access_type: access_type.try_into()?,
					contract_type: contract_type.try_into()?,
					contract_code,
					value: value.into(),
					salt,
				},
				submit_transaction_request::TransactionType::SmartContractInit(
					SmartContractInit { address, arguments },
				) => super::transaction::TransactionType::SmartContractInit(
					address.try_into().map_err(|_| anyhow!("Failed to convert address bytes"))?,
					arguments,
				),
				submit_transaction_request::TransactionType::SmartContractFunctionCall(
					SmartContractFunctionCall { contract_address, function_name, arguments },
				) => super::transaction::TransactionType::SmartContractFunctionCall {
					contract_instance_address: contract_address
						.try_into()
						.map_err(|_| anyhow!("Failed to convert contract_address bytes"))?,
					function: function_name,
					arguments,
				},
				submit_transaction_request::TransactionType::CreateStakingPool(
					CreateStakingPool {
						contract_instance_address,
						min_stake,
						max_stake,
						min_pool_balance,
						max_pool_balance,
						staking_period,
					},
				) => super::transaction::TransactionType::CreateStakingPool {
					contract_instance_address: match contract_instance_address {
						Some(x) => Some(x.try_into().map_err(|_| {
							anyhow!("Failed to convert contract_instance_address bytes")
						})?),
						None => None,
					},

					min_stake: min_stake.and_then(|s| s.parse().ok()),
					max_stake: max_stake.and_then(|s| s.parse().ok()),
					min_pool_balance: min_pool_balance.and_then(|s| s.parse().ok()),
					max_pool_balance: max_pool_balance.and_then(|s| s.parse().ok()),
					staking_period: staking_period.and_then(|s| s.parse().ok()),
				},
				submit_transaction_request::TransactionType::Stake(Stake {
					pool_address,
					amount,
				}) => super::transaction::TransactionType::Stake {
					pool_address: pool_address
						.try_into()
						.map_err(|_| anyhow!("Failed to convert pool_address bytes"))?,
					amount: u128::from_str(&amount)
						.map_err(|_| anyhow!("Failed to convert string to u128"))?,
				},
				submit_transaction_request::TransactionType::Unstake(UnStake {
					pool_address,
					amount,
				}) => super::transaction::TransactionType::UnStake {
					pool_address: pool_address
						.try_into()
						.map_err(|_| anyhow!("Failed to convert pool_address bytes"))?,
					amount: u128::from_str(&amount)
						.map_err(|_| anyhow!("Failed to convert string to u128"))?,
				},
			};
			Ok(result_txn_type)
		}
	}

	impl TryFrom<submit_transaction_request_v2::TransactionType> for super::transaction::TransactionTypeV2 {
		type Error = anyhow::Error;

		fn try_from(
			value: submit_transaction_request_v2::TransactionType,
		) -> Result<Self, Self::Error> {
			let result_txn_type = match value {
				submit_transaction_request_v2::TransactionType::NativeTokenTransfer(
					NativeTokenTransfer { address, amount },
				) => super::transaction::TransactionTypeV2::NativeTokenTransfer(
					address.try_into().map_err(|_| anyhow!("Failed to convert address bytes"))?,
					u128::from_str(&amount)
						.map_err(|_| anyhow!("Failed to convert string to u128"))?,
				),
				submit_transaction_request_v2::TransactionType::SmartContractDeployment(
					SmartContractDeploymentV2 {
						access_type,
						contract_type,
						contract_code,
						deposit,
						salt,
					},
				) => super::transaction::TransactionTypeV2::SmartContractDeployment {
					access_type: access_type.try_into()?,
					contract_type: contract_type.try_into()?,
					contract_code,
					deposit: crate::Balance::from_str(&deposit).map_err(|_| anyhow!("Failed to convert string to Balance"))?,
					salt,
				},
				submit_transaction_request_v2::TransactionType::SmartContractInit(
					SmartContractInitV2 { contract_code_address, arguments, deposit },
				) => super::transaction::TransactionTypeV2::SmartContractInit{
					contract_code_address: contract_code_address.try_into().map_err(|_| anyhow!("Failed to convert address bytes"))?,
					arguments: arguments,
					deposit: crate::Balance::from_str(&deposit).map_err(|_| anyhow!("Failed to convert string to Balance"))?,
				},
				submit_transaction_request_v2::TransactionType::SmartContractFunctionCall(
					SmartContractFunctionCallV2 { contract_instance_address, function_name, arguments, deposit },
				) => super::transaction::TransactionTypeV2::SmartContractFunctionCall {
					contract_instance_address: contract_instance_address
						.try_into()
						.map_err(|_| anyhow!("Failed to convert contract_instance_address bytes"))?,
					function: function_name,
					arguments,
					deposit: crate::Balance::from_str(&deposit).map_err(|_| anyhow!("Failed to convert string to Balance"))?,
				},
				submit_transaction_request_v2::TransactionType::CreateStakingPool(
					CreateStakingPool {
						contract_instance_address,
						min_stake,
						max_stake,
						min_pool_balance,
						max_pool_balance,
						staking_period,
					},
				) => super::transaction::TransactionTypeV2::CreateStakingPool {
					contract_instance_address: match contract_instance_address {
						Some(x) => Some(x.try_into().map_err(|_| {
							anyhow!("Failed to convert contract_instance_address bytes")
						})?),
						None => None,
					},

					min_stake: min_stake.and_then(|s| s.parse().ok()),
					max_stake: max_stake.and_then(|s| s.parse().ok()),
					min_pool_balance: min_pool_balance.and_then(|s| s.parse().ok()),
					max_pool_balance: max_pool_balance.and_then(|s| s.parse().ok()),
					staking_period: staking_period.and_then(|s| s.parse().ok()),
				},
				submit_transaction_request_v2::TransactionType::Stake(Stake {
					pool_address,
					amount,
				}) => super::transaction::TransactionTypeV2::Stake {
					pool_address: pool_address
						.try_into()
						.map_err(|_| anyhow!("Failed to convert pool_address bytes"))?,
					amount: u128::from_str(&amount)
						.map_err(|_| anyhow!("Failed to convert string to u128"))?,
				},
				submit_transaction_request_v2::TransactionType::Unstake(UnStake {
					pool_address,
					amount,
				}) => super::transaction::TransactionTypeV2::UnStake {
					pool_address: pool_address
						.try_into()
						.map_err(|_| anyhow!("Failed to convert pool_address bytes"))?,
					amount: u128::from_str(&amount)
						.map_err(|_| anyhow!("Failed to convert string to u128"))?,
				},
				submit_transaction_request_v2::TransactionType::Upgrade(
					Upgrade { instance_address, new_code_address, init_upgrade_args, migrate_args },
				) => super::transaction::TransactionTypeV2::Upgrade {
					instance_address: instance_address
						.try_into()
						.map_err(|_| anyhow!("Failed to convert instance_address bytes"))?,
					new_code_address: new_code_address
						.try_into()
						.map_err(|_| anyhow!("Failed to convert new_code_address bytes"))?,
					init_upgrade_args,
					migrate_args,
				},
			};
			Ok(result_txn_type)
		}
	}

	impl TryFrom<estimate_fee_request::TransactionType> for super::transaction::TransactionTypeV2 {
		type Error = anyhow::Error;

		fn try_from(
			value: estimate_fee_request::TransactionType,
		) -> Result<Self, Self::Error> {
			let result_txn_type = match value {
				estimate_fee_request::TransactionType::NativeTokenTransfer(
					NativeTokenTransfer { address, amount },
				) => super::transaction::TransactionTypeV2::NativeTokenTransfer(
					address.try_into().map_err(|_| anyhow!("Failed to convert address bytes"))?,
					u128::from_str(&amount)
						.map_err(|_| anyhow!("Failed to convert string to u128"))?,
				),
				estimate_fee_request::TransactionType::SmartContractDeployment(
					SmartContractDeploymentV2 {
						access_type,
						contract_type,
						contract_code,
						deposit,
						salt,
					},
				) => super::transaction::TransactionTypeV2::SmartContractDeployment {
					access_type: access_type.try_into()?,
					contract_type: contract_type.try_into()?,
					contract_code,
					deposit: u128::from_str(&deposit)
							.map_err(|_| anyhow!("Failed to convert string to u128"))?,
					salt,
				},
				estimate_fee_request::TransactionType::SmartContractInit(
					SmartContractInitV2 { contract_code_address, arguments, deposit },
				) => super::transaction::TransactionTypeV2::SmartContractInit {
					contract_code_address: contract_code_address.try_into().map_err(|_| anyhow!("Failed to convert address bytes"))?,
					arguments,
					deposit: u128::from_str(&deposit)
							.map_err(|_| anyhow!("Failed to convert string to u128"))?,

				},
				estimate_fee_request::TransactionType::SmartContractFunctionCall(
					SmartContractFunctionCallV2 { contract_instance_address, function_name, arguments, deposit },
				) => super::transaction::TransactionTypeV2::SmartContractFunctionCall {
					contract_instance_address: contract_instance_address.try_into().map_err(|_| anyhow!("Failed to convert address bytes"))?,
					function: function_name,
					arguments,
					deposit: u128::from_str(&deposit)
					.map_err(|_| anyhow!("Failed to convert string to u128"))?,
				},
				estimate_fee_request::TransactionType::CreateStakingPool(
					CreateStakingPool {
						contract_instance_address,
						min_stake,
						max_stake,
						min_pool_balance,
						max_pool_balance,
						staking_period,
					},
				) => super::transaction::TransactionTypeV2::CreateStakingPool {
					contract_instance_address: match contract_instance_address {
						Some(x) => Some(x.try_into().map_err(|_| {
							anyhow!("Failed to convert contract_instance_address bytes")
						})?),
						None => None,
					},

					min_stake: min_stake.and_then(|s| s.parse().ok()),
					max_stake: max_stake.and_then(|s| s.parse().ok()),
					min_pool_balance: min_pool_balance.and_then(|s| s.parse().ok()),
					max_pool_balance: max_pool_balance.and_then(|s| s.parse().ok()),
					staking_period: staking_period.and_then(|s| s.parse().ok()),
				},
				estimate_fee_request::TransactionType::Stake(Stake {
					pool_address,
					amount,
				}) => super::transaction::TransactionTypeV2::Stake {
					pool_address: pool_address
						.try_into()
						.map_err(|_| anyhow!("Failed to convert pool_address bytes"))?,
					amount: u128::from_str(&amount)
						.map_err(|_| anyhow!("Failed to convert string to u128"))?,
				},
				estimate_fee_request::TransactionType::Unstake(UnStake {
					pool_address,
					amount,
				}) => super::transaction::TransactionTypeV2::UnStake {
					pool_address: pool_address
						.try_into()
						.map_err(|_| anyhow!("Failed to convert pool_address bytes"))?,
					amount: u128::from_str(&amount)
						.map_err(|_| anyhow!("Failed to convert string to u128"))?,
				},
				estimate_fee_request::TransactionType::Upgrade(
					Upgrade { instance_address, new_code_address, init_upgrade_args, migrate_args },
				) => super::transaction::TransactionTypeV2::Upgrade {
					instance_address: instance_address
						.try_into()
						.map_err(|_| anyhow!("Failed to convert instance_address bytes"))?,
					new_code_address: new_code_address
						.try_into()
						.map_err(|_| anyhow!("Failed to convert new_code_address bytes"))?,
					init_upgrade_args,
					migrate_args,
				},
			};
			Ok(result_txn_type)
		}
	}

	impl TryFrom<transaction::Transaction> for super::transaction::TransactionType {
		type Error = anyhow::Error;

		fn try_from(value: transaction::Transaction) -> Result<Self, Self::Error> {
			let result_txn_type = match value {
				transaction::Transaction::NativeTokenTransfer(NativeTokenTransfer {
					address,
					amount,
				}) => super::transaction::TransactionType::NativeTokenTransfer(
					address.try_into().map_err(|_| anyhow!("Failed to convert address bytes"))?,
					u128::from_str(&amount)
						.map_err(|_| anyhow!("Failed to convert string to u128"))?,
				),
				transaction::Transaction::SmartContractDeployment(SmartContractDeployment {
					access_type,
					contract_type,
					contract_code,
					value,
					salt,
				}) => super::transaction::TransactionType::SmartContractDeployment {
					access_type: access_type.try_into()?,
					contract_type: contract_type.try_into()?,
					contract_code,
					value: value.into(),
					salt,
				},
				transaction::Transaction::SmartContractInit(SmartContractInit {
					address,
					arguments,
				}) => super::transaction::TransactionType::SmartContractInit(
					address.try_into().map_err(|_| anyhow!("Failed to convert address bytes"))?,
					arguments,
				),
				transaction::Transaction::SmartContractFunctionCall(
					SmartContractFunctionCall { contract_address, function_name, arguments },
				) => super::transaction::TransactionType::SmartContractFunctionCall {
					contract_instance_address: contract_address
						.try_into()
						.map_err(|_| anyhow!("Failed to convert contract_address bytes"))?,
					function: function_name,
					arguments,
				},
				/* TODO: fix this
				transaction::Transaction::CreateStakingPool(CreateStakingPool {
					contract_instance_address,
					min_stake,
					max_stake,
					min_pool_balance,
					max_pool_balance,
					staking_period,
				}) => super::transaction::TransactionType::CreateStakingPool {
					contract_instance_address: match contract_instance_address {
						Some(x) => Some(x.try_into().map_err(|_| {
							anyhow!("Failed to convert contract_instance_address bytes")
						})?),
						None => None,
					},
					min_stake: min_stake.map(|x| x.into()),
					max_stake: max_stake.map(|x| x.into()),
					min_pool_balance: min_pool_balance.map(|x| x.into()),
					max_pool_balance: max_pool_balance.map(|x| x.into()),
					staking_period: staking_period.map(|x| x.into()),
				},
				*/
				transaction::Transaction::Stake(Stake { pool_address, amount }) =>
					super::transaction::TransactionType::Stake {
						pool_address: pool_address
							.try_into()
							.map_err(|_| anyhow!("Failed to convert pool_address bytes"))?,
						amount: u128::from_str(&amount)
							.map_err(|_| anyhow!("Failed to convert string to u128"))?,
					},
				transaction::Transaction::Unstake(UnStake { pool_address, amount }) =>
					super::transaction::TransactionType::UnStake {
						pool_address: pool_address
							.try_into()
							.map_err(|_| anyhow!("Failed to convert pool_address bytes"))?,
						amount: u128::from_str(&amount)
							.map_err(|_| anyhow!("Failed to convert string to u128"))?,
					},
			};
			Ok(result_txn_type)
		}
	}
	
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TXSignPayload {
	pub nonce: Nonce,
	pub transaction_type: TransactionType,
	pub fee_limit: Balance,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TXSignPayloadV2 {
	pub nonce: String,
	pub transaction_type: TransactionTypeV2SignPayload,
	pub fee_limit: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TransactionTypeV2SignPayload {
	NativeTokenTransfer(Address, String),
	SmartContractDeployment {
		access_type: transaction::AccessType,
		contract_type: transaction::ContractType,
		contract_code: ContractCode,
		deposit: String,
		salt: Salt,
	},
	SmartContractInit {
		contract_code_address: Address,
		arguments: ContractArgument,
		deposit: String,
	},
	SmartContractFunctionCall {
		contract_instance_address: Address,
		function: ContractFunction,
		arguments: ContractArgument,
		deposit: String,
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
	Upgrade {
		instance_address: Address,
		new_code_address: Address,
		init_upgrade_args: UpgradeArgs,
		migrate_args: UpgradeArgs,
	},
}

impl From<TransactionTypeV2> for TransactionTypeV2SignPayload {
	fn from(value: TransactionTypeV2) -> Self {
		match value {
			TransactionTypeV2::NativeTokenTransfer(address, balance) => Self::NativeTokenTransfer(address, balance.to_string()),
			TransactionTypeV2::SmartContractDeployment { access_type, contract_type, contract_code, deposit, salt } =>
			Self::SmartContractDeployment { access_type, contract_type, contract_code, deposit: deposit.to_string(), salt },
			TransactionTypeV2::SmartContractFunctionCall { contract_instance_address, function, arguments, deposit } =>
			Self::SmartContractFunctionCall { contract_instance_address, function, arguments, deposit: deposit.to_string() },
			TransactionTypeV2::SmartContractInit { contract_code_address, arguments, deposit } =>
			Self::SmartContractInit { contract_code_address, arguments, deposit: deposit.to_string() },
			TransactionTypeV2::CreateStakingPool { contract_instance_address, min_stake, max_stake, min_pool_balance, max_pool_balance, staking_period } =>
				Self::CreateStakingPool { contract_instance_address, min_stake, max_stake, min_pool_balance, max_pool_balance, staking_period },
			TransactionTypeV2::Stake { pool_address, amount } =>
				Self::Stake { pool_address, amount },
			TransactionTypeV2::StakingPoolContract { pool_address, contract_instance_address } => 
				Self::StakingPoolContract { pool_address, contract_instance_address },
			TransactionTypeV2::UnStake { pool_address, amount } =>
				Self::UnStake { pool_address, amount },
			TransactionTypeV2::Upgrade { instance_address, new_code_address, init_upgrade_args, migrate_args } =>
				Self::Upgrade { instance_address, new_code_address, init_upgrade_args, migrate_args },
		}
	}
}

pub fn sign(
	secret_key: SecretKey,
	transaction_type: rpc_model::submit_transaction_request::TransactionType,
	fee_limit: Balance,
	nonce: Nonce,
) -> Result<Vec<u8>> {
	let transaction_type: TransactionType = transaction_type.try_into()?;
	let sign_payload = TXSignPayload { nonce, transaction_type, fee_limit };
	let json_str = serde_json::to_string(&sign_payload)?;
	let message = Message::from_hashed_data::<sha256::Hash>(json_str.as_bytes());
	let sig = secret_key.sign_ecdsa(message);
	Ok(sig.serialize_compact().to_vec())
}

pub fn sign_v2(
	secret_key: SecretKey,
	transaction_type: rpc_model::submit_transaction_request_v2::TransactionType,
	fee_limit: Balance,
	nonce: Nonce,
) -> Result<Vec<u8>> {
	let transaction_type: TransactionTypeV2 = transaction_type.try_into()?;
	let sign_payload = TXSignPayloadV2 { nonce: nonce.to_string(), transaction_type: transaction_type.into(), fee_limit: fee_limit.to_string() };
	let json_str = serde_json::to_string(&sign_payload)?;
	let message = Message::from_hashed_data::<sha256::Hash>(json_str.as_bytes());
	let sig = secret_key.sign_ecdsa(message);
	Ok(sig.serialize_compact().to_vec())
}

pub fn get_address_from_privkey_str(private_key: &str) -> Result<String> {
	let private_key = SecretKey::from_slice(&hex::decode(private_key)?)?;
	get_address_from_private_key(&private_key)
}

pub fn get_address_from_private_key(private_key: &SecretKey) -> Result<String> {
	let verifying_key_bytes = private_key.public_key(&Secp256k1::new()).serialize().to_vec();

	let public_key = match secp256k1::PublicKey::from_slice(verifying_key_bytes.as_slice()) {
		Ok(public_key) => public_key,
		Err(err) => return Err(anyhow!("Unable to construct public key {:?}", err)),
	};

	let k_pub_bytes = K256PublicKey::from_sec1_bytes(&public_key.serialize_uncompressed()).unwrap();

	let k_pub_bytes = k_pub_bytes.to_encoded_point(false);
	let k_pub_bytes = k_pub_bytes.as_bytes();

	let hash = Keccak256::digest(&k_pub_bytes[1..]);
	let mut bytes = [0u8; 20];
	bytes.copy_from_slice(&hash[12..]);

	Ok(hex::encode(bytes))
}
