// pub mod json;
pub mod json;
pub mod primitives;
pub mod transaction;
use crate::primitives::*;
use crate::transaction::TransactionType;
use anyhow::{anyhow, Result};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey as K256PublicKey;
use secp256k1::{hashes::sha256, Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

pub mod rpc_model {
    tonic::include_proto!("rpc_model");
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TXSignPayload {
    pub nonce: Nonce,
    pub transaction_type: TransactionType,
    pub fee_limit: Balance,
}

pub fn sign(
    secret_key: SecretKey,
    transaction_type: TransactionType,
    fee_limit: Balance,
    nonce: Nonce,
) -> Result<Vec<u8>> {
    let sign_payload = TXSignPayload {
        nonce,
        transaction_type,
        fee_limit,
    };
    let json_str = serde_json::to_string(&sign_payload)?;
    let message = Message::from_hashed_data::<sha256::Hash>(json_str.as_bytes());
    let sig = secret_key.sign_ecdsa(message);
    Ok(sig.serialize_compact().to_vec())
}

pub fn get_address_from_privkey_str(private_key: &str) -> Result<String> {
    let private_key = SecretKey::from_slice(&hex::decode(private_key)?)?;
    get_address_from_privkey(&private_key)
}

pub fn get_address_from_privkey(private_key: &SecretKey) -> Result<String> {
    let verifying_key_bytes = private_key
        .public_key(&Secp256k1::new())
        .serialize()
        .to_vec();

    let public_key = match secp256k1::PublicKey::from_slice(verifying_key_bytes.as_slice()) {
        Ok(public_key) => public_key,
        Err(err) => return Err(anyhow!("Unable to construct public key {:?}", err)),
    };

    let k_pub_bytes = K256PublicKey::from_sec1_bytes(&public_key.serialize_uncompressed()).unwrap();

    let k_pub_bytes = k_pub_bytes.to_encoded_point(false);
    let k_pub_bytes = k_pub_bytes.as_bytes();

    let hash = Keccak256::digest(&k_pub_bytes[1..]); // keccak256(&k_pub_bytes[1..]);
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&hash[12..]);

    Ok(hex::encode(bytes))
}
