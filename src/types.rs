use serde::{Deserialize, Serialize};
use serde_aux::prelude::*;

use crate::crypto::base64::Base64;

#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkInfo {
    pub network: String,
    pub version: usize,
    pub release: usize,
    pub height: u128,
    pub current: Base64,
    pub blocks: usize,
    pub peers: usize,
    pub queue_length: usize,
    pub node_state_latency: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProofOfAccess {
    pub option: String,
    pub tx_path: Base64,
    pub data_path: Base64,
    pub chunk: Base64,
}

//Defined in https://docs.arweave.org/developers/server/http-api#block-format
#[derive(Serialize, Deserialize, Debug)]
pub struct BlockInfo {
    pub nonce: Base64,
    pub previous_block: Base64,
    pub timestamp: u64,
    pub last_retarget: u64,
    #[serde(deserialize_with = "deserialize_string_from_number")]
    pub diff: String,
    pub height: u64,
    pub hash: Base64,
    pub indep_hash: Base64,
    pub txs: Vec<Base64>,
    pub wallet_list: Base64,
    pub reward_addr: Base64,
    pub tags: Vec<Tag>,
    pub reward_pool: u64,
    pub weave_size: u64,
    pub block_size: u64,

    //V2 Stuff
    pub cumulative_diff: Option<String>,
    pub hash_list_merkle: Option<Base64>,

    // V3 stuff
    pub tx_root: Base64,
    pub tx_tree: Vec<Base64>,
    pub poa: ProofOfAccess,
}

#[derive(Deserialize, Debug, Default, Eq, PartialEq)]
pub struct Transaction {
    pub format: u8,
    pub id: String,
    pub last_tx: String,
    pub owner: String,
    pub tags: Vec<Tag>,
    pub target: String,
    pub quantity: String,
    pub data_root: String,
    pub data: String,
    pub data_size: String,
    pub reward: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Tag {
    pub name: Base64,
    pub value: Base64,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionStatus {
    pub block_height: u128,
    pub block_indep_hash: Base64,
    pub number_of_confirmations: u64,
}

#[derive(Serialize, Deserialize, Debug, Default, Eq, PartialEq)]
pub struct Chunk {
    pub data_root: Base64,
    pub data_size: String,
    pub data_path: Base64,
    pub offset: String,
    pub chunk: Base64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct BundleTag {
    pub name: String,
    pub value: String,
}
