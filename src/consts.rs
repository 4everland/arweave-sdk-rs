pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const ARWEAVE_BASE_URL: &str = "https://arweave.net/";

/// Block size used for pricing calculations = 256 KB
pub const BLOCK_SIZE: u64 = 1024 * 256;

/// Maximum data size to send to `tx/` endpoint. Sent to `chunk/` endpoint above this.
pub const MAX_TX_DATA: u64 = 10_000_000;

/// Multiplier applied to the buffer argument from the cli to determine the maximum number
/// of simultaneous request to the `chunk/ endpoint`.
pub const CHUNKS_BUFFER_FACTOR: usize = 20;

/// Number of times to retry posting chunks if not successful.
pub const CHUNKS_RETRIES: u16 = 10;

/// Number of seconds to wait between retying to post a failed chunk.
pub const CHUNKS_RETRY_SLEEP: u64 = 1;

// First block to use V2 block format
pub const V2_BLOCK_HEIGHT: u32 = 269510;

// First block to use V3 block format
pub const V3_BLOCK_HEIGHT: u32 = 422250;

/// Winstons are a sub unit of the native Arweave network token, AR. There are 10<sup>12</sup> Winstons per AR.
pub const WINSTONS_PER_AR: u64 = 1_000_000_000_000;

pub struct SigMeta {
    pub sig_length: usize,
    pub pub_length: usize,
}

const ARWEAVE_SIGN_TYPE: i32 = 1;
const ED25519_SIGN_TYPE: i32 = 2;
const ETHEREUM_SIGN_TYPE: i32 = 3;
const SOLANA_SIGN_TYPE: i32 = 4;

pub const SIG_CONFIG_MAP: [(i32, SigMeta); 4] = [
    (ARWEAVE_SIGN_TYPE, SigMeta {
        sig_length: 512,
        pub_length: 512,
    }),
    (ED25519_SIGN_TYPE, SigMeta {
        sig_length: 64,
        pub_length: 32,
    }),
    (ETHEREUM_SIGN_TYPE, SigMeta {
        sig_length: 65,
        pub_length: 65,
    }),
    (SOLANA_SIGN_TYPE, SigMeta {
        sig_length: 64,
        pub_length: 32,
    }),
];
