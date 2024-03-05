use crate::crypto::sign::{ArweaveSigner, EthSigner, Signer};

pub struct SignatureMeta {
    pub sig_length: usize,
    pub pub_length: usize,
}

const ARWEAVE_SIGN_CONFIG: (u8, SignatureMeta) = (1, SignatureMeta {
    sig_length: 512,
    pub_length: 512,
});

#[allow(dead_code)]
const ED25519_SIGN_CONFIG: (u8, SignatureMeta) = (2, SignatureMeta {
    sig_length: 64,
    pub_length: 32,
});

const ETHEREUM_SIGN_CONFIG: (u8, SignatureMeta) = (3, SignatureMeta {
    sig_length: 65,
    pub_length: 65,
});

#[allow(dead_code)]
const SOLANA_SIGN_CONFIG: (u8, SignatureMeta) = (4, SignatureMeta {
    sig_length: 64,
    pub_length: 32,
});

pub trait BundleSigner: Signer {
    fn signature_type(&self) -> u8;
    fn signature_meta(&self) -> SignatureMeta;
}

impl BundleSigner for ArweaveSigner {
    fn signature_type(&self) -> u8 {
        ARWEAVE_SIGN_CONFIG.0
    }

    fn signature_meta(&self) -> SignatureMeta {
        ARWEAVE_SIGN_CONFIG.1
    }
}

impl BundleSigner for EthSigner {
    fn signature_type(&self) -> u8 {
        ETHEREUM_SIGN_CONFIG.0
    }

    fn signature_meta(&self) -> SignatureMeta {
        ETHEREUM_SIGN_CONFIG.1
    }
}
