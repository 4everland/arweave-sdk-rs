use std::path::PathBuf;

use crate::error::Error;

use self::{
    base64::Base64,
    hash::{deep_hash, DeepHashItem, Hasher},
    sign::JwkSigner,
};

pub mod base64;
pub mod hash;
pub mod merkle;
pub mod sign;
pub mod reader;

pub struct Provider {
    pub signer: Box<JwkSigner>,
}

impl Provider {
    pub fn from_keypair_path(keypair_path: PathBuf) -> Result<Self, Error> {
        let signer = JwkSigner::from_keypair_path(keypair_path)?;
        Ok(Provider::new(Box::new(signer)))
    }

    pub fn new(signer: Box<JwkSigner>) -> Self {
        Provider { signer }
    }
}

impl Provider {
    pub fn deep_hash(&self, deep_hash_item: DeepHashItem) -> [u8; 48] {
        deep_hash(deep_hash_item)
    }

    pub fn sign(&self, message: &[u8]) -> Result<Base64, Error> {
        self.signer.sign(message)
    }

    pub fn hash_sha256(&self, message: &[u8]) -> [u8; 32] {
        message.sha256()
    }

    pub fn keypair_modulus(&self) -> Base64 {
        self.signer.public_key()
    }

    pub fn wallet_address(&self) -> Base64 {
        self.signer.wallet_address()
    }

    pub fn public_key(&self) -> Base64 {
        self.signer.public_key()
    }
}

#[cfg(test)]
mod tests {
    use crate::{crypto::sign::verify_with_pub_key_n, error::Error};

    use super::{base64::Base64, Provider};

    impl Default for Provider {
        fn default() -> Self {
            Self {
                signer: Default::default(),
            }
        }
    }

    #[test]
    fn test_sign_verify() -> Result<(), Error> {
        let message = Base64(
            [
                9, 214, 233, 210, 242, 45, 194, 247, 28, 234, 14, 86, 105, 40, 41, 251, 52, 39,
                236, 214, 54, 13, 53, 254, 179, 53, 220, 205, 129, 37, 244, 142, 230, 32, 209, 103,
                68, 75, 39, 178, 10, 186, 24, 160, 179, 143, 211, 151,
            ]
            .to_vec(),
        );

        let provider = Provider::default();
        let signature = provider.sign(&message.0)?;

        println!("signature: {}", signature.to_string());
        let pubk = provider.public_key();
        assert!(verify_with_pub_key_n(&pubk.0, &message.0, &signature.0).is_ok());
        Ok(())
    }
}
