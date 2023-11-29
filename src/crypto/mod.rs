use std::path::PathBuf;
use crate::error::Error;

use self::{
    base64::Base64,
    hash::{deep_hash, DeepHashItem, Hasher},
    sign::ArweaveSigner,
    sign::Signer,
};

pub mod base64;
pub mod hash;
pub mod merkle;
pub mod sign;
pub mod reader;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::str::FromStr;
    use crate::error::Error;
    use crate::crypto::base64::Base64;
    use crate::crypto::sign::{ArweaveSigner, Signer};

    const DEFAULT_WALLET_PATH: &str = "res/test_wallet.json";

    impl Default for ArweaveSigner {
        fn default() -> Self {
            let path = PathBuf::from_str(DEFAULT_WALLET_PATH).unwrap();
            Self::from_keypair_path(path).expect("Could not create signer")
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

        let s = ArweaveSigner::default();
        let signature = s.sign(&message.0)?;

        let pubk = s.public_key().unwrap();

        assert!(s.verify(&message.0, &signature));
        Ok(())
    }
}
