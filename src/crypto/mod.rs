pub mod base64;
pub mod hash;
pub mod merkle;
pub mod sign;

#[cfg(test)]
mod tests {
    use crate::crypto::base64::Base64;
    use crate::crypto::sign::{ArweaveSigner, Signer};
    use crate::error::Error;

    const DEFAULT_WALLET_PATH: &str = "res/test_wallet.json";

    impl Default for ArweaveSigner {
        fn default() -> Self {
            Self::from_keypair_path(DEFAULT_WALLET_PATH).expect("Could not create signer")
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

        let _ = s.public_key().unwrap();

        assert!(s.verify(&message.0, &signature));
        Ok(())
    }
}
