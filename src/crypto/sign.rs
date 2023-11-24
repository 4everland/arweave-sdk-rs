//! Functionality for creating and verifying signatures and hashing.

use crate::error::Error;
use jsonwebkey as jwk;
use sha2::Digest;
use std::{fs, path::PathBuf};
use std::str::FromStr;

use super::base64::Base64;
use boring::{
    sign::{Signer, Verifier},
    rsa::{Rsa, Padding},
    pkey::{PKey, Private},
    hash::MessageDigest,
    bn::BigNum,
};

/// Struct for for crypto methods.
pub struct JwkSigner {
    keypair: PKey<Private>,
}

impl JwkSigner {
    fn new(keypair: PKey<Private>) -> Self {
        Self { keypair }
    }

    pub fn from_jwk(jwk: jwk::JsonWebKey) -> Result<Self, Error> {
        let pkey = PKey::private_key_from_pkcs8(&jwk.key.to_der())
            .map_err(|err| Error::KeyParseError(format!("private decode err {}", err)))?;
        Ok( Self::new(pkey))
    }

    pub fn from_keypair_path(keypair_path: PathBuf) -> Result<Self, Error> {
        let data = fs::read_to_string(keypair_path)?;
        let jwk_parsed: jwk::JsonWebKey = data.parse().map_err(Error::JsonWebKeyError)?;

        Self::from_jwk(jwk_parsed)
    }

    pub fn public_key(&self) -> Base64 {
        Base64(self.keypair.rsa().unwrap().n().to_vec())
    }

    pub fn wallet_address(&self) -> Base64 {
        let mut context = sha2::Sha256::new();
        context.update(&self.public_key().0[..]);
        Base64(context.finalize().to_vec())
    }

    pub fn sign(&self, message: &[u8]) -> Result<Base64, Error> {
        let mut signer = Signer::new(MessageDigest::sha256(), &self.keypair)
            .map_err(|err|Error::SigningError(err.to_string()))?;
        signer.set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(|e| Error::SigningError(e.to_string()))?;
        signer.update(message)
            .map_err(|e| Error::SigningError(e.to_string()))?;
        let signature = signer.sign_to_vec()
            .map_err(|e|Error::SigningError(e.to_string()))?;
        Ok(Base64(signature))

    }

    pub fn verify(&self,  message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let mut verify = Verifier::new(MessageDigest::sha256(), &self.keypair).map_err(|_| Error::InvalidSignature).unwrap();
        verify.set_rsa_padding(Padding::PKCS1_PSS).map_err(|_| Error::InvalidSignature).unwrap();
        verify.update(message).map_err(|_| Error::InvalidSignature).unwrap();
        verify.verify(signature).map_err(|_| Error::InvalidSignature).map(|_| ())
    }
}

pub fn verify_with_pub_key_n(n: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {

    let n = BigNum::from_slice(n).map_err(|_| Error::InvalidSignature).unwrap();
    let e = BigNum::from_slice(&Base64::from_str("AQAB").unwrap().0).map_err(|_| Error::InvalidSignature).unwrap();
    let rsa_pub_key = Rsa::from_public_components(n,e)
        .map_err(|_| Error::InvalidSignature).unwrap();

    let pkey = PKey::from_rsa(rsa_pub_key).map_err(|_| Error::InvalidSignature).unwrap();
    let mut verify = Verifier::new(MessageDigest::sha256(), &pkey).map_err(|_| Error::InvalidSignature).unwrap();
    verify.set_rsa_padding(Padding::PKCS1_PSS).map_err(|_| Error::InvalidSignature).unwrap();
    verify.update(message).map_err(|_| Error::InvalidSignature).unwrap();
    verify.verify(signature).map_err(|_| Error::InvalidSignature).map(|_| ())


}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, str::FromStr};

    use crate::{
        crypto::{base64::Base64, sign::JwkSigner},
        error,
    };

    const DEFAULT_WALLET_PATH: &str = "res/test_wallet.json";

    impl Default for JwkSigner {
        fn default() -> Self {
            let path = PathBuf::from_str(DEFAULT_WALLET_PATH).unwrap();
            Self::from_keypair_path(path).expect("Could not create signer")
        }
    }

    #[test]
    fn test_default_keypair() {
        let path = PathBuf::from_str(DEFAULT_WALLET_PATH).unwrap();
        let provider = JwkSigner::from_keypair_path(path).expect("Valid wallet file");
        assert_eq!(
            provider.wallet_address().to_string(),
            "ggHWyKn0I_CTtsyyt2OR85sPYz9OvKLd9DYIvRQ2ET4"
        );
    }

    #[test]
    fn test_sign_verify() -> Result<(), error::Error> {
        let message = Base64(
            [
                74, 15, 74, 255, 248, 205, 47, 229, 107, 195, 69, 76, 215, 249, 34, 186, 197, 31,
                178, 163, 72, 54, 78, 179, 19, 178, 1, 132, 183, 231, 131, 213, 146, 203, 6, 99,
                106, 231, 215, 199, 181, 171, 52, 255, 205, 55, 203, 117,
            ]
            .to_vec(),
        );
        let path = PathBuf::from_str("res/test_wallet.json").expect("Could not open .wallet.json");
        let provider = JwkSigner::from_keypair_path(path)?;
        let signature = provider.sign(&message.0).unwrap();
        let pubk = provider.public_key();
        println!("pubk: {}", &pubk.to_string());
        println!("message: {}", &message.to_string());
        println!("sig: {}", &signature.to_string());

        //TODO: implement verification
        provider.verify(&message.0, &signature.0).expect("verify failed");
        Ok(())
    }
}
