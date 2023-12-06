//! Functionality for creating and verifying signatures and hashing.
use crate::error::Error;
use jsonwebkey as jwk;
use sha2::Digest;
use std::{fs, path::PathBuf};
use std::str::FromStr;
use bip39::Language::English;

use super::base64::Base64;
use boring::{
    sign::{Signer as BoringSigner, Verifier},
    rsa::{Rsa, Padding},
    pkey::{PKey, Private},
    hash::MessageDigest,
    bn::BigNum,
};

use sha3::{Digest as _,  Keccak256};

pub trait Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
    fn public_key(&self) -> Result<Base64, Error>;
    fn wallet_address(&self) -> String;

}
/// Struct for for crypto methods.
pub struct ArweaveSigner {
    keypair: Option<PKey<Private>>,
    n: Vec<u8>,

}

pub struct EthSigner {
    key: Option<libsecp256k1::SecretKey>,
    address: [u8; 20],
}
impl Signer for EthSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {

        match &self.key {
            Some(key) => {
                let message_len = message.len().to_string();
                let mut hasher = Keccak256::new();
                let mut eth_message = vec![];
                eth_message.push("\x19Ethereum Signed Message:\n".as_bytes());
                eth_message.push(message_len.as_bytes());
                eth_message.push(&message);
                let i = eth_message.concat();
                hasher.update(i.as_slice());
                let result = hasher.finalize();

                let result = &result[..];
                let msg = libsecp256k1::Message::parse_slice(result).map_err(|err|Error::SigningError(err.to_string()))?;

                let (sig, rec_id) = libsecp256k1::sign(&msg, key);

                let mut r = [0u8; 65];
                r[64] = rec_id.serialize() + 27;
                sig.r.fill_b32((&mut r[0..32]).try_into().unwrap());
                sig.s.fill_b32((&mut r[32..64]).try_into().unwrap());
                Ok(r.to_vec())
            }
            _ => {
                Err(Error::InvalidKeyError)
            }
        }

    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match self.verify_result(message, signature) {
            Ok(_) => true,
            Err(_) => false
        }
    }

    fn public_key(&self) -> Result<Base64, Error> {
        let key = match &self.key {
            Some(k) => k,
            _ => { return Err(Error::InvalidKeyError) }
        };

        let pub_key = libsecp256k1::PublicKey::from_secret_key(&key);
        Ok(Base64::from(pub_key.serialize().as_slice()))
    }

    fn wallet_address(&self) -> String {
        format!("{}", ethaddr::Address::from_slice(&self.address))
    }
}

impl EthSigner {
    fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<EthSigner, Error> {
        let seed = bip39::Mnemonic::parse_in_normalized(English, mnemonic).map_err(|_| Error::MnemonicDecodeError)?;
        let pri_key = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Bitcoin, seed.to_seed(passphrase).as_ref()).map_err(|_| Error::MnemonicDecodeError)?;
        let x = pri_key.private_key;

        let key = libsecp256k1::SecretKey::parse_slice(x.secret_bytes().as_slice()).map_err(|_|Error::InvalidKeyError)?;
        let pub_key = libsecp256k1::PublicKey::from_secret_key(&key);

        let mut address = [0u8; 20];
        let mut hasher = Keccak256::new();
        hasher.update(&pub_key.serialize()[1..]);
        let result = hasher.finalize();
        address.copy_from_slice(&result[12..]);

        Ok(Self {
            key: Some(key),
            address,
        })
    }

    fn from_prv_hex(prv: &str) -> Result<EthSigner, Error> {
        let decode_key = hex::decode(prv).map_err(|_|Error::InvalidKeyError)?;

        let key = libsecp256k1::SecretKey::parse_slice(decode_key.as_slice()).map_err(|_|Error::InvalidKeyError)?;
        let pub_key = libsecp256k1::PublicKey::from_secret_key(&key);

        let mut address = [0u8; 20];
        let mut hasher = Keccak256::new();
        hasher.update(&pub_key.serialize()[1..]);
        let result = hasher.finalize();
        address.copy_from_slice(&result[12..]);

        Ok(Self {
            key: Some(key),
            address,
        })
    }

    fn from_address(addr: &str) -> Result<EthSigner, Error> {
        let addr = ethaddr::Address::from_str_checksum(addr).map_err(|_| Error::AddressDecodeError)?;
        Ok(Self {
            key: None,
            address: addr.0,
        })
    }

    fn from_pubkey(key: &[u8]) -> Result<EthSigner, Error> {
        let key = libsecp256k1::PublicKey::parse_slice(key, None).map_err(|_| Error::AddressDecodeError)?;
        let mut address = [0u8; 20];
        let mut hasher = Keccak256::new();
        hasher.update(&key.serialize()[1..]);
        let result = hasher.finalize();
        address.copy_from_slice(&result[12..]);

        Ok(Self {
            key: None,
            address,
        })
    }

    fn verify_result(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        if signature.len() != 65 {
            return Err(Error::InvalidSignature)
        }

        let rec_id = libsecp256k1::RecoveryId::parse(signature[0]).map_err(|_|Error::InvalidSignature)?;
        let sig = libsecp256k1::Signature::parse_standard_slice(&signature[1..]).map_err(|_|Error::InvalidSignature)?;
        let msg = libsecp256k1::Message::parse_slice(&message).map_err(|_|Error::InvalidSignature)?;
        let pubkey = libsecp256k1::recover(&msg, &sig, &rec_id).map_err(|_|Error::InvalidSignature)?;
        let mut address = [0u8; 20];

        let mut hasher = Keccak256::new();
        hasher.update(&pubkey.serialize()[1..]);
        let result = hasher.finalize();
        address.copy_from_slice(&result[12..]);
        if address.eq(&self.address) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

impl Signer for ArweaveSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let keypair = match &self.keypair {
            Some(k) => k,
            _ => {return Err(Error::InvalidKeyError)}
        };
        let mut signer = BoringSigner::new(MessageDigest::sha256(), keypair)
            .map_err(|err|Error::SigningError(err.to_string()))?;
        signer.set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(|e| Error::SigningError(e.to_string()))?;
        signer.update(message)
            .map_err(|e| Error::SigningError(e.to_string()))?;
        let signature = signer.sign_to_vec()
            .map_err(|e|Error::SigningError(e.to_string()))?;
        Ok(signature)
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match self.verify_result(message, signature) {
            Ok(_) => true,
            Err(_) => false
        }
    }

    fn public_key(&self) -> Result<Base64, Error> {

        let key = match &self.keypair {
            Some(k) => k,
            _ => { return Ok(Base64::from(self.n.as_slice())) }
        };
        let key = key.rsa().map_err(|_| Error::InvalidKeyError).unwrap();
        Ok(Base64(key.n().to_vec()))
    }

    fn wallet_address(&self) -> String {
        let key = self.public_key().unwrap();
        let mut context = sha2::Sha256::new();
        context.update(&key.0[..]);
        Base64(context.finalize().to_vec()).to_string()
    }
}
impl ArweaveSigner {
    fn new(keypair: PKey<Private>) -> Self {
        Self { keypair: Some(keypair.clone()), n: keypair.rsa().unwrap().n().to_vec() }
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

    pub fn from_owner(owner: Base64) -> Result<Self, Error> {
        Ok(Self { keypair: None, n: owner.0.to_vec() })
    }

    pub fn wallet_address(&self) -> Base64 {
        let key = self.public_key().unwrap();
        let mut context = sha2::Sha256::new();
        context.update(&key.0[..]);
        Base64(context.finalize().to_vec())
    }

    fn verify_result(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {

        let n = match &self.keypair {
            Some(key) => {
                key.rsa().unwrap().n().to_vec()
            }
            _ => {
                self.n.to_vec()
            }
        };

        let pkey = PKey::from_rsa(Rsa::from_public_components(
            BigNum::from_slice(&n).map_err(|_| Error::InvalidSignature).unwrap(),
            BigNum::from_slice(&Base64::from_str("AQAB").unwrap().0).map_err(|_| Error::InvalidSignature).unwrap()
                ).map_err(|_| Error::InvalidSignature).unwrap())
            .map_err(|_| Error::InvalidSignature).unwrap();

        let mut verify = Verifier::new(MessageDigest::sha256(), &pkey).map_err(|_| Error::InvalidSignature).unwrap();
        verify.set_rsa_padding(Padding::PKCS1_PSS).map_err(|_| Error::InvalidSignature).unwrap();
        verify.update(message).map_err(|_| Error::InvalidSignature).unwrap();
        verify.verify(signature).map_err(|_| Error::InvalidSignature).map(|_| ())
    }

}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, str::FromStr};

    use crate::{
        crypto::{base64::Base64, sign::ArweaveSigner, sign::Signer},
        error,
    };
    use crate::crypto::sign::EthSigner;
    use crate::error::Error;

    const DEFAULT_WALLET_PATH: &str = "res/test_wallet.json";

    const TEST_BUNDLER_FILE: &str = "res/test_bundle.json";


    #[test]
    fn test_default_keypair() {
        let path = PathBuf::from_str(DEFAULT_WALLET_PATH).unwrap();
        let provider = ArweaveSigner::from_keypair_path(path).expect("Valid wallet file");
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
        let provider = ArweaveSigner::from_keypair_path(path)?;
        let signature = provider.sign(&message.0).unwrap();
        let pubk = provider.public_key();

        //TODO: implement verification
        assert_eq!(provider.verify(&message.0, &signature), true);
        Ok(())
    }

    #[test]
    fn test_eth_signer() -> Result<(), error::Error> {

        let signer = EthSigner::from_prv_hex("1f534ac18009182c07d266fe4a7903c0bcc8a66190f0967b719b2b3974a69c2f")?;
        println!("{}", signer.wallet_address());

        let signer_owner = signer.public_key()?;

        println!("{}", signer_owner);
        Ok(())

    }

    #[test]
    fn test_eth_pub_key() -> Result<(), error::Error> {
        let decode_key = hex::decode("02D0E95DEE9217777132128ACA9CE7191EA391ACCB83FF47B5C984D8823FAD331E").map_err(|_| {
            Error::InvalidKeyError
        })?;
        let signer = EthSigner::from_pubkey(decode_key.as_slice())?;
        assert_eq!(signer.wallet_address(), "0x02A71bA6943D302c0152cdb237CB606ffE1C9BC4");
        Ok(())

    }

    #[test]
    fn test_eth_verify() -> Result<(), error::Error> {
        let message = Base64::from_str("MFNXFMKDurrmwEZYoH99MVPg9pLodCgz5moTcBq2xtVrP1RQDgYit5WQgJ8h42BU").unwrap();

        let signer = EthSigner::from_prv_hex("1f534ac18009182c07d266fe4a7903c0bcc8a66190f0967b719b2b3974a69c2f")?;
        let res = signer.sign(&message.0)?;
        let sig_str = Base64::from(res.as_slice()).to_string();

        assert_eq!("GqZprDMkQ7ULQwsXJz3PL2FTqEu5Lok3fC77-HZAzXU27ZN8RABV_E8otYK4qQyVV6LEx_ko7dpY_CSu-v8mBhw", sig_str);
        Ok(())

    }

}
