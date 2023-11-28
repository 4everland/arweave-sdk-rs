use std::io::Read;
use crate::bundle::tags::Tags;
use crate::bundle::utils::short_to_2_byte_array;
use crate::crypto::hash::{deep_hash, DeepHashItem, Hasher, ToItems};
use crate::error::Error;
use crate::crypto::base64::Base64;

trait ItemSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
    fn public_key(&self) -> Base64;
}

pub struct BundleItem<T> {
    pub signature_type: i32,
    pub signature: Base64,
    pub owner: Base64,
    pub target: Base64,
    pub anchor: Base64,
    pub tags: Tags,
    pub data: String,
    pub id: Base64,

    // item: Box<dyn Read>, //todo

    signer: T,
}

pub struct DataItemCreateOptions {
    pub target: Base64,
    pub anchor: Base64,
    pub tags: Tags,
}

impl<T: ItemSigner> BundleItem<T> {
    pub fn new<R: Read>(&mut self, s: T, r: R, o: DataItemCreateOptions) {
        self.anchor = o.anchor;
        self.target = o.target;
        self.tags = o.tags;
        self.owner = s.public_key()
        // self.item = r //todo
    }

    fn set_signature(&mut self, s: T) -> Result<(), Error> {
        let h = deep_hash(self.to_deep_hash_item().unwrap());
        let signature = s.sign(h.as_slice()).map_err(|e| Error::SigningError(e.to_string()))?;
        ;
        self.signature = Base64::from(signature.as_slice());
        self.id = Base64::from(signature.as_slice().sha256().as_slice());
        Ok(())
    }

    fn generate_item_meta_binary(&mut self) -> Result<Vec<u8>, Error> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend( short_to_2_byte_array(self.signature_type as u64));
    }
}

impl<'a, T> ToItems<'a, BundleItem<T>> for BundleItem<T> {
    fn to_deep_hash_item(&'a self) -> Result<DeepHashItem, Error> {
        let data: Vec<DeepHashItem> = vec![
            Base64::from_utf8_str("dataitem").unwrap(),
            Base64::from_utf8_str("1").unwrap(),
            Base64::from_utf8_str(self.signature_type.to_string().as_str()).unwrap(),
            self.owner.clone(),
            self.target.clone(),
            self.anchor.clone(),
            Base64::from(&self.tags),
            Base64::from_utf8_str("self").unwrap(),
            // DeepHashItem::Blob(Base64::from_str("dataitem")), //todo
        ].into_iter().map(|op| DeepHashItem::from_item(&op.0)).collect();
        Ok(DeepHashItem::List(data))
    }
}
