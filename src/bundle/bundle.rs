use std::fs::File;
use crate::bundle::converter::ByteArrayConverter;
use crate::bundle::item::BundleItem;
use crate::bundle::sign::BundleSigner;
use crate::crypto::base64::Base64;
use crate::crypto::reader::TransactionReader;
use crate::crypto::sign::Signer;
use crate::error::Error;
use crate::transaction::tags::Tag;
use crate::transaction::transaction::Transaction;

pub struct Bundle<T: Signer + BundleSigner> {
    items: Vec<BundleItem<T>>,
    binary: Box<dyn TransactionReader>,
}

impl<T: Signer + BundleSigner> Bundle<T> {
    pub fn new(items: Vec<BundleItem<T>>) -> Bundle<T> {
        return Bundle {
            items,
            binary: Box::new(Vec::new()),
        };
    }

    //todo reader
    pub async fn to_transaction(self, s: Box<dyn Signer>) -> Result<Transaction<T>, Error> {
        let headers = vec![0u8; 64 * self.items.len()];
        let mut binaries: Vec<u8> = vec![];
        for (i, mut item) in self.items.iter().enumerate() {
            let mut header = vec![0u8; 64];
            header[..32].copy_from_slice(&ByteArrayConverter::long_to_32_byte_array(item.binary_length() as u64));
            header[32..].copy_from_slice(&item.id.0);
            headers[64 * i..(64 * i) + 64].copy_from_slice(&header);
            binaries.extend_from_slice(item.get_binary().await.unwrap().as_slice())
        }

        let mut buffer = Vec::with_capacity(4 + headers.len() + binaries.len());
        buffer.extend_from_slice(&ByteArrayConverter::long_to_32_byte_array(self.items.len() as u64));
        buffer.extend_from_slice(&headers);
        buffer.extend_from_slice(&binaries);
        Transaction::new(s, Default::default(), binaries, 0, 0, Default::default(), vec![Tag {
            name: Base64::from_utf8_str("Bundle-Format").unwrap(),
            value: Base64::from_utf8_str("binary").unwrap(),
        }, Tag {
            name: Base64::from_utf8_str("Bundle-Version").unwrap(),
            value: Base64::from_utf8_str("2.0.0").unwrap(),
        }])
    }
}
