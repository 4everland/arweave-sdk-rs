use sha2::Digest;

use crate::error::Error;

pub trait Hasher<'a, T> {
    fn sha256(&self) -> [u8; 32];

    fn sha384(&self) -> [u8; 48];
}

impl Hasher<'_, &[u8]> for &[u8] {
    fn sha256(&self) -> [u8; 32] {
        let mut context = sha2::Sha256::new();
        context.update(self);
        let mut result: [u8; 32] = [0; 32];
        result.copy_from_slice(context.finalize().as_ref());
        result
    }

    fn sha384(&self) -> [u8; 48] {
        let mut context = sha2::Sha384::new();
        context.update(self);
        let mut result: [u8; 48] = [0; 48];
        result.copy_from_slice(context.finalize().as_ref());
        result
    }
}

impl<const N: usize> Hasher<'_, &[u8; N]> for &[u8; N] {
    fn sha256(&self) -> [u8; 32] {
        self.as_slice().sha256()
    }

    fn sha384(&self) -> [u8; 48] {
        self.as_slice().sha384()
    }
}

impl<const N: usize> Hasher<'_, Vec<&[u8; N]>> for Vec<&[u8; N]> {
    fn sha256(&self) -> [u8; 32] {
        let hash: Vec<u8> = self
            .into_iter()
            .flat_map(|&u| u.as_slice().sha256())
            .collect();
        hash.as_slice().sha256()
    }

    fn sha384(&self) -> [u8; 48] {
        let hash: Vec<u8> = self
            .into_iter()
            .flat_map(|&u| u.as_slice().sha384())
            .collect();
        hash.as_slice().sha384()
    }
}

impl Hasher<'_, Vec<&[u8]>> for Vec<&[u8]> {
    fn sha256(&self) -> [u8; 32] {
        let hash: Vec<u8> = self.into_iter().flat_map(|&u| u.sha256()).collect();
        hash.as_slice().sha256()
    }

    fn sha384(&self) -> [u8; 48] {
        let hash: Vec<u8> = self.into_iter().flat_map(|&u| u.sha384()).collect();
        hash.as_slice().sha384()
    }
}

#[derive(Debug)]
pub enum DeepHashItem {
    Blob(Vec<u8>),
    List(Vec<DeepHashItem>),
    Origin([u8; 48]),
    // Read(Box<dyn  TransactionReader>)
}

impl DeepHashItem {
    pub fn from_item(item: &[u8]) -> DeepHashItem {
        Self::Blob(item.to_vec())
    }
    pub fn from_children(children: Vec<DeepHashItem>) -> DeepHashItem {
        Self::List(children)
    }
}

pub trait ToItems<'a, T> {
    fn to_deep_hash_item(&'a self) -> Result<DeepHashItem, Error>;
}

/// Calculates data root of transaction in accordance with implementation in [arweave-js](https://github.com/ArweaveTeam/arweave-js/blob/master/src/common/lib/deepHash.ts).
/// [`DeepHashItem`] is a recursive Enum that allows the function to be applied to
/// nested [`Vec<u8>`] of arbitrary depth.
pub fn deep_hash(deep_hash_item: DeepHashItem) -> [u8; 48] {
    let hash = match deep_hash_item {
        DeepHashItem::Origin(o) => o,
        DeepHashItem::Blob(blob) => {
            let blob_tag = format!("blob{}", blob.len());
            (vec![blob_tag.as_bytes(), &blob]).sha384()
        }
        DeepHashItem::List(list) => {
            let list_tag = format!("list{}", list.len());
            let mut hash = list_tag.as_bytes().sha384();

            for child in list.into_iter() {
                let child_hash = deep_hash(child);
                hash = [hash, child_hash].concat().as_slice().sha384();
            }
            hash
        }
    };
    hash
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

    use crate::{
        crypto::hash::{deep_hash, ToItems},
        error::Error,
        transaction::transaction::Transaction,
    };

    #[tokio::test]
    async fn test_deep_hash() -> Result<(), Error> {
        let mut file = File::open("res/sample_tx.json").unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();

        let tx: Transaction = data.as_str().try_into()?;

        let actual_hash = deep_hash(tx.to_deep_hash_item().unwrap());

        let correct_hash: [u8; 48] = [
            39, 16, 175, 205, 64, 3, 182, 248, 240, 38, 169, 233, 4, 140, 97, 83, 148, 224, 29,
            119, 70, 146, 76, 254, 217, 238, 208, 164, 251, 217, 161, 48, 47, 132, 144, 116, 27,
            246, 32, 205, 17, 227, 169, 8, 39, 205, 27, 78,
        ];
        assert_eq!(actual_hash, correct_hash);

        Ok(())
    }
}
