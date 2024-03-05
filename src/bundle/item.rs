use crate::bundle::converter::ByteArrayConverter;
use crate::bundle::sign::BundleSigner;
use crate::bundle::tags::Tags;
use crate::crypto::base64::Base64;
use crate::crypto::hash::{deep_hash, DeepHashItem, Hasher};
use crate::error::Error;
use async_stream::try_stream;
use futures::StreamExt;
use futures_core::Stream;
use sha2::Digest;
use sha2::Sha384;
use std::pin::Pin;

pub trait BundleStreamFactory {
    fn stream(&self) -> Pin<Box<dyn Stream<Item = Result<Vec<u8>, Error>> + '_>>;
    fn length(&self) -> Result<usize, Error>;
    fn is_empty(&self) -> bool {
        self.length().unwrap() > 0
    }
}

impl BundleStreamFactory for Vec<u8> {
    fn stream(&self) -> Pin<Box<dyn Stream<Item = Result<Vec<u8>, Error>> + '_>> {
        Box::pin(try_stream! {
            yield self.clone();
        })
    }

    fn length(&self) -> Result<usize, Error> {
        Ok(self.len())
    }
}

pub struct BundleItem<R> {
    pub signature_type: u8,
    pub signature: Base64,
    pub owner: Base64,
    pub target: Base64,
    pub anchor: Base64,
    pub tags: Tags,
    pub id: Base64,
    item: R,
    length: usize,
}

pub struct DataItemCreateOptions {
    pub target: Base64,
    pub anchor: Base64,
    pub tags: Tags,
    pub signer: Option<Box<dyn BundleSigner>>,
}

impl<R> BundleItem<R>
where
    R: BundleStreamFactory,
{
    pub async fn new(r: R, o: DataItemCreateOptions) -> Result<BundleItem<R>, Error> {
        let l = r.length().unwrap();

        let mut item = BundleItem {
            signature_type: 0,
            signature: Default::default(),
            owner: Default::default(),
            target: Default::default(),
            anchor: Default::default(),
            tags: o.tags,
            id: Default::default(),
            item: r,
            length: l,
        };

        match o.signer {
            Some(signer) => {
                item.signature(signer)
                    .await
                    .map_err(|e| Error::SigningError(e.to_string()))?;
                Ok(item)
            }
            None => Ok(item),
        }
    }

    async fn signature(&mut self, signer: Box<dyn BundleSigner>) -> Result<(), Error> {
        self.owner = signer.public_key().unwrap();
        self.signature_type = signer.signature_type();
        let h = deep_hash(self.to_deep_hash_item().await.unwrap());
        let signature = signer
            .sign(h.as_slice())
            .map_err(|e| Error::SigningError(e.to_string()))?;

        self.signature = Base64::from(signature.as_slice());
        self.id = Base64::from(signature.as_slice().sha256().as_slice());
        Ok(())
    }

    async fn to_deep_hash_item(&mut self) -> Result<DeepHashItem, Error> {
        let mut data: Vec<DeepHashItem> = vec![
            Base64::from_utf8_str("dataitem").unwrap(),
            Base64::from_utf8_str("1").unwrap(),
            Base64::from_utf8_str(self.signature_type.to_string().as_str()).unwrap(),
            self.owner.clone(),
            self.target.clone(),
            self.anchor.clone(),
            Base64::from(&self.tags),
        ]
        .into_iter()
        .map(|op| DeepHashItem::from_item(&op.0))
        .collect();
        data.push(DeepHashItem::Origin(self.item_hash().await.unwrap()));
        Ok(DeepHashItem::from_children(data))
    }

    async fn item_hash(&mut self) -> Result<[u8; 48], Error> {
        let blob_tag = format!("blob{}", self.length);

        let mut context = Sha384::new();
        let mut stream = self.item.stream();
        while let Some(readed) = stream.next().await {
            context.update(&readed.unwrap()[..]);
        }
        let result = context.finalize();
        Ok([&blob_tag.as_bytes().sha384(), &result[..]]
            .concat()
            .as_slice()
            .sha384())
    }

    pub fn binary_length(&self) -> Result<usize, Error> {
        let data_length = self.length;

        Ok(2 + self.signature.0.len()
            + self.owner.0.len()
            + 1
            + self.target.0.len()
            + 1
            + self.anchor.0.len()
            + 16
            + Base64::from(&self.tags).0.len()
            + data_length)
    }

    pub fn binary_stream(&self) -> Pin<Box<dyn Stream<Item = Result<Vec<u8>, Error>> + '_>> {
        Box::pin(try_stream! {
           if self.signature.is_empty() {
               Err(Error::SigningError("signature is empty".to_string()))?;
           }

            yield ByteArrayConverter::short_to_2_byte_array(self.signature_type as u64);
            yield self.signature.0.clone();
            yield self.owner.0.clone();
            yield [!self.target.is_empty() as u8].to_vec();
            if !self.target.is_empty() {
               if self.target.0.len() != 32 {
                   Err(Error::SigningError("target is not 32 bytes".to_string()))?;
               }
                yield self.target.0.clone();
            }
            yield [!self.anchor.is_empty() as u8].to_vec();
            if !self.anchor.is_empty() {
               if self.anchor.0.len() != 32 {
                   Err(Error::SigningError("target is not 32 bytes".to_string()))?;
               }
                yield self.anchor.0.clone();
            }

            yield ByteArrayConverter::long_to_8_byte_array(self.tags.tags.len() as u64);

            let tags = Base64::from(&self.tags).0;
            yield ByteArrayConverter::long_to_8_byte_array(tags.len() as u64);
            if !self.tags.tags.is_empty() {
                yield tags;
            }
            let mut stream = self.item.stream();
            while let Some(readed) = stream.next().await{
                yield readed.unwrap().to_vec();
            }
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate jsonwebkey as jwk;

    use crate::bundle::item::{BundleItem, DataItemCreateOptions};
    use crate::bundle::sign::BundleSigner;
    use crate::bundle::tags::Tags;
    use crate::crypto::base64::Base64;
    use crate::crypto::sign;
    use crate::crypto::sign::{EthSigner, Signer};
    use crate::types::BundleTag;
    use futures::StreamExt;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_bundle_item_create() {
        let signer =
            sign::ArweaveSigner::from_keypair_path(&"tests/fixtures/arweave_wallet.json").unwrap();
        let bundle_signer: Box<dyn BundleSigner> = Box::new(signer.clone());
        let create_options = DataItemCreateOptions {
            target: Base64::default(),
            anchor: Base64::default(),
            tags: Tags {
                tags: vec![BundleTag {
                    name: "Content-Type".to_string(),
                    value: "application/octet-stream".to_string(),
                }],
            },
            signer: Some(bundle_signer),
        };

        let item = BundleItem::new(PathBuf::from("tests/fixtures/1mb.bin"), create_options)
            .await
            .unwrap();

        let mut stream = item.binary_stream();
        let mut b = vec![];
        while let Some(r) = stream.next().await {
            b.extend(r.unwrap())
        }

        assert!(signer.verify(b.as_slice(), &item.signature.0))
    }

    #[tokio::test]
    async fn test_bundle_item_create_2() {
        let signer = EthSigner::from_prv_hex(
            std::fs::read_to_string(PathBuf::from("tests/fixtures/secp256k1.hex"))
                .unwrap()
                .as_str(),
        )
        .unwrap();
        let s: Box<dyn BundleSigner> = Box::new(signer);
        let create_options = DataItemCreateOptions {
            target: Base64::default(),
            anchor: Base64::default(),
            tags: Tags {
                tags: vec![
                    BundleTag {
                        name: "Content-Type".to_string(),
                        value: "application/txt".to_string(),
                    },
                    BundleTag {
                        name: "App-Version".to_string(),
                        value: "2.0.0".to_string(),
                    },
                ],
            },
            signer: None,
        };

        let mut item = BundleItem::new(
            PathBuf::from("tests/fixtures/bundle_item_1"),
            create_options,
        )
        .await
        .unwrap();
        item.signature(s).await.unwrap();

        assert_eq!(
            "NIfFknqcXO9zbfuh7xV3KnzvHTIuRAof104pEYR5iGQ",
            item.id.to_string()
        );
    }
}
