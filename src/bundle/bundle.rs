use crate::bundle::converter::ByteArrayConverter;
use crate::bundle::item::{BundleItem, BundleStreamFactory};
use crate::bundle::sign::BundleSigner;
use crate::crypto::base64::Base64;
use crate::crypto::sign::Signer;
use crate::error::Error;
use crate::transaction::tags::Tag;
use crate::transaction::transaction::{Transaction, TransactionChunksFactory};
use async_stream::try_stream;
use futures::StreamExt;
use futures_core::Stream;
use std::pin::Pin;

pub struct Bundle<T: Signer + BundleSigner, R> {
    items: Vec<BundleItem<T, R>>,
}

impl<T, R> BundleStreamFactory for Bundle<T, R>
where
    T: Signer + BundleSigner,
    R: BundleStreamFactory,
{
    fn stream(&self) -> Pin<Box<dyn Stream<Item = Result<Vec<u8>, Error>> + '_>> {
        let bundle_stream = try_stream! {
            yield ByteArrayConverter::long_to_32_byte_array(
                self.items.len() as u64
            );
            for item in &self.items {
                yield ByteArrayConverter::long_to_32_byte_array(
                    item.binary_length()? as u64
                );
                yield item.id.0.clone();
            }
            for item in &self.items {
                let mut item_stream = item.binary_stream();
                while let Some(chunk) = item_stream.next().await {
                    yield chunk.unwrap();
                }
                //yield item.get_binary().await.unwrap().as_slice();
            }
        };
        Box::pin(bundle_stream)
    }

    fn length(&self) -> Result<usize, Error> {
        let mut item_length = 0;
        for item in &self.items {
            item_length += item.binary_length()?;
        }
        Ok(item_length)
    }
}

impl<T, R> Bundle<T, R>
where
    T: Signer + BundleSigner,
    R: BundleStreamFactory,
{
    pub fn new(items: Vec<BundleItem<T, R>>) -> Bundle<T, R> {
        return Bundle { items };
    }

    pub async fn to_transaction(
        self,
        s: Box<dyn Signer>,
    ) -> Result<(Transaction, TransactionChunksFactory<Bundle<T, R>>), Error> {
        let mut chunks_creator = TransactionChunksFactory::new(Box::new(self))?;
        let chunks = chunks_creator.hash().await?;
        let transaction = Transaction::new(
            s,
            Default::default(),
            Some(chunks),
            0,
            0,
            Default::default(),
            vec![
                Tag {
                    name: Base64::from_utf8_str("Bundle-Format").unwrap(),
                    value: Base64::from_utf8_str("binary").unwrap(),
                },
                Tag {
                    name: Base64::from_utf8_str("Bundle-Version").unwrap(),
                    value: Base64::from_utf8_str("2.0.0").unwrap(),
                },
            ],
        )?;
        Ok((transaction, chunks_creator))
    }
}
