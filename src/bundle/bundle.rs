use crate::bundle::converter::ByteArrayConverter;
use crate::bundle::item::{BundleItem, BundleStreamFactory};
use crate::client::client::Client;
use crate::crypto::base64::Base64;
use crate::crypto::sign::Signer;
use crate::error::Error;
use crate::transaction::tags::Tag;
use crate::transaction::transaction::{Transaction, TransactionChunksFactory};
use async_stream::try_stream;
use futures::StreamExt;
use futures_core::Stream;
use std::cmp::min;
use std::path::PathBuf;
use std::pin::Pin;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

pub struct Bundle<R> {
    items: Vec<BundleItem<R>>,
}

impl<R> BundleStreamFactory for Bundle<R>
where
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
            }
        };
        Box::pin(bundle_stream)
    }

    fn length(&self) -> Result<usize, Error> {
        let mut item_length = 32 + self.items.len() * 32;

        for item in &self.items {
            item_length += item.id.0.len();
            item_length += item.binary_length()?;
        }
        Ok(item_length)
    }
}

impl<R> Bundle<R>
where
    R: BundleStreamFactory,
{
    pub fn new(items: Vec<BundleItem<R>>) -> Bundle<R> {
        Bundle { items }
    }

    pub async fn to_transaction(
        self,
        s: Box<dyn Signer>,
        tags: Vec<Tag<Base64>>,
        c: Client,
    ) -> Result<(Transaction, TransactionChunksFactory<Bundle<R>>), Error> {
        let bundle_tags = vec![
            Tag {
                name: Base64::from_utf8_str("Bundle-Format").unwrap(),
                value: Base64::from_utf8_str("binary").unwrap(),
            },
            Tag {
                name: Base64::from_utf8_str("Bundle-Version").unwrap(),
                value: Base64::from_utf8_str("2.0.0").unwrap(),
            },
        ]
        .into_iter()
        .chain(tags)
        .collect();

        let length = self.length().unwrap();
        let mut chunks_creator = TransactionChunksFactory::new(Box::new(self))?;
        let chunks = chunks_creator.hash().await?;

        let fee = c.get_fee(length, Base64::empty()).await?;
        let last_tx = c.get_transaction_anchor().await?;
        let transaction = Transaction::new(
            s,
            Default::default(),
            Some(chunks),
            0,
            fee,
            last_tx,
            bundle_tags,
        )?;
        Ok((transaction, chunks_creator))
    }
}

impl BundleStreamFactory for PathBuf {
    fn stream(&self) -> Pin<Box<dyn Stream<Item = Result<Vec<u8>, Error>> + '_>> {
        Box::pin(try_stream! {
             let mut f = File::open(self).await?;
        let mut length = self.length().unwrap();
            while length > 0 {
                let mut buffer = vec![0; min(1024, length)];
                length -= f.read(&mut buffer).await?;
                yield buffer;
            }
        })
    }

    fn length(&self) -> Result<usize, Error> {
        let f = std::fs::File::open(self).unwrap();
        Ok(f.metadata().unwrap().len() as usize)
    }
}
