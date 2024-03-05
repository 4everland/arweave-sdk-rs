use futures::StreamExt;

use tokio::task;
use tokio::sync::mpsc;

use crate::error::Error;
use crate::bundle::bundle::Bundle;
use crate::bundle::item::BundleStreamFactory;
use crate::client::client::Client;
use crate::transaction::transaction::{Transaction, TransactionChunksFactory};

pub struct Uploader {
    client: Client,
}

impl Default for Uploader {
    fn default() -> Self {
        Self { client: Client::default() }
    }
}

#[allow(dead_code)]
impl Uploader
{
    pub fn new(client: Client) -> Self {
        Uploader { client }
    }

    pub async fn submit<R>(&self, transaction: Transaction, mut chunks_creator: TransactionChunksFactory<Bundle<R>>, concurrent_limit: usize) -> Result<(), Error>
        where
            R: BundleStreamFactory
    {
        self.client.submit_transaction(transaction).await?;

        let (tx, mut rx) = mpsc::channel(concurrent_limit);
        let mut sc = 0;
        let mut rc = 0;
        let mut iter = chunks_creator.iterator();
        while let Some(value) = iter.next().await {
            let v = value.unwrap();
            sc += 1;
            let t = tx.clone();
            let c  = self.client.clone();
            task::spawn(async move {
                t.send(c.upload_chunk(&v).await).await.unwrap()
            });
            if sc == concurrent_limit {
                break;
            }
        }

        while let Some(r) = rx.recv().await {
            r?;
            rc += 1;
            if let Some(value) = iter.next().await {
                sc += 1;
                let v = value.unwrap();
                let t = tx.clone();
                let c  = self.client.clone();
                task::spawn(async move {
                    t.send(c.upload_chunk(&v).await).await.unwrap()
                });
            }

            if sc == rc {
                break
            }
        };

        Ok(())
    }
}
