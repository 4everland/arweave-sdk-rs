use crate::consts::ARWEAVE_BASE_URL;
use crate::crypto::base64::Base64;
use crate::error::Error;
use crate::error::Error::ReqwestError;
use crate::transaction::transaction::Transaction;
use crate::types::Chunk;
use backoff::future::retry;
use backoff::{ExponentialBackoff, ExponentialBackoffBuilder};
use reqwest::StatusCode;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Client {
    client: reqwest::Client,
    base_url: url::Url,
    retry_strategy: ExponentialBackoff,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: url::Url::from_str(ARWEAVE_BASE_URL).unwrap(),
            retry_strategy: ExponentialBackoffBuilder::default()
                .with_max_elapsed_time(Some(Duration::from_secs(5)))
                .build(),
        }
    }
}

#[allow(dead_code)]
impl Client {
    pub fn new(
        client: reqwest::Client,
        base_url: url::Url,
        retry_strategy: ExponentialBackoff,
    ) -> Result<Self, Error> {
        Ok(Self {
            client,
            base_url,
            retry_strategy,
        })
    }

    pub async fn submit_transaction(&self, transaction: Transaction) -> Result<String, Error> {
        let resp = retry(self.retry_strategy.clone(), || async {
            Ok(self
                .client
                .post(self.base_url.join("tx").map_err(Error::UrlParseError)?)
                .json(&transaction)
                .send()
                .await
                .map_err(|e| ReqwestError(e))?)
        })
        .await
        .unwrap();

        match resp.status() {
            StatusCode::OK => Ok(resp.text().await.map_err(|e| ReqwestError(e))?),
            _ => Err(Error::ArweaveGatewayError(
                resp.status().to_string(),
                resp.text().await.unwrap(),
            )),
        }
    }

    pub async fn upload_chunk(&self, chunk: &Chunk) -> Result<usize, Error> {
        let resp = retry(self.retry_strategy.clone(), || async {
            Ok(self
                .client
                .post(self.base_url.join("chunk").map_err(Error::UrlParseError)?)
                .json(&chunk)
                .send()
                .await
                .map_err(|e| ReqwestError(e))?)
        })
        .await
        .unwrap();

        match resp.status() {
            StatusCode::OK => Ok(chunk.offset.parse().unwrap()),
            _ => Err(Error::ArweaveGatewayError(
                resp.status().to_string(),
                resp.text().await.unwrap(),
            )),
        }
    }

    pub async fn get_fee(&self, size: usize, target: Base64) -> Result<u64, Error> {
        let mut url = self
            .base_url
            .join(&format!("price/{}", size))
            .map_err(Error::UrlParseError)?;

        if !target.is_empty() {
            url = url
                .join(&format!("/{}", target.to_string()))
                .map_err(Error::UrlParseError)?;
        }

        retry(self.retry_strategy.clone(), || async {
            Ok(self
                .client
                .get(url.clone())
                .send()
                .await
                .map_err(|e| Error::GetPriceError(e.to_string()))
                .unwrap()
                .json::<u64>()
                .await
                .map_err(|e| ReqwestError(e))?)
        })
        .await
    }

    pub async fn get_transaction_anchor(&self) -> Result<Base64, Error> {
        let u = self
            .base_url
            .join("tx_anchor")
            .map_err(Error::UrlParseError)?;

        let s = retry(self.retry_strategy.clone(), || async {
            let c = self
                .client
                .get(u.clone())
                .send()
                .await
                .map_err(|e| ReqwestError(e));
            Ok(c.unwrap().text().await.map_err(|e| ReqwestError(e))?)
        })
        .await?;

        Base64::from_str(&s).map_err(Error::Base64DecodeError)
    }
}
