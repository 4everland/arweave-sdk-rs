use std::io::{SeekFrom};
use async_trait::async_trait;
use bytes::BytesMut;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use crate::crypto::base64::Base64;
use crate::error::Error;

#[async_trait]
pub trait TransactionReader {
    async fn chunk_read(&mut self, start: usize, end: usize) -> Result<Vec<u8>, Error>;
    async fn length(&self) -> Result<usize, Error>;
    async fn read_all(&mut self) -> Result<Vec<u8>, Error>
        where Self: Sync + Sized {
        let end = self.length().await.unwrap();
        self.chunk_read(0, end).await
    }
    async fn is_empty(&self) -> bool
        where Self: Sync + Sized {
        self.length().await.unwrap() > 0
    }
}

#[async_trait]
impl TransactionReader for Vec<u8> {
    async fn chunk_read(&mut self, start: usize, end: usize) -> Result<Vec<u8>, Error> {
        self.as_slice().chunk_read(start, end).await
    }

    async fn length(&self) -> Result<usize, Error> {
        Ok(self.len())
    }
}
#[async_trait]
impl TransactionReader for &[u8] {
    async fn chunk_read(&mut self, start: usize, end: usize) -> Result<Vec<u8>, Error> {
        let end = if end > self.len() {
            self.len()
        } else {
            end
        };
        let len = end - start;
        if len <= 0 {
            return Ok(vec![])
        }
        Ok(self[start..end].to_vec())

    }

    async fn length(&self) -> Result<usize, Error> {
        Ok(self.len())
    }
}
#[async_trait]
impl TransactionReader for Base64 {
    async fn chunk_read(&mut self, start: usize, end: usize) -> Result<Vec<u8>, Error> {
       self.0.chunk_read(start, end).await
    }

    async fn length(&self) -> Result<usize, Error> {
        Ok(self.0.len())
    }
}
#[async_trait]
impl TransactionReader for File {
    async fn chunk_read(&mut self, start: usize, end: usize) -> Result<Vec<u8>, Error> {
        let l = self.length().await.unwrap();
        let end = if end > l {
            l
        } else {
            end
        };
        let len = end - start;
        if len <= 0 {
            return Ok(vec![])
        }


        self.seek(SeekFrom::Start(start as u64)).await.map_err(|err|Error::IoError(err)).unwrap();

        let mut buf = [0u8; 32 * 1024];
        let mut res = Vec::with_capacity(len);
        let mut readed = 0;
        let s: Option<Error> = loop {
            let rn = self.read_exact(&mut buf).await;
            match rn {
                Ok(n) => {
                    readed += n;
                    res.extend(buf[0..n].to_vec());
                    if readed == len {
                        break None;
                    }
                }
                Err(io_error) => {
                    match io_error.kind() {
                        std::io::ErrorKind::UnexpectedEof => break None,
                        _ => break Some(Error::IoError(io_error))
                    }
                }
            }
        };
        if s.is_none() {
            Ok(res)
        } else {
            Err(s.unwrap())
        }
    }

    async fn length(&self) -> Result<usize, Error> {
        let metadata = self.metadata().await.map_err(|err|Error::IoError(err)).unwrap();
        Ok(metadata.len() as usize)
    }
}



