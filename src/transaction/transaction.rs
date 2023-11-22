use serde::Deserialize;
use std::str::FromStr;

use crate::{
    crypto::{
        base64::Base64,
        hash::{DeepHashItem, ToItems},
        merkle::{generate_data_root, generate_leaves, Node, Proof, resolve_proofs},
        Provider,
        hash::{deep_hash, Hasher},
        sign::verify_with_pub_key_n,
    },
    currency::Currency,
    transaction::tags::{FromUtf8Strs, Tag},
    types::{
        Chunk,
        Transaction as JsonTransaction
    },

    error::Error,
};

#[derive(Deserialize, Debug, Default, PartialEq)]
pub struct Transaction {
    /* Fields required for signing */
    pub format: u8,
    pub id: Base64,
    pub last_tx: Base64,
    pub owner: Base64,
    pub tags: Vec<Tag<Base64>>,
    pub target: Base64,
    pub quantity: Currency,
    pub data_root: Base64,
    pub data: Base64,
    pub data_size: u64,
    pub reward: u64,
    pub signature: Base64,
    #[serde(skip)]
    pub chunks: Vec<Node>,
    #[serde(skip)]
    pub proofs: Vec<Proof>,
}

impl<'a> ToItems<'a, Transaction> for Transaction {
    fn to_deep_hash_item(&'a self) -> Result<DeepHashItem, Error> {
        match &self.format {
            1 => {
                let quantity = Base64::from_utf8_str(&self.quantity.to_string()).unwrap();
                let reward = Base64::from_utf8_str(&self.reward.to_string()).unwrap();
                let mut children: Vec<DeepHashItem> = vec![
                    &self.owner,
                    &self.target,
                    &self.data,
                    &quantity,
                    &reward,
                    &self.last_tx,
                ]
                    .into_iter()
                    .map(|op| DeepHashItem::from_item(&op.0))
                    .collect();
                children.push(self.tags.to_deep_hash_item()?);

                Ok(DeepHashItem::from_children(children))
            }
            2 => {
                let mut children: Vec<DeepHashItem> = vec![
                    self.format.to_string().as_bytes(),
                    &self.owner.0,
                    &self.target.0,
                    self.quantity.to_string().as_bytes(),
                    self.reward.to_string().as_bytes(),
                    &self.last_tx.0,
                ]
                    .into_iter()
                    .map(DeepHashItem::from_item)
                    .collect();
                children.push(self.tags.to_deep_hash_item().unwrap());
                children.push(DeepHashItem::from_item(
                    self.data_size.to_string().as_bytes(),
                ));
                children.push(DeepHashItem::from_item(&self.data_root.0));

                Ok(DeepHashItem::from_children(children))
            }
            _ => unreachable!(),
        }
    }
}

impl Transaction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        crypto: &Provider,
        target: Base64,
        data: Vec<u8>,
        quantity: u128,
        fee: u64,
        last_tx: Base64,
        other_tags: Vec<Tag<Base64>>,
    ) -> Result<Self, Error> {
        if quantity.lt(&0) {
            return Err(Error::InvalidValueForTx);
        }

        let mut transaction = Transaction::generate_merkle(data).unwrap();
        transaction.owner = crypto.keypair_modulus();

        let mut tags = vec![];
        tags.extend(other_tags);
        transaction.tags = tags;

        //todo... Fetch and set last_tx if not provided (primarily for testing).
        transaction.last_tx = last_tx;

        transaction.reward = fee;
        transaction.quantity = Currency::from(quantity);
        transaction.target = target;

        Ok(transaction)
    }

    fn generate_merkle(data: Vec<u8>) -> Result<Transaction, Error> {
        if data.is_empty() {
            let empty = Base64(vec![]);
            Ok(Transaction {
                format: 2,
                data_size: 0,
                data: empty.clone(),
                data_root: empty,
                chunks: vec![],
                proofs: vec![],
                ..Default::default()
            })
        } else {
            let mut chunks = generate_leaves(data.clone()).unwrap();
            let root = generate_data_root(chunks.clone()).unwrap();
            let data_root = Base64(root.id.into_iter().collect());
            let mut proofs = resolve_proofs(root, None).unwrap();

            // Discard the last chunk & proof if it's zero length.
            let last_chunk = chunks.last().unwrap();
            if last_chunk.max_byte_range == last_chunk.min_byte_range {
                chunks.pop();
                proofs.pop();
            }

            Ok(Transaction {
                format: 2,
                data_size: data.len() as u64,
                data: Base64(data),
                data_root,
                chunks,
                proofs,
                ..Default::default()
            })
        }
    }

    pub fn clone_with_no_data(&self) -> Result<Self, Error> {
        Ok(Self {
            format: self.format,
            id: self.id.clone(),
            last_tx: self.last_tx.clone(),
            owner: self.owner.clone(),
            tags: self.tags.clone(),
            target: self.target.clone(),
            quantity: self.quantity,
            data_root: self.data_root.clone(),
            data: Base64::default(),
            data_size: self.data_size,
            reward: self.reward,
            signature: self.signature.clone(),
            chunks: Vec::new(),
            proofs: Vec::new(),
        })
    }

    pub fn get_chunk(&self, idx: usize) -> Result<Chunk, Error> {
        Ok(Chunk {
            data_root: self.data_root.clone(),
            data_size: self.data_size,
            data_path: Base64(self.proofs[idx].proof.clone()),
            offset: self.proofs[idx].offset,
            chunk: Base64(
                self.data.0[self.chunks[idx].min_byte_range..self.chunks[idx].max_byte_range]
                    .to_vec(),
            ),
        })
    }

    pub fn verify(&self) -> Result<(), Error> {
        if self.signature.is_empty() {
            return Err(Error::UnsignedTransaction);
        }

        let deep_hash_item = self.to_deep_hash_item()?;
        let message = deep_hash(deep_hash_item);

        verify_with_pub_key_n(&self.owner.0, &message, &self.signature.0).map(|_| ())
            .map_err(|err| {
                println!("er3 {}", err);
                Error::InvalidSignature})

    }
}



impl TryFrom<JsonTransaction> for Transaction {
    type Error = Error;
    fn try_from(json_tx: JsonTransaction) -> Result<Self, Self::Error> {
        let tags = json_tx.tags.iter().map(Tag::from).collect();
        Ok(Transaction {
            quantity: Currency::from_str(&json_tx.quantity).unwrap(),
            format: json_tx.format,
            id: json_tx.id.try_into().map_err(Error::Base64DecodeError)?,
            last_tx: json_tx.last_tx.try_into().map_err(Error::Base64DecodeError)?,
            owner: json_tx.owner.try_into().map_err(Error::Base64DecodeError)?,
            tags,
            target: json_tx.target.try_into().map_err(Error::Base64DecodeError)?,
            data_root: json_tx.data_root.try_into().map_err(Error::Base64DecodeError)?,
            data: json_tx.data.try_into().map_err(Error::Base64DecodeError)?,
            data_size: u64::from_str(&json_tx.data_size).unwrap(),
            reward: u64::from_str(&json_tx.reward).unwrap(),
            signature: json_tx.signature.try_into().map_err(Error::Base64DecodeError)?,
            chunks: vec![],
            proofs: vec![],
        })
    }
}

impl TryFrom<&str> for Transaction {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let json_tx: JsonTransaction = serde_json::from_str(s).map_err(Error::SerdeJsonError)?;
        Transaction::try_from(json_tx)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read, str::FromStr};

    use crate::{
        crypto::base64::Base64,
        currency::Currency,
        transaction::{tags::Tag, transaction::Transaction},
    };
    use crate::error::Error;

    #[test]
    pub fn should_parse_correctly() {
        let mut file = File::open("res/sample_tx.json").unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();

        let actual_tx: Transaction = data.as_str().try_into().unwrap();
        let expected_tx = Transaction {
            format: 2,
            id: Base64::from_str("t3K1b8IhvtGWxAGsipZE5NafmEGrtj3OAcYikJ0edeU").unwrap(),
            last_tx: Base64::from_str("ddvXNxatQmS3LeKi_x1RJn6g9G0esUaTEgT40a6f_WYyawZaSK3w8WC2czAuLgmT").unwrap(),
            owner: Base64::from_str("pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w").unwrap(),
            tags: vec![
                Tag { name: Base64(b"test".to_vec()), value: Base64(b"test".to_vec()) }
            ],
            target: Base64::from_str("PAgdonEn9f5xd-UbYdCX40Sj28eltQVnxz6bbUijeVY").unwrap(),
            quantity: Currency::from(100000),
            data_root: Base64(vec![]),
            data: Base64(vec![]),
            data_size: 0,
            reward: 600912,
            signature: Base64::from_str("EJQN0DpfPBm1aUo1qk6dCkrY_zKHMJBQx3v36UOzmodF39RvBI2rqx_gTgLzszNkHIWnf-zwzXCz6xF5wzlrHWkosgfSwfZOhm3aVE5KLGvqVqSlMTlIzkIcR6KKFRe9m7HyOxJHvXykAD8X1X_6RExnXAZX4B9mwR10lqCG2wkRMJxchVisOZph-O5OfgteC1lb5YFx0BNAtmVgtUlY7dQdV1vVYq2_sDJPkYpHK5YIMIjoRsqdGP31gOFXTmzuIHYhRyii-clx2uxrv0pjfnv9tl9WPViHu3FGLlW9tH5z3mXdt7PQx-o8MGK_MXz10LLlqsPdos2rI3D3MgPUqQ").unwrap(),
            chunks: vec![],
            proofs: vec![]
        };

        assert_eq!(actual_tx, expected_tx);
    }

    #[test]
    pub fn should_verify_correctly() {

        let tx = &Transaction {
            format: 2,
            id: Base64::from_str("t3K1b8IhvtGWxAGsipZE5NafmEGrtj3OAcYikJ0edeU").unwrap(),
            last_tx: Base64::from_str("ddvXNxatQmS3LeKi_x1RJn6g9G0esUaTEgT40a6f_WYyawZaSK3w8WC2czAuLgmT").unwrap(),
            owner: Base64::from_str("pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w").unwrap(),
            tags: vec![
                Tag { name: Base64(b"test".to_vec()), value: Base64(b"test".to_vec()) }
            ],
            target: Base64::from_str("PAgdonEn9f5xd-UbYdCX40Sj28eltQVnxz6bbUijeVY").unwrap(),
            quantity: Currency::from(100000),
            data_root: Base64(vec![]),
            data: Base64(vec![]),
            data_size: 0,
            reward: 600912,
            signature: Base64::from_str("EJQN0DpfPBm1aUo1qk6dCkrY_zKHMJBQx3v36UOzmodF39RvBI2rqx_gTgLzszNkHIWnf-zwzXCz6xF5wzlrHWkosgfSwfZOhm3aVE5KLGvqVqSlMTlIzkIcR6KKFRe9m7HyOxJHvXykAD8X1X_6RExnXAZX4B9mwR10lqCG2wkRMJxchVisOZph-O5OfgteC1lb5YFx0BNAtmVgtUlY7dQdV1vVYq2_sDJPkYpHK5YIMIjoRsqdGP31gOFXTmzuIHYhRyii-clx2uxrv0pjfnv9tl9WPViHu3FGLlW9tH5z3mXdt7PQx-o8MGK_MXz10LLlqsPdos2rI3D3MgPUqQ").unwrap(),
            chunks: vec![],
            proofs: vec![]
        };

        let v = tx.verify().map_err(|err| {
            println!("err: {}", err);
            Error::InvalidSignature
        });
        assert!(v.is_ok());

    }
}

