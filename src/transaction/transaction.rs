use async_stream::try_stream;
use futures::StreamExt;
use serde::{Deserialize, Serialize, Serializer};
use std::pin::Pin;
use std::str::FromStr;

use crate::bundle::item::BundleStreamFactory;
use crate::crypto::merkle::{Chunks, Helpers, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE};
use crate::crypto::sign::ArweaveSigner;
use crate::{
    crypto::{
        base64::Base64,
        hash::{deep_hash, Hasher},
        hash::{DeepHashItem, ToItems},
        merkle::{generate_data_root, resolve_proofs, Node, Proof},
        sign::Signer,
    },
    currency::Currency,
    error::Error,
    transaction::tags::Tag,
    types::{Chunk, Transaction as JsonTransaction},
};
use futures_core::Stream;
use serde::ser::SerializeStruct;

#[derive(Deserialize, Debug, Default, PartialEq)]
pub struct Transaction {
    pub format: u8,
    pub id: Base64,
    pub last_tx: Base64,
    pub owner: Base64,
    pub tags: Vec<Tag<Base64>>,
    pub target: Base64,
    pub quantity: Currency,
    pub data: Base64,
    pub data_root: Base64,
    pub data_size: u64,
    pub reward: u64,
    pub signature: Base64,
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

#[allow(dead_code)]
impl Transaction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        crypto: Box<dyn Signer>,
        target: Base64,
        chunks: Option<TransactionChunks>,
        quantity: u128,
        fee: u64,
        last_tx: Base64,
        tags: Vec<Tag<Base64>>,
    ) -> Result<Self, Error> {
        if quantity.lt(&0) {
            return Err(Error::InvalidValueForTx);
        }
        let empty = Base64(vec![]);
        let mut transaction = match chunks {
            Some(c) => Transaction {
                format: 2,
                data_size: c.data_size as u64,
                data_root: c.data_root,
                ..Default::default()
            },
            None => Transaction {
                format: 2,
                data_size: 0,
                data_root: empty,
                ..Default::default()
            },
        };
        transaction.owner = crypto.public_key()?;

        transaction.tags = tags;

        //todo... Fetch and set last_tx if not provided (primarily for testing).
        transaction.last_tx = last_tx;

        transaction.reward = fee;
        transaction.quantity = Currency::from(quantity);
        transaction.target = target;

        let deep_hash_item = transaction.to_deep_hash_item()?;
        let signature_data = deep_hash(deep_hash_item);
        let signature = crypto.sign(&signature_data)?;
        let id = signature.as_slice().sha256();
        transaction.signature = Base64::from(signature.as_slice());
        transaction.id = Base64(id.to_vec());

        Ok(transaction)
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
            data: Default::default(),
            data_root: self.data_root.clone(),
            data_size: self.data_size,
            reward: self.reward,
            signature: self.signature.clone(),
        })
    }

    pub fn verify(&mut self) -> Result<(), Error> {
        if self.signature.is_empty() {
            return Err(Error::UnsignedTransaction);
        }

        let id = self.signature.0.as_slice().sha256();
        if !Base64(id.to_vec()).eq(&self.id) {
            return Err(Error::TransactionWrongId);
        }
        let deep_hash_item = self.to_deep_hash_item()?;
        let message = deep_hash(deep_hash_item);

        let singer = ArweaveSigner::from_owner(Base64::from(self.owner.0.as_slice())).unwrap();
        if singer.verify(&message, &self.signature.0) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
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
            last_tx: json_tx
                .last_tx
                .try_into()
                .map_err(Error::Base64DecodeError)?,
            owner: json_tx.owner.try_into().map_err(Error::Base64DecodeError)?,
            tags,
            target: json_tx
                .target
                .try_into()
                .map_err(Error::Base64DecodeError)?,
            data_root: json_tx
                .data_root
                .try_into()
                .map_err(Error::Base64DecodeError)?,
            data: Base64::from_str(json_tx.data.as_str()).unwrap(),
            data_size: u64::from_str(&json_tx.data_size).unwrap(),
            reward: u64::from_str(&json_tx.reward).unwrap(),
            signature: json_tx
                .signature
                .try_into()
                .map_err(Error::Base64DecodeError)?,
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

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Transaction", 12)?;
        state.serialize_field("format", &self.format)?;
        state.serialize_field("id", &self.id.to_string())?;
        state.serialize_field("last_tx", &self.last_tx.to_string())?;
        state.serialize_field("owner", &self.owner.to_string())?;
        state.serialize_field("tags", &self.tags)?;
        state.serialize_field("target", &self.target.to_string())?;
        state.serialize_field("quantity", &self.quantity.to_string())?;
        state.serialize_field("data_root", &self.data_root.to_string())?;
        state.serialize_field("data", &self.data.to_string())?;
        state.serialize_field("data_size", &self.data_size.to_string())?;
        state.serialize_field("reward", &self.reward.to_string())?;
        state.serialize_field("signature", &self.signature.to_string())?;
        state.end()
    }
}

#[derive(Clone, Debug)]
pub struct TransactionChunks {
    chunks: Vec<Node>,
    proofs: Vec<Proof>,
    data_root: Base64,
    data_size: usize,
}

pub struct TransactionChunksFactory<T: ?Sized> {
    inner: Box<T>,
    length: usize,
    chunks: Option<TransactionChunks>,
}

impl<T> TransactionChunksFactory<T>
where
    T: BundleStreamFactory + ?Sized,
{
    pub fn new(inner: Box<T>) -> Result<TransactionChunksFactory<T>, Error> {
        Ok(Self {
            length: inner.length()?,
            inner,
            chunks: None,
        })
    }

    pub async fn hash(&mut self) -> Result<TransactionChunks, Error> {
        if self.chunks.is_none() {
            let mut chunks = self.generate_leaves().await.unwrap();
            let root = generate_data_root(chunks.clone()).unwrap();
            let data_root = Base64(root.id.as_slice().to_vec());
            let mut proofs = resolve_proofs(root, None).unwrap();

            // Discard the last chunk & proof if it's zero length.
            let last_chunk = chunks.last().unwrap();
            if last_chunk.max_byte_range == last_chunk.min_byte_range {
                chunks.pop();
                proofs.pop();
            }
            self.chunks = Some(TransactionChunks {
                chunks,
                proofs,
                data_root,
                data_size: self.length,
            });
        }
        Ok(self.chunks.clone().unwrap())
    }

    async fn generate_leaves(&self) -> Result<Vec<Node>, Error> {
        let chunks = Chunks::new(MIN_CHUNK_SIZE, MAX_CHUNK_SIZE, self.length);

        let mut leaves = Vec::<Node>::new();
        let mut buf = Vec::with_capacity(MAX_CHUNK_SIZE);
        let mut binary_stream = self.inner.stream();
        for chunk in chunks {
            if buf.len() < chunk.1 - chunk.0 {
                while let Some(item) = binary_stream.next().await {
                    match item {
                        Ok(d) => {
                            buf.extend(d);
                            if buf.len() >= chunk.1 - chunk.0 {
                                break;
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
            }

            let data_hash = (&buf[0..(chunk.1 - chunk.0)]).sha256();
            if buf.len() > chunk.1 - chunk.0 {
                buf.copy_within((chunk.1 - chunk.0).., 0);
                buf.resize(buf.len() - (chunk.1 - chunk.0), 0);
            } else {
                buf.clear();
            }
            let offset = chunk.1.to_note_vec();
            let id = (vec![data_hash.as_slice(), &offset]).sha256();

            leaves.push(Node {
                id,
                data_hash: Some(data_hash),
                min_byte_range: chunk.0,
                max_byte_range: chunk.1,
                left_child: None,
                right_child: None,
            });
        }
        Ok(leaves)
    }

    pub fn iterator(&mut self) -> Pin<Box<dyn Stream<Item = Result<Chunk, Error>> + '_>> {
        Box::pin(try_stream! {
            if self.chunks.is_none() {
                self.hash().await?;
            }
            let chunks = self.chunks.clone().unwrap();
            let mut buf = Vec::with_capacity(MAX_CHUNK_SIZE);
            let mut binary_stream = self.inner.stream();

            for (i, _) in chunks.proofs.iter().enumerate() {
                let chunk = chunks.chunks.get(i);
                let proof = chunks.proofs.get(i);
                if chunk.is_none() || proof.is_none() {
                    return
                }
                let chunk = chunk.unwrap();
                let proof = proof.unwrap();
                assert!(chunk.max_byte_range > chunk.min_byte_range);
                let chunk_size = chunk.max_byte_range - chunk.min_byte_range;
                if buf.len() >= chunk_size {
                    break;
                }
                while let Some(item) = binary_stream.next().await {
                    let item = item.unwrap();
                    buf.extend(item);
                    if buf.len() >= chunk_size {
                        break;
                    }
                }

                let mut chnunk_buf = vec![0u8; chunk_size];
                chnunk_buf.copy_from_slice(&buf[0..chunk_size]);
                yield Chunk {
                    data_root: chunks.data_root.clone(),
                    data_size: chunks.data_size.to_string(),
                    data_path: Base64(proof.proof.clone()),
                    offset: proof.offset.to_string(),
                    chunk: Base64(chnunk_buf)
                };
                if buf.len() > chunk_size {
                    buf.copy_within(chunk_size.., 0);
                    buf.resize(buf.len() - chunk_size, 0);
                } else {
                    buf.clear();
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read, str::FromStr};

    use crate::error::Error;
    use crate::{
        crypto::base64::Base64,
        currency::Currency,
        transaction::{tags::Tag, transaction::Transaction},
    };

    #[test]
    pub fn should_parse_correctly() {
        let mut file = File::open("res/sample_tx.json").unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();

        let actual_tx: Transaction = data.as_str().try_into().unwrap();
        let expected_tx = Transaction {
            format: 2,
            id: Base64::from_str("7DjRLlYLAQOwcblMLX5hXW8WiZdvFDmxu_fNToLjYP0").unwrap(),
            last_tx: Base64::from_str("8iQ198CY00aVsLSONWLVVYGWl41Pwzk851hEaJmlmg88qnI7VhgPpZdGUog_KGQ3").unwrap(),
            owner: Base64::from_str("4iZJkYeVMYweuaF_X1-59T9Uk6znM-6XIUPQ_RgjWNJ5hFtgwk-teR9WrdvK3ndMvVxDqORmjCSsEvbohSdL3XVi3Qx3RfSKdK2xjMfe5aPyjNZygk3_diEg1X01pUuv5AZZpT8ANprpB1wOquJtG1ZNVgkp_0s-JzjynKgOY90vc5MKC4jkGB9KMMmQG7FMkajlirmZPHjzhOotJVbbL9Ynd_LWtQRva4EYf59h8ddaB7Gq1U5lXcKYN9x1EokkR-uLUYlVk1AQ6WfBtRuX51OOI_rLM0tn_KCeUioVSesC8WxASreOx8V8kZIKAMoDRAJIZ64XSu8uL6kyLFfi2yaAPMIXIEF3zO-37lEsUa_Z2Mdg05AsV4CWTIvwgd9n8oGIiQXWMmvt2oG0ZLT72lLSCavVh4Uf1JXTRpnkl0RUduu5N_MZSw6qMoYSvzEmSEmpI3ag9k3Zb6WVwZWllIcHupsXR5LvpMDV-HhGXkVnDVDp3Y0MbnMacQNrdkSLSDYoz4RkuaZiIj0CR6PnHoAM-gG-WnFW6ktdjaEKiSxHg1FOJjyZ1YeyPRFWXxOPsdak1SRMsGhrd2dIx6FO3_0tdKJn7e0bSoxtbV9Ljvnflm3fnMKs2ohA8F9ugDGAbv4zoiFqApETi8HLwU47Myn149NycxMXcf0PUjWMiXM").unwrap(),
            tags: vec![
                Tag { name: Base64(b"Bundle-Format".to_vec()), value: Base64(b"binary".to_vec()) },
                Tag { name: Base64(b"Bundle-Version".to_vec()), value: Base64(b"2.0.0".to_vec()) },
                Tag { name: Base64(b"Application".to_vec()), value: Base64(b"4EVERLAND".to_vec()) },
                Tag { name: Base64(b"Website".to_vec()), value: Base64(b"4everland.org".to_vec()) },
                Tag { name: Base64(b"App-Name".to_vec()), value: Base64(b"arseeding".to_vec()) },
                Tag { name: Base64(b"App-Version".to_vec()), value: Base64(b"1.0.0".to_vec()) },
                Tag { name: Base64(b"Action".to_vec()), value: Base64(b"Bundle".to_vec()) },
                Tag { name: Base64(b"Protocol-Name".to_vec()), value: Base64(b"U".to_vec()) },
                Tag { name: Base64(b"Action".to_vec()), value: Base64(b"Burn".to_vec()) },
                Tag { name: Base64(b"App-Name".to_vec()), value: Base64(b"SmartWeaveAction".to_vec()) },
                Tag { name: Base64(b"App-Version".to_vec()), value: Base64(b"0.3.0".to_vec()) },
                Tag { name: Base64(b"Input".to_vec()), value: Base64(b"{\"function\":\"mint\"}".to_vec()) },
                Tag { name: Base64(b"Contract".to_vec()), value: Base64(b"KTzTXT_ANmF84fWEKHzWURD1LWd9QaFR9yfYUwH2Lxw".to_vec()) },
            ],
            target: Base64(vec![]),
            quantity: Currency::from(0),
            data_root: Base64::from_str("UhOCNNZ6QteHG4nCDbFMDpbYWIo1FmEhU9nLw4M8KB0").unwrap(),
            data: Base64(vec![]),
            data_size: 60589,
            reward: 212017846,
            signature: Base64::from_str("UJvcZhVoS_vRlETe8mEL-yq_qb_76dzBVmD2-mPUPAnWyC--2U85C1gpVD3-PTYQZq-aZpMmIJp4nFAjEsxssCwcIlCboC5EEG14T520g_9blmdB0u9Jj_4AVMB858K_KRL7Dh_GRudgSDOPY_2d9KjjIJTSm_4TeJk9ZoifsOn0OAMny71mUSNWtEjcTozSlKEMn6xqlsuXGAMVswlTaqy_MWbFllUkhpQdYg7lI2MdppMt-I30cVed4opxDRMHmFhA31FjpOmqkRbB1E7h8xK_t7XEZ2lSCjVH_stlPjgmKgh83Wm87f0qgkOp_N-oZrExX7yMkjzPUguxsG06zVzvNdA3OM2sIkAJuTbCmX0BeVUliYPaEWiny_cOQYbyKCiW8Mla2_ut77b-nKvR2Llu32HCLjh8hpx7GuPKQzOmBgfBLvLApu_ob-ytOnxWBaod9iqHk_hkGFUdyg_eb7w7RumijCAa2azVvor1IUizJFZ-9Cp6GkKCdCeQsTjiaS0wpPoh4MQ18HSey8lfqio_QrH_L6ARIeWh0aOzZ_R4ciYBK0YNqawMygTnktYZo4T6rzkB6FHR5hEwcqA2LtBc5Q6ktaZi0dyiUsE_zMALyM7toUAg3njorgYCQfQqj_79oPetgMz_cBQvHkHdpSqM2EdMxONz-aIpzq5iboA").unwrap(),
        };

        assert_eq!(actual_tx, expected_tx);
    }

    #[test]
    pub fn should_verify_correctly() {
        let mut tx = Transaction {
            format: 2,
            id: Base64::from_str("7DjRLlYLAQOwcblMLX5hXW8WiZdvFDmxu_fNToLjYP0").unwrap(),
            last_tx: Base64::from_str("8iQ198CY00aVsLSONWLVVYGWl41Pwzk851hEaJmlmg88qnI7VhgPpZdGUog_KGQ3").unwrap(),
            owner: Base64::from_str("4iZJkYeVMYweuaF_X1-59T9Uk6znM-6XIUPQ_RgjWNJ5hFtgwk-teR9WrdvK3ndMvVxDqORmjCSsEvbohSdL3XVi3Qx3RfSKdK2xjMfe5aPyjNZygk3_diEg1X01pUuv5AZZpT8ANprpB1wOquJtG1ZNVgkp_0s-JzjynKgOY90vc5MKC4jkGB9KMMmQG7FMkajlirmZPHjzhOotJVbbL9Ynd_LWtQRva4EYf59h8ddaB7Gq1U5lXcKYN9x1EokkR-uLUYlVk1AQ6WfBtRuX51OOI_rLM0tn_KCeUioVSesC8WxASreOx8V8kZIKAMoDRAJIZ64XSu8uL6kyLFfi2yaAPMIXIEF3zO-37lEsUa_Z2Mdg05AsV4CWTIvwgd9n8oGIiQXWMmvt2oG0ZLT72lLSCavVh4Uf1JXTRpnkl0RUduu5N_MZSw6qMoYSvzEmSEmpI3ag9k3Zb6WVwZWllIcHupsXR5LvpMDV-HhGXkVnDVDp3Y0MbnMacQNrdkSLSDYoz4RkuaZiIj0CR6PnHoAM-gG-WnFW6ktdjaEKiSxHg1FOJjyZ1YeyPRFWXxOPsdak1SRMsGhrd2dIx6FO3_0tdKJn7e0bSoxtbV9Ljvnflm3fnMKs2ohA8F9ugDGAbv4zoiFqApETi8HLwU47Myn149NycxMXcf0PUjWMiXM").unwrap(),
            tags: vec![
                Tag { name: Base64(b"Bundle-Format".to_vec()), value: Base64(b"binary".to_vec()) },
                Tag { name: Base64(b"Bundle-Version".to_vec()), value: Base64(b"2.0.0".to_vec()) },
                Tag { name: Base64(b"Application".to_vec()), value: Base64(b"4EVERLAND".to_vec()) },
                Tag { name: Base64(b"Website".to_vec()), value: Base64(b"4everland.org".to_vec()) },
                Tag { name: Base64(b"App-Name".to_vec()), value: Base64(b"arseeding".to_vec()) },
                Tag { name: Base64(b"App-Version".to_vec()), value: Base64(b"1.0.0".to_vec()) },
                Tag { name: Base64(b"Action".to_vec()), value: Base64(b"Bundle".to_vec()) },
                Tag { name: Base64(b"Protocol-Name".to_vec()), value: Base64(b"U".to_vec()) },
                Tag { name: Base64(b"Action".to_vec()), value: Base64(b"Burn".to_vec()) },
                Tag { name: Base64(b"App-Name".to_vec()), value: Base64(b"SmartWeaveAction".to_vec()) },
                Tag { name: Base64(b"App-Version".to_vec()), value: Base64(b"0.3.0".to_vec()) },
                Tag { name: Base64(b"Input".to_vec()), value: Base64(b"{\"function\":\"mint\"}".to_vec()) },
                Tag { name: Base64(b"Contract".to_vec()), value: Base64(b"KTzTXT_ANmF84fWEKHzWURD1LWd9QaFR9yfYUwH2Lxw".to_vec()) },
            ],
            target: Base64(vec![]),
            quantity: Currency::from(0),
            data_root: Base64::from_str("UhOCNNZ6QteHG4nCDbFMDpbYWIo1FmEhU9nLw4M8KB0").unwrap(),
            data: Base64(vec![]),
            data_size: 60589,
            reward: 212017846,
            signature: Base64::from_str("UJvcZhVoS_vRlETe8mEL-yq_qb_76dzBVmD2-mPUPAnWyC--2U85C1gpVD3-PTYQZq-aZpMmIJp4nFAjEsxssCwcIlCboC5EEG14T520g_9blmdB0u9Jj_4AVMB858K_KRL7Dh_GRudgSDOPY_2d9KjjIJTSm_4TeJk9ZoifsOn0OAMny71mUSNWtEjcTozSlKEMn6xqlsuXGAMVswlTaqy_MWbFllUkhpQdYg7lI2MdppMt-I30cVed4opxDRMHmFhA31FjpOmqkRbB1E7h8xK_t7XEZ2lSCjVH_stlPjgmKgh83Wm87f0qgkOp_N-oZrExX7yMkjzPUguxsG06zVzvNdA3OM2sIkAJuTbCmX0BeVUliYPaEWiny_cOQYbyKCiW8Mla2_ut77b-nKvR2Llu32HCLjh8hpx7GuPKQzOmBgfBLvLApu_ob-ytOnxWBaod9iqHk_hkGFUdyg_eb7w7RumijCAa2azVvor1IUizJFZ-9Cp6GkKCdCeQsTjiaS0wpPoh4MQ18HSey8lfqio_QrH_L6ARIeWh0aOzZ_R4ciYBK0YNqawMygTnktYZo4T6rzkB6FHR5hEwcqA2LtBc5Q6ktaZi0dyiUsE_zMALyM7toUAg3njorgYCQfQqj_79oPetgMz_cBQvHkHdpSqM2EdMxONz-aIpzq5iboA").unwrap(),
        };

        let v = tx.verify().map_err(|_| Error::InvalidSignature);
        assert!(v.is_ok());
    }
}
