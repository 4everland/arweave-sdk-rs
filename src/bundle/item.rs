use crate::bundle::converter::ByteArrayConverter;
use crate::bundle::sign::BundleSigner;
use crate::bundle::tags::Tags;
use crate::crypto::base64::Base64;
use crate::crypto::hash::{deep_hash, DeepHashItem, Hasher, ToItems};
use crate::crypto::sign::Signer;
use crate::error::Error;
use async_stream::try_stream;
use bitcoin::hex::DisplayHex;
use futures::StreamExt;
use futures_core::Stream;
use sha2::Digest;
use sha2::Sha384;
use std::io::Read;
use std::ops::DerefMut;
use std::pin::Pin;
use std::str::FromStr;
use tokio::io::{AsyncReadExt, AsyncSeek, AsyncSeekExt};

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
pub struct BundleItem<T, R> {
    pub signature_type: u8,
    pub signature: Base64,
    pub owner: Base64,
    pub target: Base64,
    pub anchor: Base64,
    pub tags: Tags,
    pub id: Base64,
    item: R,
    signer: T,
    length: usize,
}

pub struct DataItemCreateOptions {
    pub target: Base64,
    pub anchor: Base64,
    pub tags: Tags,
}

impl<T, R> BundleItem<T, R>
where
    T: Signer + BundleSigner,
    R: BundleStreamFactory,
{
    pub fn new(s: T, r: R, o: DataItemCreateOptions) -> Result<BundleItem<T, R>, Error> {
        let l = r.length().unwrap();
        return Ok(BundleItem {
            signature_type: s.signature_type(),
            signature: Default::default(),
            owner: s.public_key().unwrap(),
            target: Default::default(),
            anchor: Default::default(),
            tags: o.tags,
            id: Default::default(),
            item: r,
            signer: s,
            length: l,
        });
    }

    async fn signature(&mut self) -> Result<(), Error> {
        let h = deep_hash(self.to_deep_hash_item().await.unwrap());
        let signature = self
            .signer
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

    //todo
    pub fn binary_length(&self) -> Result<usize, Error> {
        let _owner = self.signer.public_key().unwrap();
        let data_length = self.length;

        Ok(2 + self.signature.0.len()
            + _owner.0.len()
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
            let _owner = self.signer.public_key().unwrap();


            yield ByteArrayConverter::short_to_2_byte_array(
                self.signature_type as u64,
            );
            yield self.signature.0.clone();
            // if _owner.len() != signer.owner_length() {
            //     // return "Owner must be {} bytes, but was incorrectly {}", signer.owner_length(),  _owner.len()
            // }
            yield _owner.0.clone();

            //let position = 2 + self.signature.0.len() + _owner.0.len();
            //bytes[position] = !self.target.is_empty() as u8;
            yield [self.target.is_empty() as u8].to_vec();
            if !self.target.is_empty() {
                if self.target.0.len() != 32 {
                    // return Err()//Target must be 32 bytes;
                }
                yield self.target.0.clone();
            }
            yield [self.anchor.is_empty() as u8].to_vec();
            if !self.anchor.is_empty() {
                if self.anchor.0.len() != 32 {
                    // return Err()//Anchor must be 32 bytes
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
            while let Some(readed) = stream.next().await {
                yield readed.unwrap().to_vec();
            }
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate jsonwebkey as jwk;

    use crate::bundle::item::{BundleItem, DataItemCreateOptions};
    use crate::bundle::tags::Tags;
    use crate::crypto::base64::Base64;
    use crate::crypto::sign;
    use crate::crypto::sign::EthSigner;
    use crate::types::BundleTag;
    use futures::StreamExt;

    #[tokio::test]
    async fn test_bundle_item_create() {
        let jwt_str = r#"{
    "d":"YQtd4erLTR6hljK_RBtZMnov6Cys9g04SKHSF2y82B2iFPjrzu910HnCDKjDQk7z2gFdvqeCIz7xaHUaw7AabnVrIt3F9N5dyKmQxj7z1ZtMbAQH17N5HezeuQ1YehAo7aD4voXVY1A_fBWRSgtK_9X-AeaATYIwZc_UVVmVovzyUQYM_u0jvIgT-gaeNpAOU_fpBVvQUkirmaaZnINpuo08Ev-_zfSjblxXQ70gW29_7Q4QBikJwuH1xCIuOsMCQ4a4b3qgeVca6scrqkbUyyCJyeRSa9QMdlE6ZgbsH-qpjHUPbKepS33BzjKuRWJ5gN0TYdpfMcdxb9rgjuwwZoeZq_Ccs5VApUarr-pHIkdATr0EMSqAakGYpMYrQKdqEILZDlWXiFNYVfS1PFXiGzn1RTFzECAofg4IKB_YVGrVH4vYfus3LPyWx5Az-EvcgRx8DlcUpYShpM68KqoYfxgRH1hd83mwVB_9B5iAfSy-wsTsroIgAqkXnVCvtjB6GOiySFUf6yYYS71Lk7MHhbmMG3J6PgyUT9Dm6OTMzBjxemyNRwy_ovWXWonqUCy70EYaeLcBEsVhkChNFPgfZ1zOqwCoLpAvi76djfpewtntziD1jajLHz2tL0uxY9dp40cwUpR3YysN8t3svivElKbziGHWDPHgDxtvfPh-Uzk",
    "dp":"bRzYcg5qTH-XRbcj0u4a4wnLvYdjZRxqbIBLMfO2cujpP0xddxLsXFIM8l75NkIuxW0mG_dN01Or6Wo8RdK9JlIJjrnLZrnUab4pnNFowWAOHh4A_uSmPGNtKP350BXLp4XhQgP1XtkLfvf1F0GZ6p4lbHv5vVfUOWZ3VzmYpfUBuFxP_ngxQbG1JHYrGTGsM22mTw51pAt1eNZyVmyzjBARXkL1qTAqUc-RLWdhF5xcQK0AdioNP8pTtHVfXiHmixsKE00CAZXRZ7_FXEq8zRnG8Jc_syyIX9EzoMXDAc0iBkpfGZ87izHZfsBJ6RPNqJ_onIBOTk7_c-y7HoLXtQ",
    "dq":"N5zW0UvE2M7FwsrSgC3bAyhGpcWD2YIBYTNrzEQlKjArGuKzcBZA6JcMqXjUnz6KrBvfGpDvubri3LhWq8EleHhTCVrX-F4YW6QDgA9YqQn7OeLUX3pdAJHZpXJFjP6Mt9KqHNlhag-PFg7u5vqBy-jZv1w-yTquiLbG6kAqzUfMXWMWlao95j6UWh5PbgEsifhXE4KXk_sYSjNC9solt5F3xXaVIOpXA_XZeEhk6wapg-_vvlxFhkk8mBCNutvY93rgqtB_NYd7qPcgdtN2GRvkhqPkpkbnviRyp-04_SFudC9KwwEFI51mmsrWNqXRmScnb4WIPgouizI4hhYLLw",
    "e":"AQAB",
    "ext":true,
    "kty":"RSA",
    "n":"tZ2cIsXXOPCHexnSzJsL9zkeSg7KLfB5r7vFUmaQ0tkAOyXWK1hHDkneBlJx9gfABvBnv4g7yg7JRyP0Kb-NmP8czCPTmhE6VieWq-wLHaMSSu8ek7yL3wfGjhG3ffCCZl95uGvtyoPazrqVfj8CCIB4ai3Dmiu-h1_GBe9050m_q0Lw0thcaiT6s2ZHyAUBu5PBjMfn1TKyOlZ5xM78cIrE3lls-QWaP2h0UoWPaR0veE5JaW4KqGm9vW6OfCch32N4oQZaMce6IIvSA5mtkY0D8YMCrxmjsCANvOpibqebZ1I34MN9_LQTxEr6YPvvROdqzZ9wOMbOP4dpeqaRZkCqm1EUR_-bAfaKPyqLSXiSGHJWSf-wTPQJroPPfd5VBqMqPHCKK1rj0czXkQeVSHetQbhC_sm9Ep6hDqpyM5vlEXynK1Ct0PL-8dGvGjtstLFuGGXXvaQvsEQWQ621iTyVuVc5g6N_bMVyywVDJqMOS-IEQ9h8q1iICCCsTNlr_TacPOEaZR8wdB5hPwdDH85FEw81Z-9BdL9FOd4sketN5SvTaiPeMy9_sUyfSDKOW6iIglPD8HVlo2nmI5OcbdsybQoVISJFfjXl1J_l3AXis_zMEkCqMc2-LsvHdwhvzde-fqhiHPwIOUARAEBj4WDYsepsNS6HiQHI6fjbe4c",
    "p":"1_soBS_nGC1erGWMi7ekZlDKU6Nwb3as6TA092LDr-wNdJKqy92qVrHcsuNFssh_6nFFT5TRICNgO8z7SqkfZHyroE2lZmemJoKO5Uc7YWA0r_tqcDxJpd9t3iR4czw5CqyhqR3lITJkcHNU3lUTsfgBYZTV8K_ucTu4YixVovco58KkLDKgk_uxJmZSht4-tx_YokkyZMHGzPnE8w6PKCZE6RO5TKV2NwUyImGFMSX4kd3pF1zJooQyzjjEa7uHwldtcxmIl0yT-O0yUBbVW0f6U9kAeZSRTZpphtGdIoJYZ1WA_lcWU2Cp3K2qqhJYmNP9tuiOEryw1rxMctII5Q",
    "q":"10RdaiMztGStyPDqGyGKG6jA53ZeyfFwA3WilSzK40bT0dHrJWM3-PvM5tE0VQX4oZUmGCmlOnqiO9VpjjPhe01VE5QuzNlweaHovwqUdLUVXOJabGSGvCsoAzRJHDNfwwaqwpbX0TPdTvkaxsqXkjT52WnEmZU3tXJwa0dtuAl1uoeRNep-FFvo2K6xH2ns2ErkGdm7bGgm6KHstRijcesYCkHAZZmDp_P8Z0TUhUsUd3izHkk10jpBnG-NvjDGbWCLbwuROtfX9_AOACZrVO4TuYvV_6keol0Pzmdn3a76ztck-S1wN3BUzAYAt80zKpMg3cwx1GZXoJKpYYyH-w",
    "qi":"C3a29iAAc-E_gXASeH2dnGvo-X_rG0h4UJEkHPgjTcxa2AC7Kym4eR_X_kNABDnj1aDW3G2HwXBVNKhTDldU0nnaoRPma_6W3Hv_MFg0DdWEuHOJ6lv1kcHSGIdlFwsI8whom7332P2EDYrb4V_cEz1pZNDwbo2yWw2Eyef1kLbNm8TMzNQ1uJACM1JM0jm9KFI9pR_N9fuLY_ulVqXCXngBQ0dnlmVbLB1L9eqnPzue7m4Kz07NZKC46n4bt_Fde5bGXu-7sCzp_kCtUhWO9k39s2M71TlsMlVlIOptohrD2H0HJHMf-8zPnVVXihMu-8stqyPcH_QJ2Pt2YkeEvw"
}"#;

        let the_jwk: jwk::JsonWebKey = jwt_str.parse().unwrap();
        let signer = sign::ArweaveSigner::from_jwk(the_jwk).unwrap();
        let create_options = DataItemCreateOptions {
            target: Base64::default(),
            anchor: Base64::default(),
            tags: Tags {
                tags: vec![BundleTag {
                    name: "Content-Type".to_string(),
                    value: "application/txt".to_string(),
                }],
            },
            //length: 0,
        };

        let mut b =
            BundleItem::new(signer, "dd ee ff".as_bytes().to_vec(), create_options).unwrap();
        b.signature().await.expect("TODO: panic message");
        let mut st = b.binary_stream();
        let mut meta = vec![];
        while let Some(r) = st.next().await {
            meta.extend(r.unwrap())
        }
        let binary = Base64::from(meta.as_slice());

        println!("{:?}", b.signature.to_string());
        println!("{}", binary);
    }

    #[tokio::test]
    async fn test_bundle_item_create_2() {
        let signer = EthSigner::from_prv_hex(
            &"0ba6e4ec4bfa6f02f2027eba34f0fe9f1cc915f14b42d490ebd99bbb90c466e1",
        )
        .unwrap();
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
        };

        let mut b =
            BundleItem::new(signer, "aa bb cc".as_bytes().to_vec(), create_options).unwrap();
        b.signature().await.expect("TODO: panic message");
        let mut st = b.binary_stream();
        let mut meta = vec![];
        while let Some(r) = st.next().await {
            meta.extend(r.unwrap())
        }

        let binary = Base64::from(meta.as_slice());
        println!("{:?}", b.id.to_string());
        println!("{:?}", b.signature.to_string());
        println!("{}", binary);
    }
}
