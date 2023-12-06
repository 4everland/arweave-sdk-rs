use std::io::Read;
use std::ops::DerefMut;
use std::str::FromStr;
use crate::bundle::tags::Tags;
use crate::bundle::converter::ByteArrayConverter;
use crate::bundle::sign::BundleSigner;
use crate::crypto::hash::{deep_hash, deep_hash_reader, DeepHashItem, Hasher, ToItems};
use crate::error::Error;
use crate::crypto::base64::Base64;
use crate::crypto::reader::TransactionReader;
use crate::crypto::sign::Signer;

pub struct BundleItem<T: Signer + BundleSigner> {
    pub signature_type: u8,
    pub signature: Base64,
    pub owner: Base64,
    pub target: Base64,
    pub anchor: Base64,
    pub tags: Tags,
    pub id: Base64,
    item: Box<dyn TransactionReader>,
    signer: T,
}

pub struct DataItemCreateOptions {
    pub target: Base64,
    pub anchor: Base64,
    pub tags: Tags,
}

impl<T: Signer + BundleSigner> BundleItem<T> {
    pub fn new<R: TransactionReader + 'static>(s: T, r: Box<R>, o: DataItemCreateOptions) -> BundleItem<T> {
        return BundleItem {
            signature_type: s.signature_type(),
            signature: Default::default(),
            owner: s.public_key().unwrap(),
            target: Default::default(),
            anchor: Default::default(),
            tags: o.tags,
            id: Default::default(),
            item: r,
            signer: s,
        };
    }

    async fn signature(&mut self) -> Result<(), Error> {
        let h = deep_hash(self.to_deep_hash_item().await.unwrap());
        let signature = self.signer.sign(h.as_slice()).map_err(|e| Error::SigningError(e.to_string()))?;

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
        ].into_iter().map(|op| DeepHashItem::from_item(&op.0)).collect();
        data.push(DeepHashItem::Origin(deep_hash_reader(self.item.deref_mut()).await));
        Ok(DeepHashItem::from_children(data))
    }


    //todo
    pub async fn binary_length(&mut self) -> Result<usize, Error> {
        let _owner = self.signer.public_key().unwrap();
        let data_length = self.item.length().await.unwrap();

        Ok(2 + self.signature.0.len()
            + _owner.0.len()
            + 1 + self.target.0.len()
            + 1 + self.anchor.0.len()
            + 16 + Base64::from(&self.tags).0.len()
            + data_length)
    }

    pub async fn get_binary(&mut self) -> Result<Vec<u8>, Error> {
        self.item.read_all().await
    }


    //todo error
    async fn create(&mut self) -> Result<Vec<u8>, Error> {
        let _owner = self.signer.public_key().unwrap();

        let target_length = 1 + self.target.0.len();
        let anchor_length = 1 + self.anchor.0.len();

        let tags_length = 16 + Base64::from(&self.tags).0.len();

        let data_length = self.item.length().await.unwrap();

        let length = 2
            + self.signature.0.len()
            + _owner.0.len()
            + target_length
            + anchor_length
            + tags_length
            + data_length;
        let mut bytes = vec![0; length];

        bytes[0..2].copy_from_slice(&ByteArrayConverter::short_to_2_byte_array(self.signature_type as u64));
        bytes[2..(2 + self.signature.0.len())].copy_from_slice(&self.signature.0);
        // if _owner.len() != signer.owner_length() {
        //     // return "Owner must be {} bytes, but was incorrectly {}", signer.owner_length(),  _owner.len()
        // }
        bytes[(2 + self.signature.0.len())..(2 + self.signature.0.len() + _owner.0.len())]
            .copy_from_slice(_owner.0.as_slice());

        let position = 2 + self.signature.0.len() + _owner.0.len();
        bytes[position] = !self.target.is_empty() as u8;
        if !self.target.is_empty() {
            if self.target.0.len() != 32 {
                // return Err()//Target must be 32 bytes;
            }
            bytes[(position + 1)..(position + 33)].copy_from_slice(&self.target.0);
        }

        let anchor_start = position + target_length;
        let mut tags_start = anchor_start + 1;
        bytes[anchor_start] = !self.anchor.is_empty() as u8;
        if !self.anchor.is_empty() {
            tags_start += self.anchor.0.len();
            if self.anchor.0.len() != 32 {
                // return Err()//Anchor must be 32 bytes
            }
            bytes[(anchor_start + 1)..(anchor_start + 33)].copy_from_slice(&self.anchor.0);
        }

        bytes[tags_start..(tags_start + 8)].copy_from_slice(
            &ByteArrayConverter::long_to_8_byte_array(self.tags.tags.len() as u64),
        );

        let tags = Base64::from(&self.tags).0;
        bytes[tags_start + 8..(tags_start + 16)].copy_from_slice(
            &ByteArrayConverter::long_to_8_byte_array(tags.len() as u64),
        );
        if !self.tags.tags.is_empty() {
            bytes[(tags_start + 16)..(tags_start + tags_length)].copy_from_slice(&tags);
        }

        let data_start = tags_start + tags_length;
        bytes[data_start..].copy_from_slice((&self.item.chunk_read(0, data_length).await.unwrap()).as_ref());
        Ok(bytes)
    }
}

// impl<'a, T> ToItems<'a, BundleItem<T>> for BundleItem<T> where T: Signer {
//     async fn to_deep_hash_item(&'a self) -> Result<DeepHashItem, Error> {
//         let mut data: Vec<DeepHashItem> = vec![
//             Base64::from_utf8_str("dataitem").unwrap(),
//             Base64::from_utf8_str("1").unwrap(),
//             Base64::from_utf8_str(self.signature_type.to_string().as_str()).unwrap(),
//             self.owner.clone(),
//             self.target.clone(),
//             self.anchor.clone(),
//             Base64::from(&self.tags),
//         ].into_iter().map(|op| DeepHashItem::from_item(&op.0)).collect();
//         data.push(DeepHashItem::Origin(deep_hash_reader(&self.item).await));
//         Ok(DeepHashItem::List(data))
//     }
// }

#[cfg(test)]
mod tests {
    extern crate jsonwebkey as jwk;

    use crate::bundle::item::{BundleItem, DataItemCreateOptions};
    use crate::bundle::tags::Tags;
    use crate::crypto::base64::Base64;
    use crate::crypto::sign;
    use crate::crypto::sign::EthSigner;
    use crate::types::{BundleTag};

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
                tags: vec![
                    BundleTag { name: "Content-Type".to_string(), value: "application/txt".to_string() },
                ]
            },
        };


        let mut b = BundleItem::new(signer, Box::new("dd ee ff".as_bytes()), create_options);
        b.signature().await.expect("TODO: panic message");
        let meta = b.create();
        let binary = Base64::from(meta.await.unwrap().as_slice());

        println!("{:?}", b.signature.to_string());
        println!("{}", binary);
    }

    #[tokio::test]
    async fn test_bundle_item_create_2() {
        let signer = EthSigner::from_prv_hex(&"0ba6e4ec4bfa6f02f2027eba34f0fe9f1cc915f14b42d490ebd99bbb90c466e1").unwrap();
        let create_options = DataItemCreateOptions {
            target: Base64::default(),
            anchor: Base64::default(),
            tags: Tags {
                tags: vec![
                    BundleTag { name: "Content-Type".to_string(), value: "application/txt".to_string() },
                    BundleTag { name: "App-Version".to_string(), value: "2.0.0".to_string() },
                ]
            },
        };


        let mut b = BundleItem::new(signer, Box::new("aa bb cc".as_bytes()), create_options);
        b.signature().await.expect("TODO: panic message");
        let meta = b.create().await;

        let binary = Base64::from(meta.unwrap().as_slice());
        println!("{:?}", b.id.to_string());
        println!("{:?}", b.signature.to_string());
        println!("{}", binary);
    }
}