use arweave_sdk_rs::bundle::bundle::Bundle;
use arweave_sdk_rs::bundle::item::{BundleItem, BundleStreamFactory, DataItemCreateOptions};
use arweave_sdk_rs::bundle::tags::Tags;
use arweave_sdk_rs::client::client::Client;
use arweave_sdk_rs::client::uploader::Uploader;
use arweave_sdk_rs::crypto::base64::Base64;
use arweave_sdk_rs::crypto::sign;
use arweave_sdk_rs::crypto::sign::{EthSigner, Signer};
use arweave_sdk_rs::error::Error;
use arweave_sdk_rs::transaction::tags::Tag;
use arweave_sdk_rs::types::BundleTag;
use std::path::PathBuf;

async fn get_bundle() -> Bundle<PathBuf> {
    let eth_signer = EthSigner::from_prv_hex(
        std::fs::read_to_string(PathBuf::from("tests/fixtures/secp256k1.hex"))
            .unwrap()
            .as_str(),
    )
    .unwrap();

    let item1 = BundleItem::new(
        PathBuf::from("tests/fixtures/1mb.bin"),
        DataItemCreateOptions {
            target: Default::default(),
            anchor: Default::default(),
            tags: Tags {
                tags: vec![
                    BundleTag {
                        name: "File".to_string(),
                        value: "1mb.bin".to_string(),
                    },
                    BundleTag {
                        name: "IPFS-Hash".to_string(),
                        value: "bafybeigqbjyw32q3yefgntbuegq3zx74fk7ygrm2lvk2elbv4d3gzbrllm"
                            .to_string(),
                    },
                ],
            },
            signer: Some(Box::new(eth_signer.clone())),
        },
    )
    .await
    .unwrap();

    let item2 = BundleItem::new(
        PathBuf::from("tests/fixtures/bundle_item_1"),
        DataItemCreateOptions {
            target: Default::default(),
            anchor: Default::default(),
            tags: Tags {
                tags: vec![
                    BundleTag {
                        name: "File".to_string(),
                        value: "bundle_item_1".to_string(),
                    },
                    BundleTag {
                        name: "IPFS-Hash".to_string(),
                        value: "bafkreicuapcbpg7wmkyzxlxh3pumtrhrtxyxkctvve7an7hzytqdcxldgi"
                            .to_string(),
                    },
                ],
            },
            signer: Some(Box::new(eth_signer.clone())),
        },
    )
    .await
    .unwrap();

    let items = vec![item1, item2];
    Bundle::new(items)
}

async fn send_transaction<R: BundleStreamFactory>(bundle: Bundle<R>) -> Result<(), Error> {
    let transaction_signer: Box<dyn Signer> = Box::new(
        sign::ArweaveSigner::from_keypair_path(&"tests/fixtures/arweave_wallet.json").unwrap(),
    );

    let tags = vec![
        Tag {
            name: Base64::from_utf8_str("App-Name").unwrap(),
            value: Base64::from_utf8_str("arweave-sdk-rs").unwrap(),
        },
        Tag {
            name: Base64::from_utf8_str("Website").unwrap(),
            value: Base64::from_utf8_str("4everland.org").unwrap(),
        },
    ];

    let (transaction, chunks_creator) = bundle
        .to_transaction(transaction_signer, tags, Client::default())
        .await
        .unwrap();
    Uploader::new(Client::default())
        .submit(transaction, chunks_creator, 5)
        .await
}
