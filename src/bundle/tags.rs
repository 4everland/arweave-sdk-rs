use lazy_static::lazy_static;
use serde::{Deserialize, Serialize, Serializer, Deserializer, ser::Error};
use apache_avro::{Schema, from_avro_datum, types::Value, types::Value::{Array, Bytes, Record}, from_value, to_value, to_avro_datum};
use crate::crypto::{base64::Base64, hash::Hasher};
use crate::types::{BundleTag as Tag};

const SCHEMA_STR: &str = r#"{"type": "array", "items": {"type": "record", "name": "Tag", "fields": [{"name": "name", "type": "string"}, {"name": "value", "type": "string"}]}}"#;

lazy_static! {
    static ref SCHEMA: Schema = Schema::parse_str(SCHEMA_STR).unwrap();
}
#[derive(Debug, Eq, PartialEq)]
pub struct Tags {
    pub tags: Vec<Tag>,
}

impl Tags {
    pub fn get_tag_value(&self, name: &str) -> String {
        for tag in &self.tags {
            match tag.name == name {
                true => return tag.value.clone(),
                false => continue,
            }
        }
        String::new()
    }
}

impl From<&Tags> for Base64 {
    fn from(value: &Tags) -> Self {
        match to_value(value) {
            Ok(Bytes(v)) => Base64::from(v.as_slice()),
            _ => Base64::empty()
        }
    }
}

impl Serialize for Tags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        if self.tags.is_empty() {
            return serializer.serialize_none();
        }

        let values = Array(self.tags.iter().map(|t| Record(vec![
            ("name".to_owned(), Value::String(t.name.clone())),
            ("value".to_owned(), Value::String(t.value.clone())),
        ])).collect());

        let serialized_tags = to_avro_datum(&*SCHEMA, values).map_err(Error::custom)?;
        serializer.serialize_bytes(serialized_tags.clone().as_slice()).map_err(Error::custom)
    }
}


impl<'de> Deserialize<'de> for Tags {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct TagsVisitor;

        impl<'de> serde::de::Visitor<'de> for TagsVisitor {
            type Value = Tags;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("deserialize bundle tags error")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E> where E: serde::de::Error {
                let decoded_datum = from_avro_datum(&*SCHEMA, &mut Box::new(v), Some(&*SCHEMA)).map_err(serde::de::Error::custom)?;
                match decoded_datum {
                    Array(values) => {
                        let mut tags = Vec::new();
                        for tag in values {
                            let t = from_value::<Tag>(&tag).map_err(serde::de::Error::custom)?;
                            tags.push(t);
                        }

                        Ok(Self::Value { tags })
                    }
                    _ => {
                        Err(serde::de::Error::custom("wrong tag type"))
                    }
                }
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E> where E: serde::de::Error {
                self.visit_bytes(v.as_slice())
            }
        }
        deserializer.deserialize_byte_buf(TagsVisitor)
    }
}

#[cfg(test)]
mod tests {
    use crate::bundle::tags::Tags;
    use crate::types::{BundleTag as Tag};
    use apache_avro::{to_value, from_value, types::Value};

    fn setup() -> Tags {
        let mut tags = Tags {
            tags: vec![
                Tag {
                    name: String::from("tag1"),
                    value: String::from("value1"),
                },
                Tag {
                    name: String::from("tag2"),
                    value: String::from("value2"),
                },
                Tag {
                    name: String::from("tag3"),
                    value: String::from("value3"),
                },
            ],
        };

        tags
    }

    #[test]
    fn test_serialize_deserialize_tags() {
        let mut tags = setup();
        let v = to_value(&tags).unwrap();
        let empty = Value::Union(0, Box::new(Value::Null));
        assert_ne!(Tags { tags: vec![] }, tags);
        let deserialized = from_value::<Tags>(&v).unwrap();
        assert_eq!(deserialized, tags);
    }

    #[test]
    fn test_get_tag_value() {
        let mut tags = setup();
        assert_eq!(tags.get_tag_value("tag2"), "value2");
        assert_eq!(tags.get_tag_value("tag4"), "");

        tags.tags.push(Tag {
            name: String::from("tag4"),
            value: String::from("value4"),
        });

        assert_eq!(tags.get_tag_value("tag4"), "value4");
    }
}