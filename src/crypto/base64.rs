use crate::error::Error;
use base64::{engine::general_purpose, Engine as _};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct Base64(pub Vec<u8>);

impl std::fmt::Display for Base64 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let string = general_purpose::URL_SAFE_NO_PAD.encode(&self.0);
        write!(f, "{}", string)
    }
}

impl TryFrom<String> for Base64 {
    type Error = base64::DecodeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let result = general_purpose::URL_SAFE_NO_PAD.decode(value)?;
        Ok(Self(result))
    }
}

impl From<&[u8]> for Base64 {
    fn from(u: &[u8]) -> Self {
        Base64(u.to_vec())
    }
}

impl FromStr for Base64 {
    type Err = base64::DecodeError;
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        let result = general_purpose::URL_SAFE_NO_PAD.decode(str)?;
        Ok(Self(result))
    }
}

impl Base64 {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn from_utf8_str(str: &str) -> Result<Self, Error> {
        Ok(Self(str.as_bytes().to_vec()))
    }
    pub fn to_utf8_string(&self) -> Result<String, Error> {
        String::from_utf8(self.0.clone()).map_err(Error::FromUtf8Error)
    }

    pub fn empty() -> Self {
        Base64(vec![])
    }
}

impl Serialize for Base64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format!("{}", &self))
    }
}

//TODO: remove unwraps
impl<'de> Deserialize<'de> for Base64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Vis;
        impl de::Visitor<'_> for Vis {
            type Value = Base64;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a base64 string")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                general_purpose::URL_SAFE_NO_PAD
                    .decode(v)
                    .map(Base64)
                    .map_err(|_| de::Error::custom("failed to decode base64 string"))
            }
        }
        deserializer.deserialize_str(Vis)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::crypto::base64::Base64;

    #[test]
    fn test_deserialize_base64() {
        let base_64 = Base64(vec![44; 7]);
        assert_eq!(base_64.0, vec![44; 7]);
        assert_eq!(format!("{}", base_64), "LCwsLCwsLA");

        let base_64: Base64 = serde_json::from_str("\"LCwsLCwsLA\"").unwrap();
        assert_eq!(base_64.0, vec![44; 7]);
        assert_eq!(format!("{}", base_64), "LCwsLCwsLA");
    }

    #[test]
    fn test_base64_convert_utf8() {
        let foo_b64 = Base64::from_utf8_str("foo").unwrap();
        assert_eq!(foo_b64.0, vec![102, 111, 111]);

        let foo_b64 = Base64(vec![102, 111, 111]);
        assert_eq!(foo_b64.to_utf8_string().unwrap(), "foo".to_string());
    }

    #[test]
    fn test_base64_convert_string() {
        let foo_b64 = Base64::from_str("LCwsLCwsLA").unwrap();
        assert_eq!(foo_b64.0, vec![44; 7]);

        let foo_b64 = Base64(vec![44; 7]);
        assert_eq!(foo_b64.to_string(), "LCwsLCwsLA".to_string());
    }
}
