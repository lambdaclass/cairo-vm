use serde::{Deserialize, Deserializer};
use num_bigint::{BigInt, Sign};
use serde::de;
use std::fmt;

struct BigIntVisitor;

impl<'de> de::Visitor<'de> for BigIntVisitor {
    type Value = BigInt;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a hexadecimal string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let decoded_result: Result<Vec<u8>, prefix_hex::Error> = prefix_hex::decode(value);

        match decoded_result {
            Ok(decoded_hex) => Ok(BigInt::from_bytes_le(Sign::Plus, &decoded_hex)),
            Err(e) => Err(e).map_err(de::Error::custom),
        }
    }
}

fn deserialize_bigint_hex<'de, D: Deserializer<'de>>(d: D) -> Result<BigInt, D::Error> {
    d.deserialize_str(BigIntVisitor)
}  
