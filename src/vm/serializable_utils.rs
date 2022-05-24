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
            Ok(decoded_hex) => Ok(BigInt::from_bytes_be(Sign::Plus, &decoded_hex)),
            Err(e) => Err(e).map_err(de::Error::custom),
        }
    }
}

fn deserialize_bigint_hex<'de, D: Deserializer<'de>>(d: D) -> Result<BigInt, D::Error> {
    d.deserialize_str(BigIntVisitor)
}  

#[cfg(test)]
mod tests {
    use std::{fs::File, io::BufReader};
    use super::*; 
    use crate::bigint;
    use num_traits::FromPrimitive;

    #[derive(Deserialize)]
    struct TestStruct {
        #[serde(deserialize_with = "deserialize_bigint_hex")]
        bigint: BigInt,
    }

    #[test]
    fn deserialize_bigint_from_string_json() {

        let valid_json_data = r#"
            {
                "bigint": "0x000A"
            }"#;
        
        let test_struct: TestStruct = serde_json::from_str(&valid_json_data).unwrap();

        assert_eq!(test_struct.bigint, bigint!(10));
    }

    #[test]
    fn deserialize_bigint_from_string_json_gives_error() {

        let invalid_json_data = r#"
            {
                "bigint": "0bx000A"
            }"#;
        
        let result: Result<TestStruct, _> = serde_json::from_str(&invalid_json_data);

        assert!(result.is_err());
    }

    #[test]
    fn deserialize_bigint_from_file_json() {

        let file = File::open("tests/support/valid_json_data.json").unwrap();
        let mut reader = BufReader::new(file);
        
        let test_struct: TestStruct = serde_json::from_reader(&mut reader).unwrap();

        assert_eq!(test_struct.bigint, bigint!(10));
    }

    #[test]
    fn deserialize_bigint_from_file_json_gives_error() {

        let file = File::open("tests/support/invalid_json_data.json").unwrap();
        let mut reader = BufReader::new(file);
        
        let result: Result<TestStruct, _> = serde_json::from_reader(&mut reader);

        assert!(result.is_err());
    }
}