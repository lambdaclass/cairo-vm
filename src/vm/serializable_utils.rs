use num_bigint::{BigInt, Sign};
use serde::de;
use serde::Deserializer;
use std::{fmt, ops::Rem};

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
        // Strip the '0x' prefix from the encoded hex string
        if let Some(no_prefix_hex) = value.strip_prefix("0x") {
            // Add padding if necessary
            let no_prefix_hex = maybe_add_padding(no_prefix_hex.to_string());
            let decoded_result: Result<Vec<u8>, hex::FromHexError> = hex::decode(&no_prefix_hex);

            match decoded_result {
                Ok(decoded_hex) => Ok(BigInt::from_bytes_be(Sign::Plus, &decoded_hex)),
                Err(e) => Err(e).map_err(de::Error::custom),
            }
        } else {
            Err(String::from("hex prefix error")).map_err(de::Error::custom)
        }
    }
}

// This directive should be removed once the entire Program struct is deserializable and the
// '#[derive(Deserialize)]' directive is could be applied to it.
#[allow(dead_code)]
pub fn deserialize_bigint_hex<'de, D: Deserializer<'de>>(d: D) -> Result<BigInt, D::Error> {
    d.deserialize_str(BigIntVisitor)
}

// Checks if the hex string has an odd length.
// If that is the case, prepends '0' to it.
fn maybe_add_padding(mut hex: String) -> String {
    if !(hex.len().rem(2) == 0) {
        hex.insert(0, '0');
        return hex;
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint;
    use num_traits::FromPrimitive;
    use serde::Deserialize;
    use std::{fs::File, io::BufReader};

    #[derive(Deserialize)]
    struct TestStruct {
        #[serde(deserialize_with = "deserialize_bigint_hex")]
        bigint: BigInt,
    }

    #[test]
    fn deserialize_bigint_from_string_json() {
        let valid_even_length_hex_json = r#"
            {
                "bigint": "0x000A"
            }"#;

        // TestStruct instance for the json with an even length encoded hex.
        let even_test_struct: TestStruct =
            serde_json::from_str(&valid_even_length_hex_json).unwrap();

        assert_eq!(even_test_struct.bigint, bigint!(10));

        let valid_odd_length_hex_json = r#"
            {
                "bigint": "0x00A"
            }"#;

        // TestStruct instance for the json with an odd length encoded hex.
        let odd_test_struct: TestStruct = serde_json::from_str(&valid_odd_length_hex_json).unwrap();

        assert_eq!(odd_test_struct.bigint, bigint!(10));
    }

    #[test]
    fn deserialize_bigint_from_string_json_gives_error() {
        let invalid_even_length_hex_json = r#"
            {
                "bigint": "0bx000A"
            }"#;

        // TestStruct result instance for the json with an even length encoded hex.
        let even_result: Result<TestStruct, _> =
            serde_json::from_str(&invalid_even_length_hex_json);

        assert!(even_result.is_err());

        let invalid_odd_length_hex_json = r#"
            {
                "bigint": "0bx00A"
            }"#;

        // TestStruct result instance for the json with an odd length encoded hex.
        let odd_result: Result<TestStruct, _> = serde_json::from_str(&invalid_odd_length_hex_json);

        assert!(odd_result.is_err());
    }

    #[test]
    fn deserialize_bigint_from_file_json() {
        // Open json file with (valid) even length encoded hex
        let even_length_file = File::open("tests/support/valid_even_length_hex.json").unwrap();
        let mut reader = BufReader::new(even_length_file);

        let even_test_struct: TestStruct = serde_json::from_reader(&mut reader).unwrap();

        assert_eq!(even_test_struct.bigint, bigint!(10));

        // Open json file with (valid) odd length encoded hex
        let odd_length_file = File::open("tests/support/valid_odd_length_hex.json").unwrap();
        let mut reader = BufReader::new(odd_length_file);

        let odd_test_struct: TestStruct = serde_json::from_reader(&mut reader).unwrap();

        assert_eq!(odd_test_struct.bigint, bigint!(10));
    }

    #[test]
    fn deserialize_bigint_from_file_json_gives_error() {
        // Open json file with (invalid) even length encoded hex
        let even_length_file = File::open("tests/support/invalid_even_length_hex.json").unwrap();
        let mut reader = BufReader::new(even_length_file);

        let even_result: Result<TestStruct, _> = serde_json::from_reader(&mut reader);

        assert!(even_result.is_err());

        // Open json file with (invalid) odd length encoded hex
        let odd_length_file = File::open("tests/support/invalid_odd_length_hex.json").unwrap();
        let mut reader = BufReader::new(odd_length_file);

        let odd_result: Result<TestStruct, _> = serde_json::from_reader(&mut reader);

        assert!(odd_result.is_err());
    }
}
