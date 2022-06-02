use crate::types::relocatable::MaybeRelocatable;
use num_bigint::{BigInt, Sign};
use serde::de;
use serde::de::SeqAccess;
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

struct MaybeRelocatableVisitor;

impl<'de> de::Visitor<'de> for MaybeRelocatableVisitor {
    type Value = Vec<MaybeRelocatable>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a list of hexadecimals")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut data: Vec<MaybeRelocatable> = vec![];

        while let Some(value) = seq.next_element::<&str>()? {
            if let Some(no_prefix_hex) = value.strip_prefix("0x") {
                // Add padding if necessary
                let no_prefix_hex = maybe_add_padding(no_prefix_hex.to_string());
                let decoded_result: Result<Vec<u8>, hex::FromHexError> =
                    hex::decode(&no_prefix_hex);

                match decoded_result {
                    Ok(decoded_hex) => data.push(MaybeRelocatable::Int(BigInt::from_bytes_be(
                        Sign::Plus,
                        &decoded_hex,
                    ))),
                    Err(e) => return Err(e).map_err(de::Error::custom),
                    // panic!("failt to decode data hex"),
                };
            } else {
                // Err(_e) => panic!("failt to decode data hex"),
                return Err(String::from("hex prefix error")).map_err(de::Error::custom);
            };
        }
        Ok(data)
    }
}

// This directive should be removed once the entire Program struct is deserializable and the
// '#[derive(Deserialize)]' directive can be applied to it.
#[allow(dead_code)]
pub fn deserialize_bigint_hex<'de, D: Deserializer<'de>>(d: D) -> Result<BigInt, D::Error> {
    d.deserialize_str(BigIntVisitor)
}

#[allow(dead_code)]
pub fn deserialize_maybe_relocatable<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<MaybeRelocatable>, D::Error> {
    d.deserialize_seq(MaybeRelocatableVisitor)
}

// Checks if the hex string has an odd length.
// If that is the case, prepends '0' to it.
fn maybe_add_padding(mut hex: String) -> String {
    if hex.len().rem(2) != 0 {
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
        builtins: Vec<String>,
        #[serde(deserialize_with = "deserialize_maybe_relocatable")]
        data: Vec<MaybeRelocatable>,
    }

    #[test]
    fn deserialize_from_string_json() {
        let valid_even_length_hex_json = r#"
            {
                "bigint": "0x000A",
                "builtins": [],
                "data": [
                    "0x480680017fff8000",
                    "0x3e8",
                    "0x480680017fff8000",
                    "0x7d0",
                    "0x48307fff7ffe8000",
                    "0x208b7fff7fff7ffe"
                ]            
            }"#;

        // TestStruct instance for the json with an even length encoded hex.
        let even_test_struct: TestStruct =
            serde_json::from_str(&valid_even_length_hex_json).unwrap();

        let builtins: Vec<String> = Vec::new();

        let data: Vec<MaybeRelocatable> = vec![
            MaybeRelocatable::Int(BigInt::parse_bytes(b"5189976364521848832", 10).unwrap()),
            MaybeRelocatable::Int(BigInt::parse_bytes(b"1000", 10).unwrap()),
            MaybeRelocatable::Int(BigInt::parse_bytes(b"5189976364521848832", 10).unwrap()),
            MaybeRelocatable::Int(BigInt::parse_bytes(b"2000", 10).unwrap()),
            MaybeRelocatable::Int(BigInt::parse_bytes(b"5201798304953696256", 10).unwrap()),
            MaybeRelocatable::Int(BigInt::parse_bytes(b"2345108766317314046", 10).unwrap()),
        ];

        assert_eq!(even_test_struct.bigint, bigint!(10));
        assert_eq!(even_test_struct.builtins, builtins);
        assert_eq!(even_test_struct.data, data);

        let valid_odd_length_hex_json = r#"
            {
                "bigint": "0x00A",
                "builtins": ["output","pedersen"],
                "data": [
                    "0x480680017fff8000",
                    "0x3",
                    "0x480680017fff8000",
                    "0x7",
                    "0x48307fff7ffe8000",
                    "0x208b7fff7fff7ffe"
                ]
            }"#;

        // TestStruct instance for the json with an odd length encoded hex.
        let odd_test_struct: TestStruct = serde_json::from_str(&valid_odd_length_hex_json).unwrap();
        let builtins: Vec<String> = vec![String::from("output"), String::from("pedersen")];

        let data: Vec<MaybeRelocatable> = vec![
            MaybeRelocatable::Int(BigInt::parse_bytes(b"5189976364521848832", 10).unwrap()),
            MaybeRelocatable::Int(BigInt::parse_bytes(b"3", 10).unwrap()),
            MaybeRelocatable::Int(BigInt::parse_bytes(b"5189976364521848832", 10).unwrap()),
            MaybeRelocatable::Int(BigInt::parse_bytes(b"7", 10).unwrap()),
            MaybeRelocatable::Int(BigInt::parse_bytes(b"5201798304953696256", 10).unwrap()),
            MaybeRelocatable::Int(BigInt::parse_bytes(b"2345108766317314046", 10).unwrap()),
        ];

        assert_eq!(odd_test_struct.bigint, bigint!(10));
        assert_eq!(odd_test_struct.builtins, builtins);
        assert_eq!(odd_test_struct.data, data);
    }

    #[test]
    fn deserialize_bigint_from_string_json_gives_error() {
        let invalid_even_length_hex_json = r#"
            {
                "bigint": "0bx000A",
                "builtins": []
            }"#;

        // TestStruct result instance for the json with an even length encoded hex.
        let even_result: Result<TestStruct, _> =
            serde_json::from_str(&invalid_even_length_hex_json);

        assert!(even_result.is_err());

        let invalid_odd_length_hex_json = r#"
            {
                "bigint": "0bx00A",
                "builtins": []
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
        let builtins: Vec<String> = vec![String::from("output")];

        assert_eq!(even_test_struct.bigint, bigint!(10));
        assert_eq!(even_test_struct.builtins, builtins);

        // Open json file with (valid) odd length encoded hex
        let odd_length_file = File::open("tests/support/valid_odd_length_hex.json").unwrap();
        let mut reader = BufReader::new(odd_length_file);

        let odd_test_struct: TestStruct = serde_json::from_reader(&mut reader).unwrap();
        let builtins: Vec<String> = Vec::new();

        assert_eq!(odd_test_struct.bigint, bigint!(10));
        assert_eq!(odd_test_struct.builtins, builtins);
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
