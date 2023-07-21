pub mod deserialize_program;
mod deserialize_utils;

pub(crate) fn from_slice<'a, T>(v: &'a [u8]) -> serde_json::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    #[cfg(not(feature = "std"))]
    let res = serde_json::from_slice(v);

    #[cfg(feature = "std")]
    let res = {
        let mut copy = v.to_vec();
        simd_json::from_slice(&mut copy).map_err(|e| serde::de::Error::custom(e.to_string()))
    };

    res
}

#[cfg(test)]
pub(crate) fn from_str<'a, T>(s: &'a str) -> serde_json::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    #[cfg(not(feature = "std"))]
    let res = serde_json::from_str(s);

    #[cfg(feature = "std")]
    let res = {
        let mut copy = s.as_bytes().to_vec();
        simd_json::from_slice(&mut copy).map_err(|e| serde::de::Error::custom(e.to_string()))
    };

    res
}
