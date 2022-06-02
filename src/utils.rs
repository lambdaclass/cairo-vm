#[macro_export]
macro_rules! bigint {
    ($val : expr) => {
        BigInt::from_i32($val).unwrap()
    };
}

#[macro_export]
macro_rules! bigint64 {
    ($val : expr) => {
        BigInt::from_i64($val).unwrap()
    };
}

#[macro_export]
macro_rules! bigint_str {
    ($val: expr) => {
        //BigInt::from_bytes_be(Sign::Plus, $val.chars().map(|c| c.to_digit(10).unwrap()).collect())
        BigInt::parse_bytes($val, 10).unwrap()
    };
}

#[macro_export]
macro_rules! relocatable {
    ($val1 : expr, $val2 : expr) => {
        Relocatable {
            segment_index: bigint!($val1),
            offset: bigint!($val2),
        }
    };
}

pub fn is_subsequence<T: PartialEq>(subsequence: &[T], mut sequence: &[T]) -> bool {
    for search in subsequence {
        if let Some(index) = sequence.iter().position(|element| search == element) {
            sequence = &sequence[index + 1..];
        } else {
            return false;
        }
    }
    true
}

pub fn from_relocatable_to_indexes(relocatable: Relocatable) -> (usize, usize) {
    return (relocatable.segment_index, relocatable.offset);
}
