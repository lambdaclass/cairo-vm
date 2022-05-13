#[macro_export]
macro_rules! bigint {
    ($val : expr) => {
        BigInt::from_i32($val).unwrap()
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
