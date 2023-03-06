pub(crate) const CELLS_PER_POSEIDON: u32 = 6;
pub(crate) const INPUT_CELLS_PER_POSEIDON: u32 = 3;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PoseidonInstanceDef {
    pub(crate) ratio: u32,
}

impl PoseidonInstanceDef {
    pub(crate) fn default() -> Self {
        PoseidonInstanceDef { ratio: 32 }
    }

    pub(crate) fn _new(ratio: u32) -> Self {
        PoseidonInstanceDef { ratio }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let builtin_instance = PoseidonInstanceDef { ratio: 8 };
        assert_eq!(PoseidonInstanceDef::_new(8), builtin_instance);
    }

    #[test]
    fn test_default() {
        let builtin_instance = PoseidonInstanceDef { ratio: 32 };
        assert_eq!(PoseidonInstanceDef::default(), builtin_instance);
    }
}
