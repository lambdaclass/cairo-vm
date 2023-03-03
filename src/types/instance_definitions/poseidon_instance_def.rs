#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PoseidonInstanceDef {
    pub(crate) ratio: u32,
    pub(crate) partial_rounds_partition: Vec<u32>,
}

impl PoseidonInstanceDef {
    pub(crate) fn default() -> Self {
        PoseidonInstanceDef {
            ratio: 32,
            partial_rounds_partition: vec![64, 22],
        }
    }

    pub(crate) fn _new(ratio: u32, partial_rounds_partition: Vec<u32>) -> Self {
        PoseidonInstanceDef {
            ratio,
            partial_rounds_partition,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let builtin_instance = PoseidonInstanceDef {
            ratio: 8,
            partial_rounds_partition: vec![1, 2],
        };
        assert_eq!(PoseidonInstanceDef::_new(8, vec![1, 2]), builtin_instance);
    }

    #[test]
    fn test_default() {
        let builtin_instance = PoseidonInstanceDef {
            ratio: 32,
            partial_rounds_partition: vec![64, 22],
        };
        assert_eq!(PoseidonInstanceDef::default(), builtin_instance);
    }
}
