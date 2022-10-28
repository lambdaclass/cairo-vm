use super::{
    bitwise_instance_def::BitwiseInstanceDef, ec_op_instance_def::EcOpInstanceDef,
    ecdsa_instance_def::EcdsaInstanceDef, pedersen_instance_def::PedersenInstanceDef,
    range_check_instance_def::RangeCheckInstanceDef,
};

pub(crate) struct BuiltinsInstanceDef {
    pub(crate) _output: bool,
    pub(crate) pedersen: Option<PedersenInstanceDef>,
    pub(crate) range_check: Option<RangeCheckInstanceDef>,
    pub(crate) _ecdsa: Option<EcdsaInstanceDef>,
    pub(crate) bitwise: Option<BitwiseInstanceDef>,
    pub(crate) ec_op: Option<EcOpInstanceDef>,
}

impl BuiltinsInstanceDef {
    pub(crate) fn plain() -> BuiltinsInstanceDef {
        BuiltinsInstanceDef {
            _output: false,
            pedersen: None,
            range_check: None,
            _ecdsa: None,
            bitwise: None,
            ec_op: None,
        }
    }

    pub(crate) fn small() -> BuiltinsInstanceDef {
        BuiltinsInstanceDef {
            _output: true,
            pedersen: Some(PedersenInstanceDef::default()),
            range_check: Some(RangeCheckInstanceDef::default()),
            _ecdsa: Some(EcdsaInstanceDef::default()),
            bitwise: None,
            ec_op: None,
        }
    }

    pub(crate) fn dex() -> BuiltinsInstanceDef {
        BuiltinsInstanceDef {
            _output: true,
            pedersen: Some(PedersenInstanceDef::default()),
            range_check: Some(RangeCheckInstanceDef::default()),
            _ecdsa: Some(EcdsaInstanceDef::default()),
            bitwise: None,
            ec_op: None,
        }
    }

    pub(crate) fn perpetual_with_bitwise() -> BuiltinsInstanceDef {
        BuiltinsInstanceDef {
            _output: true,
            pedersen: Some(PedersenInstanceDef::new(32, 1)),
            range_check: Some(RangeCheckInstanceDef::new(16, 8)),
            _ecdsa: Some(EcdsaInstanceDef::new(2048)),
            bitwise: Some(BitwiseInstanceDef::new(64)),
            ec_op: Some(EcOpInstanceDef::new(1024)),
        }
    }

    pub(crate) fn bitwise() -> BuiltinsInstanceDef {
        BuiltinsInstanceDef {
            _output: true,
            pedersen: Some(PedersenInstanceDef::new(256, 1)),
            range_check: Some(RangeCheckInstanceDef::default()),
            _ecdsa: Some(EcdsaInstanceDef::new(1024)),
            bitwise: Some(BitwiseInstanceDef::new(8)),
            ec_op: None,
        }
    }

    pub(crate) fn recursive() -> BuiltinsInstanceDef {
        BuiltinsInstanceDef {
            _output: true,
            pedersen: Some(PedersenInstanceDef::new(256, 1)),
            range_check: Some(RangeCheckInstanceDef::default()),
            _ecdsa: None,
            bitwise: Some(BitwiseInstanceDef::new(16)),
            ec_op: None,
        }
    }

    pub(crate) fn all() -> BuiltinsInstanceDef {
        BuiltinsInstanceDef {
            _output: true,
            pedersen: Some(PedersenInstanceDef::default()),
            range_check: Some(RangeCheckInstanceDef::default()),
            _ecdsa: Some(EcdsaInstanceDef::default()),
            bitwise: Some(BitwiseInstanceDef::default()),
            ec_op: Some(EcOpInstanceDef::default()),
        }
    }
}
