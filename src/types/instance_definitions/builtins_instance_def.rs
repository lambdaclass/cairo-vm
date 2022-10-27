pub(crate) struct BuiltinInstanceDef {
    output: bool,
    pedersen: Option<PedersenInstanceDef>,
    range_check: Option<RangeCheckInstanceDef>,
    ecdsa: Option<EcdsaInstanceDef>,
    bitwise: Option<BitwiseInstanceDef>,
    ec_op: Option<EcOpInstanceDef>,
}

impl BuiltinInstanceDef {
    pub(crate) fn plain() -> BuiltinsInstanceDef {
        BitwiseInstanceDef {
            output: false,
            pedersen: None,
            range_check: None,
            ecdsa: None,
            bitwise: None,
            ec_op: None,
        }
    }

    pub(crate) fn small() -> BuiltinsInstanceDef {
        BitwiseInstanceDef {
            output: true,
            pedersen: Some(PedersenInstanceDef::default()),
            range_check: Some(RangeCheckInstanceDef::default()),
            ecdsa: Some(EcdsaInstanceDef::default()),
            bitwise: None,
            ec_op: None,
        }
    }

    pub(crate) fn dex() -> BuiltinsInstanceDef {
        BitwiseInstanceDef {
            output: true,
            pedersen: Some(PedersenInstanceDef::default()),
            range_check: Some(RangeCheckInstanceDef::default()),
            ecdsa: Some(EcdsaInstanceDef::default()),
            bitwise: None,
            ec_op: None,
        }
    }

    pub(crate) fn perpetual_with_bitwise() -> BuiltinsInstanceDef {
        BitwiseInstanceDef {
            output: true,
            pedersen: Some(PedersenInstanceDef::new(32, 1)),
            range_check: Some(RangeCheckInstanceDef::new(16,8)),
            ecdsa: Some(EcdsaInstanceDef::new(2048)),
            bitwise: Some(BitwiseInstanceDef::new(64)),
            ec_op: Some(EcOpInstanceDef::new(1024)),
        }
    }

    pub(crate) fn bitwise() -> BuiltinsInstanceDef {
        BitwiseInstanceDef {
            output: true,
            pedersen: Some(PedersenInstanceDef::new(256, 1)),
            range_check: Some(RangeCheckInstanceDef::default()),
            ecdsa: Some(EcdsaInstanceDef::new(1024)),
            bitwise: Some(BitwiseInstanceDef::new(8)),
            ec_op: None,
        }
    }

    pub(crate) fn recursive() -> BuiltinsInstanceDef {
        BitwiseInstanceDef {
            output: true,
            pedersen: Some(PedersenInstanceDef::new(256, 1)),
            range_check: Some(RangeCheckInstanceDef::default()),
            ecdsa: None,
            bitwise: Some(BitwiseInstanceDef::new(16)),
            ec_op: None,
        }
    }

    pub(crate) fn all() -> BuiltinsInstanceDef {
        BitwiseInstanceDef {
            output: true,
            pedersen: Some(PedersenInstanceDef::default()),
            range_check: Some(RangeCheckInstanceDef::default()),
            ecdsa: Some(EcdsaInstanceDef::default()),
            bitwise: Some(BitwiseInstanceDef::default()),
            ec_op: Some(EcOpInstanceDef::default()),
        }
    }
}
