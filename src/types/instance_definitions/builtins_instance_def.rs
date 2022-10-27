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
            pedersen: PedersenInstanceDef::default(),
            range_check: RangeCheckInstanceDef::default(),
            ecdsa: None,
            bitwise: None,
            ec_op: None,
        }
    }

    pub(crate) fn dex() -> BuiltinsInstanceDef {
        BitwiseInstanceDef {
            output: true,
            pedersen: PedersenInstanceDef::default(),
            range_check: RangeCheckInstanceDef::default(),
            ecdsa: None,
            bitwise: None,
            ec_op: None,
        }
    }

    pub(crate) fn perpetual_with_bitwise() -> BuiltinsInstanceDef {
        BitwiseInstanceDef {
            output: true,
            pedersen: PedersenInstanceDef::new(32, 1),
            range_check: RangeCheckInstanceDef::new(16,8),
            ecdsa: None,
            bitwise: None,
            ec_op: None,
        }
    }

    pub(crate) fn bitwise() -> BuiltinsInstanceDef {
        BitwiseInstanceDef {
            output: true,
            pedersen: PedersenInstanceDef::new(256, 1),
            range_check: RangeCheckInstanceDef::default(),
            ecdsa: None,
            bitwise: None,
            ec_op: None,
        }
    }

    pub(crate) fn recursive() -> BuiltinsInstanceDef {
        BitwiseInstanceDef {
            output: true,
            pedersen: PedersenInstanceDef::new(256, 1),
            range_check: RangeCheckInstanceDef::default(),
            ecdsa: None,
            bitwise: None,
            ec_op: None,
        }
    }

    pub(crate) fn all() -> BuiltinsInstanceDef {
        BitwiseInstanceDef {
            output: true,
            pedersen: PedersenInstanceDef::default(),
            range_check: RangeCheckInstanceDef::default(),
            ecdsa: None,
            bitwise: None,
            ec_op: None,
        }
    }
}
