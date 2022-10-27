pub struct CairoLayout {
    name: String,
    cpu_component_step: i32,
    rc_units: i32,
    builtins: BuiltinsInstanceDef,
    public_memory_fraction: i32,
    memory_units_per_step: i32,
    diluted_pool_instance_def: Option<DilutedPoolInstanceDef>,
    n_trace_colums: Option<i32>,
    cpu_instance_def: CpuInstanceDef,
}

impl CairoLayout {
    fn plain_instance() -> CairoLayout {
        CairoLayout {
            name: "plain",
            cpu_component_step: 1,
            rc_units: 16,
            builtins: BuiltinInstanceDef::plain(),
            public_memory_fraction: 4,
            memory_units_per_step: 8,
            diluted_pool_instance_def: None,
            n_trace_colums: None,
            cpu_instance_def: CpuInstanceDef::default()
        }
    }

    fn small_instance() -> CairoLayout {
        CairoLayout {
            name: "small",
            cpu_component_step: 1,
            rc_units: 16,
            builtins: BuiltinInstanceDef::small(),
            public_memory_fraction: 4,
            memory_units_per_step: 8,
            diluted_pool_instance_def: None,
            n_trace_colums: None,
            cpu_instance_def: CpuInstanceDef::default()
        }
    }

    fn dex_instance() -> CairoLayout {
        CairoLayout {
            name: "dex",
            cpu_component_step: 1,
            rc_units: 4,
            builtins: BuiltinInstanceDef::dex(),
            public_memory_fraction: 4,
            memory_units_per_step: 8,
            diluted_pool_instance_def: None,
            n_trace_colums: Some(22),
            cpu_instance_def: CpuInstanceDef::default()
        }
    }

    fn perpetual_with_bitwise_instance() -> CairoLayout {
        CairoLayout {
            name: "perpetual_with_bitwise",
            cpu_component_step: 1,
            rc_units: 4,
            builtins: BuiltinInstanceDef::perpetual_with_bitwise(),
            public_memory_fraction: 4,
            memory_units_per_step: 8,
            diluted_pool_instance_def: Some(DilutedPoolInstanceDef::perpetual_with_bitwise()),
            n_trace_colums: Some(10),
            cpu_instance_def: CpuInstanceDef::default()
        }
    }

    fn bitwise_instance() -> CairoLayout {
        CairoLayout {
            name: "bitwise",
            cpu_component_step: 1,
            rc_units: 4,
            builtins: BuiltinInstanceDef::bitwise(),
            public_memory_fraction: 8,
            memory_units_per_step: 8,
            diluted_pool_instance_def: Some(DilutedPoolInstanceDef::bitwise()),
            n_trace_colums: Some(10),
            cpu_instance_def: CpuInstanceDef::default()
        }
    }

    fn recursive_instance() -> CairoLayout {
        CairoLayout {
            name: "recursive",
            cpu_component_step: 1,
            rc_units: 4,
            builtins: BuiltinInstanceDef::plain(),
            public_memory_fraction: 8,
            memory_units_per_step: 8,
            diluted_pool_instance_def: Some(DilutedPoolInstanceDef::recursive()),
            n_trace_colums: Some(11),
            cpu_instance_def: CpuInstanceDef::default()
        }
    }

    fn all_instance() -> CairoLayout {
        CairoLayout {
            name: "all",
            cpu_component_step: 1,
            rc_units: 8,
            builtins: BuiltinInstanceDef::all(),
            public_memory_fraction: 8,
            memory_units_per_step: 8,
            diluted_pool_instance_def: Some(DilutedPoolInstanceDef::all()),
            n_trace_colums: Some(27),
            cpu_instance_def: CpuInstanceDef::default()
        }
    }
}

pub struct BuiltinInstanceDef {
    output: bool,
    pedersen: Option<PedersenInstanceDef>,
    range_check: Option<RangeCheckInstanceDef>,
    ecdsa: Option<EcdsaInstanceDef>,
    bitwise: Option<BitwiseInstanceDef>,
    ec_op: Option<EcOpInstanceDef>,
}
