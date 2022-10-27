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
}

pub struct BuiltinInstanceDef {
    output: bool,
    pedersen: Option<PedersenInstanceDef>,
    range_check: Option<RangeCheckInstanceDef>,
    ecdsa: Option<EcdsaInstanceDef>,
    bitwise: Option<BitwiseInstanceDef>,
    ec_op: Option<EcOpInstanceDef>,
}
