use super::instance_definitions::{
    builtins_instance_def::BuiltinsInstanceDef, cpu_instance_def::CpuInstanceDef,
    diluted_pool_instance_def::DilutedPoolInstanceDef,
};
pub(crate) struct CairoLayout {
    pub(crate) name: String,
    pub(crate) cpu_component_step: i32,
    pub(crate) rc_units: i32,
    pub(crate) builtins: BuiltinsInstanceDef,
    pub(crate) public_memory_fraction: i32,
    pub(crate) memory_units_per_step: i32,
    pub(crate) diluted_pool_instance_def: Option<DilutedPoolInstanceDef>,
    pub(crate) n_trace_colums: Option<i32>,
    pub(crate) cpu_instance_def: CpuInstanceDef,
}

impl CairoLayout {
    pub(crate) fn plain_instance() -> CairoLayout {
        CairoLayout {
            name: String::from("plain"),
            cpu_component_step: 1,
            rc_units: 16,
            builtins: BuiltinsInstanceDef::plain(),
            public_memory_fraction: 4,
            memory_units_per_step: 8,
            diluted_pool_instance_def: None,
            n_trace_colums: None,
            cpu_instance_def: CpuInstanceDef::default(),
        }
    }

    pub(crate) fn small_instance() -> CairoLayout {
        CairoLayout {
            name: String::from("small"),
            cpu_component_step: 1,
            rc_units: 16,
            builtins: BuiltinsInstanceDef::small(),
            public_memory_fraction: 4,
            memory_units_per_step: 8,
            diluted_pool_instance_def: None,
            n_trace_colums: None,
            cpu_instance_def: CpuInstanceDef::default(),
        }
    }

    pub(crate) fn dex_instance() -> CairoLayout {
        CairoLayout {
            name: String::from("dex"),
            cpu_component_step: 1,
            rc_units: 4,
            builtins: BuiltinsInstanceDef::dex(),
            public_memory_fraction: 4,
            memory_units_per_step: 8,
            diluted_pool_instance_def: None,
            n_trace_colums: Some(22),
            cpu_instance_def: CpuInstanceDef::default(),
        }
    }

    pub(crate) fn perpetual_with_bitwise_instance() -> CairoLayout {
        CairoLayout {
            name: String::from("perpetual_with_bitwise"),
            cpu_component_step: 1,
            rc_units: 4,
            builtins: BuiltinsInstanceDef::perpetual_with_bitwise(),
            public_memory_fraction: 4,
            memory_units_per_step: 8,
            diluted_pool_instance_def: Some(DilutedPoolInstanceDef::new(2, 4, 16)),
            n_trace_colums: Some(10),
            cpu_instance_def: CpuInstanceDef::default(),
        }
    }

    pub(crate) fn bitwise_instance() -> CairoLayout {
        CairoLayout {
            name: String::from("bitwise"),
            cpu_component_step: 1,
            rc_units: 4,
            builtins: BuiltinsInstanceDef::bitwise(),
            public_memory_fraction: 8,
            memory_units_per_step: 8,
            diluted_pool_instance_def: Some(DilutedPoolInstanceDef::default()),
            n_trace_colums: Some(10),
            cpu_instance_def: CpuInstanceDef::default(),
        }
    }

    pub(crate) fn recursive_instance() -> CairoLayout {
        CairoLayout {
            name: String::from("recursive"),
            cpu_component_step: 1,
            rc_units: 4,
            builtins: BuiltinsInstanceDef::recursive(),
            public_memory_fraction: 8,
            memory_units_per_step: 8,
            diluted_pool_instance_def: Some(DilutedPoolInstanceDef::default()),
            n_trace_colums: Some(11),
            cpu_instance_def: CpuInstanceDef::default(),
        }
    }

    pub(crate) fn all_instance() -> CairoLayout {
        CairoLayout {
            name: String::from("all"),
            cpu_component_step: 1,
            rc_units: 8,
            builtins: BuiltinsInstanceDef::all(),
            public_memory_fraction: 8,
            memory_units_per_step: 8,
            diluted_pool_instance_def: Some(DilutedPoolInstanceDef::default()),
            n_trace_colums: Some(27),
            cpu_instance_def: CpuInstanceDef::default(),
        }
    }
}
