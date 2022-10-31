use super::instance_definitions::{
    builtins_instance_def::BuiltinsInstanceDef, cpu_instance_def::CpuInstanceDef,
    diluted_pool_instance_def::DilutedPoolInstanceDef,
};

#[derive(Debug)]
pub(crate) struct CairoLayout {
    pub(crate) name: String,
    pub(crate) _cpu_component_step: i32,
    pub(crate) _rc_units: i32,
    pub(crate) builtins: BuiltinsInstanceDef,
    pub(crate) _public_memory_fraction: i32,
    pub(crate) _memory_units_per_step: i32,
    pub(crate) _diluted_pool_instance_def: Option<DilutedPoolInstanceDef>,
    pub(crate) _n_trace_colums: Option<i32>,
    pub(crate) _cpu_instance_def: CpuInstanceDef,
}

impl CairoLayout {
    pub(crate) fn plain_instance() -> CairoLayout {
        CairoLayout {
            name: String::from("plain"),
            _cpu_component_step: 1,
            _rc_units: 16,
            builtins: BuiltinsInstanceDef::plain(),
            _public_memory_fraction: 4,
            _memory_units_per_step: 8,
            _diluted_pool_instance_def: None,
            _n_trace_colums: None,
            _cpu_instance_def: CpuInstanceDef::default(),
        }
    }

    pub(crate) fn small_instance() -> CairoLayout {
        CairoLayout {
            name: String::from("small"),
            _cpu_component_step: 1,
            _rc_units: 16,
            builtins: BuiltinsInstanceDef::small(),
            _public_memory_fraction: 4,
            _memory_units_per_step: 8,
            _diluted_pool_instance_def: None,
            _n_trace_colums: None,
            _cpu_instance_def: CpuInstanceDef::default(),
        }
    }

    pub(crate) fn dex_instance() -> CairoLayout {
        CairoLayout {
            name: String::from("dex"),
            _cpu_component_step: 1,
            _rc_units: 4,
            builtins: BuiltinsInstanceDef::dex(),
            _public_memory_fraction: 4,
            _memory_units_per_step: 8,
            _diluted_pool_instance_def: None,
            _n_trace_colums: Some(22),
            _cpu_instance_def: CpuInstanceDef::default(),
        }
    }

    pub(crate) fn perpetual_with_bitwise_instance() -> CairoLayout {
        CairoLayout {
            name: String::from("perpetual_with_bitwise"),
            _cpu_component_step: 1,
            _rc_units: 4,
            builtins: BuiltinsInstanceDef::perpetual_with_bitwise(),
            _public_memory_fraction: 4,
            _memory_units_per_step: 8,
            _diluted_pool_instance_def: Some(DilutedPoolInstanceDef::new(2, 4, 16)),
            _n_trace_colums: Some(10),
            _cpu_instance_def: CpuInstanceDef::default(),
        }
    }

    pub(crate) fn bitwise_instance() -> CairoLayout {
        CairoLayout {
            name: String::from("bitwise"),
            _cpu_component_step: 1,
            _rc_units: 4,
            builtins: BuiltinsInstanceDef::bitwise(),
            _public_memory_fraction: 8,
            _memory_units_per_step: 8,
            _diluted_pool_instance_def: Some(DilutedPoolInstanceDef::default()),
            _n_trace_colums: Some(10),
            _cpu_instance_def: CpuInstanceDef::default(),
        }
    }

    pub(crate) fn recursive_instance() -> CairoLayout {
        CairoLayout {
            name: String::from("recursive"),
            _cpu_component_step: 1,
            _rc_units: 4,
            builtins: BuiltinsInstanceDef::recursive(),
            _public_memory_fraction: 8,
            _memory_units_per_step: 8,
            _diluted_pool_instance_def: Some(DilutedPoolInstanceDef::default()),
            _n_trace_colums: Some(11),
            _cpu_instance_def: CpuInstanceDef::default(),
        }
    }

    pub(crate) fn all_instance() -> CairoLayout {
        CairoLayout {
            name: String::from("all"),
            _cpu_component_step: 1,
            _rc_units: 8,
            builtins: BuiltinsInstanceDef::all(),
            _public_memory_fraction: 8,
            _memory_units_per_step: 8,
            _diluted_pool_instance_def: Some(DilutedPoolInstanceDef::default()),
            _n_trace_colums: Some(27),
            _cpu_instance_def: CpuInstanceDef::default(),
        }
    }
}
