pub(crate) struct CpuInstanceDef {
    pub(crate) safe_call: bool,
}

impl CpuInstanceDef {
    pub(crate) fn default() -> Self {
        CpuInstanceDef { safe_call: true }
    }
}
