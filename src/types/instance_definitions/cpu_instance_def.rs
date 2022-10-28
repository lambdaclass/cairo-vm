pub(crate) struct CpuInstanceDef {
    pub(crate) _safe_call: bool,
}

impl CpuInstanceDef {
    pub(crate) fn default() -> Self {
        CpuInstanceDef { _safe_call: true }
    }
}
