use crate::vm::vm_core::VirtualMachine;

use super::cairo_runner::CairoRunner;

pub struct CairoPie {}

impl CairoRunner {
    pub fn get_cairo_pie(&self, _vm: &VirtualMachine) -> CairoPie {
        CairoPie {}
    }
}
