use crate::serde::deserialize_program::ApTracking;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::execute_hint::HintReference;
use crate::vm::vm_core::VMProxy;
use num_bigint::BigInt;
use std::any::Any;
use std::collections::HashMap;

use super::exec_scope::ExecutionScopesProxy;

pub struct HintProcessorData {
    pub code: String,
    pub ap_tracking: ApTracking,
    pub ids_data: HashMap<String, HintReference>,
}
pub trait HintExecutor {
    fn execute_hint(
        &self,
        vm_proxy: &mut VMProxy,
        exec_scopes_proxy: &mut ExecutionScopesProxy,
        hint_data: &Box<dyn Any>,
    ) -> Result<(), VirtualMachineError>;

    fn compile_hint(
        &self,
        hint_code: String,
        ap_tracking_data: &ApTracking,
        reference_ids: &HashMap<String, BigInt>,
        references: &HashMap<usize, HintReference>,
    ) -> Result<Box<dyn Any>, VirtualMachineError>;
}
