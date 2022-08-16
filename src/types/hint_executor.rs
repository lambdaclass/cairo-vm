use crate::serde::deserialize_program::ApTracking;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::vm_core::VMProxy;
use num_bigint::BigInt;
use std::collections::HashMap;

pub trait HintExecutor {
    fn execute_hint(
        &self,
        vm: &mut VMProxy,
        hint_code: &str,
        ref_ids: &HashMap<String, BigInt>,
        ap_tracking: &ApTracking,
    ) -> Result<(), VirtualMachineError>;
}
