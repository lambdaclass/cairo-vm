use crate::serde::deserialize_program::ApTracking;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use std::collections::HashMap;

pub trait HintExecutor {
    fn execute_hint(
        &self,
        vm: &mut VirtualMachine,
        hint_code: &str,
        ref_ids: &HashMap<String, BigInt>,
        ap_tracking: &ApTracking,
    ) -> Result<(), VirtualMachineError>;
}
