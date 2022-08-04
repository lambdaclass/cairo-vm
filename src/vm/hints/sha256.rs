pub fn sha256_input(vm: &mut VirtualMachine) -> Result<(), VirtualMachineError> {
    let n_bytes = get_int_from_scope_ref(vm, "n")?;
}
