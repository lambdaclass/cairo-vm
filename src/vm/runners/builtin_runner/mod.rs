use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use crate::vm::errors::memory_errors::MemoryError;
use crate::vm::errors::runner_errors::RunnerError;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::vm_core::VirtualMachine;
use crate::vm::vm_memory::memory::Memory;
use crate::vm::vm_memory::memory_segments::MemorySegmentManager;

mod bitwise;
mod ec_op;
mod hash;
mod output;
mod range_check;

pub use bitwise::BitwiseBuiltinRunner;
pub use ec_op::EcOpBuiltinRunner;
pub use hash::HashBuiltinRunner;
use nom::ToUsize;
use num_integer::{div_ceil, div_floor};
pub use output::OutputBuiltinRunner;
pub use range_check::RangeCheckBuiltinRunner;

/* NB: this enum is no accident: we may need (and cairo-rs-py *does* need)
 * structs containing this to be `Send`. The only two ways to achieve that
 * are either storing a `dyn Trait` inside an `Arc<Mutex<&dyn Trait>>` or
 * making the type itself `Send`. We opted for not complicating the user nor
 * moving the guarantees to runtime by using an `enum` rather than a `Trait`.
 * This works under the assumption that we don't expect downstream users to
 * extend Cairo by adding new builtin runners.
 */
pub enum BuiltinRunner {
    Bitwise(BitwiseBuiltinRunner),
    EcOp(EcOpBuiltinRunner),
    Hash(HashBuiltinRunner),
    Output(OutputBuiltinRunner),
    RangeCheck(RangeCheckBuiltinRunner),
}

impl BuiltinRunner {
    ///Creates the necessary segments for the builtin in the MemorySegmentManager and stores the first address on the builtin's base
    pub fn initialize_segments(
        &mut self,
        segments: &mut MemorySegmentManager,
        memory: &mut Memory,
    ) {
        match *self {
            BuiltinRunner::Bitwise(ref mut bitwise) => {
                bitwise.initialize_segments(segments, memory)
            }
            BuiltinRunner::EcOp(ref mut ec) => ec.initialize_segments(segments, memory),
            BuiltinRunner::Hash(ref mut hash) => hash.initialize_segments(segments, memory),
            BuiltinRunner::Output(ref mut output) => output.initialize_segments(segments, memory),
            BuiltinRunner::RangeCheck(ref mut range_check) => {
                range_check.initialize_segments(segments, memory)
            }
        }
    }

    pub fn initial_stack(&self) -> Vec<MaybeRelocatable> {
        match *self {
            BuiltinRunner::Bitwise(ref bitwise) => bitwise.initial_stack(),
            BuiltinRunner::EcOp(ref ec) => ec.initial_stack(),
            BuiltinRunner::Hash(ref hash) => hash.initial_stack(),
            BuiltinRunner::Output(ref output) => output.initial_stack(),
            BuiltinRunner::RangeCheck(ref range_check) => range_check.initial_stack(),
        }
    }

    ///Returns the builtin's base
    pub fn base(&self) -> isize {
        match *self {
            BuiltinRunner::Bitwise(ref bitwise) => bitwise.base(),
            BuiltinRunner::EcOp(ref ec) => ec.base(),
            BuiltinRunner::Hash(ref hash) => hash.base(),
            BuiltinRunner::Output(ref output) => output.base(),
            BuiltinRunner::RangeCheck(ref range_check) => range_check.base(),
        }
    }

    pub fn add_validation_rule(&self, memory: &mut Memory) -> Result<(), RunnerError> {
        match *self {
            BuiltinRunner::Bitwise(ref bitwise) => bitwise.add_validation_rule(memory),
            BuiltinRunner::EcOp(ref ec) => ec.add_validation_rule(memory),
            BuiltinRunner::Hash(ref hash) => hash.add_validation_rule(memory),
            BuiltinRunner::Output(ref output) => output.add_validation_rule(memory),
            BuiltinRunner::RangeCheck(ref range_check) => range_check.add_validation_rule(memory),
        }
    }

    pub fn deduce_memory_cell(
        &mut self,
        address: &Relocatable,
        memory: &Memory,
    ) -> Result<Option<MaybeRelocatable>, RunnerError> {
        match *self {
            BuiltinRunner::Bitwise(ref mut bitwise) => bitwise.deduce_memory_cell(address, memory),
            BuiltinRunner::EcOp(ref mut ec) => ec.deduce_memory_cell(address, memory),
            BuiltinRunner::Hash(ref mut hash) => hash.deduce_memory_cell(address, memory),
            BuiltinRunner::Output(ref mut output) => output.deduce_memory_cell(address, memory),
            BuiltinRunner::RangeCheck(ref mut range_check) => {
                range_check.deduce_memory_cell(address, memory)
            }
        }
    }

    pub fn get_memory_accesses(
        &self,
        vm: &VirtualMachine,
    ) -> Result<Vec<Relocatable>, MemoryError> {
        let base = self.base();
        let segment_size = vm
            .segments
            .get_segment_size(
                base.try_into()
                    .map_err(|_| MemoryError::AddressInTemporarySegment(base))?,
            )
            .ok_or(MemoryError::MissingSegmentUsedSizes)?;

        Ok((0..segment_size).map(|i| (base, i).into()).collect())
    }

    pub fn get_memory_segment_addresses(&self) -> (&'static str, (isize, Option<usize>)) {
        match self {
            BuiltinRunner::Bitwise(ref bitwise) => bitwise.get_memory_segment_addresses(),
            BuiltinRunner::EcOp(ref ec) => ec.get_memory_segment_addresses(),
            BuiltinRunner::Hash(ref hash) => hash.get_memory_segment_addresses(),
            BuiltinRunner::Output(ref output) => output.get_memory_segment_addresses(),
            BuiltinRunner::RangeCheck(ref range_check) => {
                range_check.get_memory_segment_addresses()
            }
        }
    }

    pub fn get_used_cells(&self, vm: &VirtualMachine) -> Result<usize, MemoryError> {
        let base = self.base();
        vm.segments
            .get_segment_used_size(
                base.try_into()
                    .map_err(|_| MemoryError::AddressInTemporarySegment(base))?,
            )
            .ok_or(MemoryError::MissingSegmentUsedSizes)
    }

    pub fn get_used_instances(&self, vm: &VirtualMachine) -> Result<usize, MemoryError> {
        let used_cells = self.get_used_cells(vm)?;
        match self {
            BuiltinRunner::Bitwise(ref bitwise) => {
                Ok(div_ceil(used_cells, bitwise.cells_per_instance.to_usize()))
            }
            BuiltinRunner::EcOp(ref ec) => {
                Ok(div_ceil(used_cells, ec.cells_per_instance.to_usize()))
            }
            BuiltinRunner::Hash(ref hash) => {
                Ok(div_ceil(used_cells, hash.cells_per_instance.to_usize()))
            }
            BuiltinRunner::Output(_) => Ok(used_cells),
            BuiltinRunner::RangeCheck(_) => Ok(used_cells),
        }
    }

    pub fn get_range_check_usage(&self, memory: &Memory) -> Option<(isize, isize)> {
        match self {
            BuiltinRunner::RangeCheck(ref range_check) => range_check.get_range_check_usage(memory),
            _ => None,
        }
    }

    /// Returns the number of range check units used by the builtin.
    pub fn get_used_perm_range_check_units(
        &self,
        vm: &VirtualMachine,
    ) -> Result<usize, MemoryError> {
        match self {
            BuiltinRunner::RangeCheck(range_check) => {
                range_check.get_used_perm_range_check_units(vm)
            }
            _ => Ok(0),
        }
    }

    pub fn get_used_diluted_check_units(&self, diluted_spacing: u32, diluted_n_bits: u32) -> usize {
        match self {
            BuiltinRunner::Bitwise(ref bitwise) => {
                bitwise.get_used_diluted_check_units(diluted_spacing, diluted_n_bits)
            }
            _ => 0,
        }
    }

    pub fn run_security_checks(&self, vm: &mut VirtualMachine) -> Result<(), VirtualMachineError> {
        if let BuiltinRunner::Output(_) = self {
            return Ok(());
        }

        let (cells_per_instance, n_input_cells) = match self {
            BuiltinRunner::Bitwise(x) => (x.cells_per_instance, x.n_input_cells),
            BuiltinRunner::EcOp(x) => (x.cells_per_instance, x.n_input_cells),
            BuiltinRunner::Hash(x) => (x.cells_per_instance, x.n_input_cells),
            BuiltinRunner::RangeCheck(x) => (x.cells_per_instance, x.n_input_cells),
            BuiltinRunner::Output(_) => unreachable!(),
        };

        let base = self.base();
        let offsets = vm
            .memory
            .data
            .get(
                TryInto::<usize>::try_into(base)
                    .map_err(|_| MemoryError::AddressInTemporarySegment(base))?,
            )
            .ok_or(MemoryError::NumOutOfBounds)?
            .iter()
            .enumerate()
            .filter_map(|(offset, value)| match value {
                Some(MaybeRelocatable::RelocatableValue(_)) => Some(offset),
                _ => None,
            })
            .collect::<Vec<_>>();

        let n = div_floor(offsets.len(), cells_per_instance as usize);
        if n > div_floor(offsets.len(), n_input_cells as usize) {
            return Err(MemoryError::MissingMemoryCells(match self {
                BuiltinRunner::Bitwise(_) => "bitwise",
                BuiltinRunner::EcOp(_) => "ec_op",
                BuiltinRunner::Hash(_) => "hash",
                BuiltinRunner::Output(_) => "output",
                BuiltinRunner::RangeCheck(_) => "range_check",
            })
            .into());
        }

        // Since both offsets and this iterator are ordered, a simple pointer is
        // enough to check if the values are present.
        let mut offsets_iter = offsets.iter().copied().peekable();
        let mut missing_offsets = Vec::new();
        for i in 0..n as usize {
            let offset = cells_per_instance as usize * i;
            for j in 0..n_input_cells as usize {
                let offset = offset + j;
                match offsets_iter.next_if_eq(&offset) {
                    Some(_) => {}
                    None => {
                        missing_offsets.push(offset);
                    }
                }
            }
        }
        if !missing_offsets.is_empty() {
            return Err(MemoryError::MissingMemoryCellsWithOffsets(
                match self {
                    BuiltinRunner::Bitwise(_) => "bitwise",
                    BuiltinRunner::EcOp(_) => "ec_op",
                    BuiltinRunner::Hash(_) => "hash",
                    BuiltinRunner::Output(_) => "output",
                    BuiltinRunner::RangeCheck(_) => "range_check",
                },
                missing_offsets,
            )
            .into());
        }

        let mut should_validate_auto_deductions = false;
        for i in 0..n {
            for j in n_input_cells as usize..cells_per_instance as usize {
                let addr: Relocatable = (base, cells_per_instance as usize * i + j).into();
                if !vm.memory.validated_addresses.contains(&addr.into()) {
                    should_validate_auto_deductions = true;
                }
            }
        }
        if should_validate_auto_deductions {
            vm.verify_auto_deductions()?;
        }

        Ok(())
    }
}

impl From<BitwiseBuiltinRunner> for BuiltinRunner {
    fn from(runner: BitwiseBuiltinRunner) -> Self {
        BuiltinRunner::Bitwise(runner)
    }
}

impl From<EcOpBuiltinRunner> for BuiltinRunner {
    fn from(runner: EcOpBuiltinRunner) -> Self {
        BuiltinRunner::EcOp(runner)
    }
}

impl From<HashBuiltinRunner> for BuiltinRunner {
    fn from(runner: HashBuiltinRunner) -> Self {
        BuiltinRunner::Hash(runner)
    }
}

impl From<OutputBuiltinRunner> for BuiltinRunner {
    fn from(runner: OutputBuiltinRunner) -> Self {
        BuiltinRunner::Output(runner)
    }
}

impl From<RangeCheckBuiltinRunner> for BuiltinRunner {
    fn from(runner: RangeCheckBuiltinRunner) -> Self {
        BuiltinRunner::RangeCheck(runner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bigint,
        types::instance_definitions::{
            bitwise_instance_def::BitwiseInstanceDef, ec_op_instance_def::EcOpInstanceDef,
        },
        utils::test_utils::*,
        vm::vm_core::VirtualMachine,
    };
    use num_bigint::{BigInt, Sign};

    #[test]
    fn get_memory_accesses_missing_segment_used_sizes() {
        let builtin: BuiltinRunner =
            BitwiseBuiltinRunner::new(&BitwiseInstanceDef::default()).into();
        let vm = vm!();

        assert_eq!(
            builtin.get_memory_accesses(&vm),
            Err(MemoryError::MissingSegmentUsedSizes),
        );
    }

    #[test]
    fn get_memory_accesses_empty() {
        let builtin: BuiltinRunner =
            BitwiseBuiltinRunner::new(&BitwiseInstanceDef::default()).into();
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![0]);
        assert_eq!(builtin.get_memory_accesses(&vm), Ok(vec![]));
    }

    #[test]
    fn get_memory_accesses() {
        let builtin: BuiltinRunner =
            BitwiseBuiltinRunner::new(&BitwiseInstanceDef::default()).into();
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![4]);
        assert_eq!(
            builtin.get_memory_accesses(&vm),
            Ok(vec![
                (builtin.base(), 0).into(),
                (builtin.base(), 1).into(),
                (builtin.base(), 2).into(),
                (builtin.base(), 3).into(),
            ]),
        );
    }

    #[test]
    fn get_range_check_usage_range_check() {
        let builtin = BuiltinRunner::RangeCheck(RangeCheckBuiltinRunner::new(8, 8));
        let memory = memory![((0, 0), 1), ((0, 1), 2), ((0, 2), 3), ((0, 3), 4)];
        assert_eq!(builtin.get_range_check_usage(&memory), Some((1, 4)));
    }

    #[test]
    fn get_range_check_usage_output() {
        let builtin = BuiltinRunner::Output(OutputBuiltinRunner::new());
        let memory = memory![((0, 0), 1), ((0, 1), 2), ((0, 2), 3), ((0, 3), 4)];
        assert_eq!(builtin.get_range_check_usage(&memory), None);
    }

    #[test]
    fn get_range_check_usage_hash() {
        let builtin = BuiltinRunner::Hash(HashBuiltinRunner::new(256));
        let memory = memory![((0, 0), 1), ((0, 1), 2), ((0, 2), 3), ((0, 3), 4)];
        assert_eq!(builtin.get_range_check_usage(&memory), None);
    }

    #[test]
    fn get_range_check_usage_ec_op() {
        let builtin = BuiltinRunner::EcOp(EcOpBuiltinRunner::new(&EcOpInstanceDef::default()));
        let memory = memory![((0, 0), 1), ((0, 1), 2), ((0, 2), 3), ((0, 3), 4)];
        assert_eq!(builtin.get_range_check_usage(&memory), None);
    }

    #[test]
    fn get_range_check_usage_bitwise() {
        let builtin =
            BuiltinRunner::Bitwise(BitwiseBuiltinRunner::new(&BitwiseInstanceDef::default()));
        let memory = memory![((0, 0), 1), ((0, 1), 2), ((0, 2), 3), ((0, 3), 4)];
        assert_eq!(builtin.get_range_check_usage(&memory), None);
    }

    #[test]
    fn get_used_diluted_check_units_bitwise() {
        let builtin =
            BuiltinRunner::Bitwise(BitwiseBuiltinRunner::new(&BitwiseInstanceDef::default()));
        assert_eq!(builtin.get_used_diluted_check_units(270, 7), 1255);
    }

    #[test]
    fn get_used_diluted_check_units_ec_op() {
        let builtin = BuiltinRunner::EcOp(EcOpBuiltinRunner::new(&EcOpInstanceDef::default()));
        assert_eq!(builtin.get_used_diluted_check_units(270, 7), 0);
    }

    #[test]
    fn get_used_diluted_check_units_hash() {
        let builtin = BuiltinRunner::Hash(HashBuiltinRunner::new(16));
        assert_eq!(builtin.get_used_diluted_check_units(270, 7), 0);
    }

    #[test]
    fn get_used_diluted_check_units_range_check() {
        let builtin = BuiltinRunner::RangeCheck(RangeCheckBuiltinRunner::new(8, 8));
        assert_eq!(builtin.get_used_diluted_check_units(270, 7), 0);
    }

    #[test]
    fn get_used_diluted_check_units_output() {
        let builtin = BuiltinRunner::Output(OutputBuiltinRunner::new());
        assert_eq!(builtin.get_used_diluted_check_units(270, 7), 0);
    }

    #[test]
    fn run_security_checks_for_output() {
        let builtin = BuiltinRunner::Output(OutputBuiltinRunner::new());
        let mut vm = vm!();

        assert_eq!(builtin.run_security_checks(&mut vm), Ok(()));
    }

    #[test]
    fn run_security_checks_empty_memory() {
        let builtin =
            BuiltinRunner::Bitwise(BitwiseBuiltinRunner::new(&BitwiseInstanceDef::default()));
        let mut vm = vm!();

        assert_eq!(
            builtin.run_security_checks(&mut vm),
            Err(MemoryError::NumOutOfBounds.into()),
        );
    }

    #[test]
    fn run_security_checks_temporary_segment() {
        let builtin = BuiltinRunner::Bitwise({
            let mut builtin = BitwiseBuiltinRunner::new(&BitwiseInstanceDef::default());
            builtin.base = -1;
            builtin
        });
        let mut vm = vm!();

        assert_eq!(
            builtin.run_security_checks(&mut vm),
            Err(MemoryError::AddressInTemporarySegment(-1).into()),
        );
    }

    #[test]
    fn run_security_checks_empty_offsets() {
        let builtin =
            BuiltinRunner::Bitwise(BitwiseBuiltinRunner::new(&BitwiseInstanceDef::default()));
        let mut vm = vm!();

        vm.memory.data = vec![vec![]];

        assert_eq!(builtin.run_security_checks(&mut vm), Ok(()));
    }

    #[test]
    fn run_security_checks_missing_memory_cells() {
        let builtin =
            BuiltinRunner::Bitwise(BitwiseBuiltinRunner::new(&BitwiseInstanceDef::default()));
        let mut vm = vm!();

        vm.memory.data = vec![vec![
            None,
            mayberelocatable!(0, 1).into(),
            mayberelocatable!(0, 2).into(),
            mayberelocatable!(0, 3).into(),
            mayberelocatable!(0, 4).into(),
            mayberelocatable!(0, 5).into(),
        ]];

        assert_eq!(
            builtin.run_security_checks(&mut vm),
            Err(MemoryError::MissingMemoryCellsWithOffsets("bitwise", vec![0],).into()),
        );
    }
}
