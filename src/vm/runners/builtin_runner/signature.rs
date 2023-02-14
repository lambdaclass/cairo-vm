use crate::{
    math_utils::safe_div_usize,
    types::{
        instance_definitions::ecdsa_instance_def::EcdsaInstanceDef,
        relocatable::{MaybeRelocatable, Relocatable},
    },
    vm::{
        errors::{
            memory_errors::{InsufficientAllocatedCellsError, MemoryError},
            runner_errors::RunnerError,
        },
        vm_core::VirtualMachine,
        vm_memory::{
            memory::{Memory, ValidationRule},
            memory_segments::MemorySegmentManager,
        },
    },
};
use felt::Felt;
use num_integer::div_ceil;
use num_traits::ToPrimitive;
use starknet_crypto::{verify, FieldElement, Signature};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

pub(crate) const NAME: &'static str = "ecda";

#[derive(Debug, Clone)]
pub struct SignatureBuiltinRunner {
    pub(crate) included: bool,
    ratio: u32,
    base: isize,
    pub(crate) cells_per_instance: u32,
    pub(crate) n_input_cells: u32,
    _total_n_bits: u32,
    pub(crate) stop_ptr: Option<usize>,
    instances_per_component: u32,
    signatures: Rc<RefCell<HashMap<Relocatable, Signature>>>,
}

impl SignatureBuiltinRunner {
    pub(crate) fn new(instance_def: &EcdsaInstanceDef, included: bool) -> Self {
        SignatureBuiltinRunner {
            base: 0,
            included,
            ratio: instance_def.ratio,
            cells_per_instance: 2,
            n_input_cells: 2,
            _total_n_bits: 251,
            stop_ptr: None,
            instances_per_component: 1,
            signatures: Rc::new(RefCell::new(HashMap::new())),
        }
    }

    pub fn add_signature(
        &mut self,
        relocatable: Relocatable,
        (r, s): &(Felt, Felt),
    ) -> Result<(), MemoryError> {
        let r_string = r.to_str_radix(10);
        let s_string = s.to_str_radix(10);
        let (r_felt, s_felt) = (
            FieldElement::from_dec_str(&r_string)
                .map_err(|_| MemoryError::FailedStringToFieldElementConversion(r_string))?,
            FieldElement::from_dec_str(&s_string)
                .map_err(|_| MemoryError::FailedStringToFieldElementConversion(s_string))?,
        );

        let signature = Signature {
            r: r_felt,
            s: s_felt,
        };

        self.signatures
            .borrow_mut()
            .entry(relocatable)
            .or_insert(signature);

        Ok(())
    }
}

impl SignatureBuiltinRunner {
    pub fn initialize_segments(&mut self, segments: &mut MemorySegmentManager) {
        self.base = segments.add().segment_index
    }

    pub fn initial_stack(&self) -> Vec<MaybeRelocatable> {
        if self.included {
            vec![MaybeRelocatable::from((self.base, 0))]
        } else {
            vec![]
        }
    }

    pub fn base(&self) -> isize {
        self.base
    }
    pub fn add_validation_rule(&self, memory: &mut Memory) -> Result<(), RunnerError> {
        let cells_per_instance = self.cells_per_instance;
        let signatures = Rc::clone(&self.signatures);
        let rule: ValidationRule = ValidationRule(Box::new(
            move |memory: &Memory, addr: &Relocatable| -> Result<Vec<Relocatable>, MemoryError> {
                let cell_index = addr.offset % cells_per_instance as usize;

                let (pubkey_addr, message_addr) = match cell_index {
                    0 => (*addr, addr + 1),
                    1 => match addr.sub_usize(1) {
                        Ok(prev_addr) => (prev_addr, *addr),
                        Err(_) => return Ok(vec![]),
                    },
                    _ => return Ok(vec![]),
                };

                let pubkey = match memory.get_integer(&pubkey_addr) {
                    Ok(num) => num,
                    Err(_) if cell_index == 1 => return Ok(vec![]),
                    _ => return Err(MemoryError::PubKeyNonInt(pubkey_addr)),
                };

                let msg = match memory.get_integer(&message_addr) {
                    Ok(num) => num,
                    Err(_) if cell_index == 0 => return Ok(vec![]),
                    _ => return Err(MemoryError::MsgNonInt(message_addr)),
                };

                let signatures_map = signatures.borrow();
                let signature = signatures_map
                    .get(&pubkey_addr)
                    .ok_or(MemoryError::SignatureNotFound(pubkey_addr))?;

                let public_key = FieldElement::from_dec_str(&pubkey.to_str_radix(10))
                    .map_err(|_| MemoryError::ErrorParsingPubKey(pubkey.to_str_radix(10)))?;
                let (r, s) = (signature.r, signature.s);
                let message = FieldElement::from_dec_str(&msg.to_str_radix(10))
                    .map_err(|_| MemoryError::ErrorRetrievingMessage(msg.to_str_radix(10)))?;
                match verify(&public_key, &message, &r, &s) {
                    Ok(true) => Ok(vec![]),
                    _ => Err(MemoryError::InvalidSignature(
                        signature.to_string(),
                        pubkey.into_owned(),
                        msg.into_owned(),
                    )),
                }
            },
        ));
        memory.add_validation_rule(
            self.base
                .to_usize()
                .ok_or(RunnerError::RunnerInTemporarySegment(self.base))?,
            rule,
        );
        Ok(())
    }

    pub fn deduce_memory_cell(
        &self,
        _address: &Relocatable,
        _memory: &Memory,
    ) -> Result<Option<MaybeRelocatable>, RunnerError> {
        Ok(None)
    }

    pub fn ratio(&self) -> u32 {
        self.ratio
    }

    pub fn get_allocated_memory_units(&self, vm: &VirtualMachine) -> Result<usize, MemoryError> {
        let value = safe_div_usize(vm.current_step, self.ratio as usize)
            .map_err(|_| MemoryError::ErrorCalculatingMemoryUnits)?;
        Ok(self.cells_per_instance as usize * value)
    }

    pub fn get_memory_segment_addresses(&self) -> (isize, Option<usize>) {
        (self.base, self.stop_ptr)
    }

    pub fn get_used_cells(&self, segments: &MemorySegmentManager) -> Result<usize, MemoryError> {
        let base = self.base();
        segments
            .get_segment_used_size(
                base.try_into()
                    .map_err(|_| MemoryError::AddressInTemporarySegment(base))?,
            )
            .ok_or(MemoryError::MissingSegmentUsedSizes)
    }

    pub fn get_used_cells_and_allocated_size(
        &self,
        vm: &VirtualMachine,
    ) -> Result<(usize, usize), MemoryError> {
        let ratio = self.ratio as usize;
        let min_step = ratio * self.instances_per_component as usize;
        dbg!(min_step);
        if vm.current_step < min_step {
            Err(InsufficientAllocatedCellsError::MinStepNotReached(min_step, NAME).into())
        } else {
            let used = self.get_used_cells(&vm.segments)?;
            let size = self.cells_per_instance as usize
                * safe_div_usize(vm.current_step, ratio).map_err(|_| {
                    InsufficientAllocatedCellsError::CurrentStepNotDivisibleByBuiltinRatio(
                        NAME,
                        vm.current_step,
                        ratio,
                    )
                })?;
            if used > size {
                return Err(InsufficientAllocatedCellsError::BuiltinCells(NAME, used, size).into());
            }
            Ok((used, size))
        }
    }

    pub fn get_used_instances(
        &self,
        segments: &MemorySegmentManager,
    ) -> Result<usize, MemoryError> {
        let used_cells = self.get_used_cells(segments)?;
        Ok(div_ceil(used_cells, self.cells_per_instance as usize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        relocatable,
        types::instance_definitions::ecdsa_instance_def::EcdsaInstanceDef,
        utils::test_utils::*,
        vm::{
            errors::memory_errors::MemoryError,
            runners::builtin_runner::BuiltinRunner,
            vm_core::VirtualMachine,
            vm_memory::{memory::Memory, memory_segments::MemorySegmentManager},
        },
    };

    #[test]
    fn get_used_cells_and_allocated_size_min_step_not_reached() {
        let builtin = SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true);
        let mut vm = vm!();
        vm.current_step = 100;
        vm.segments.segment_used_sizes = Some(vec![1]);
        assert_eq!(
            builtin.get_used_cells_and_allocated_size(&vm),
            Err(MemoryError::InsufficientAllocatedCells(
                InsufficientAllocatedCellsError::MinStepNotReached(512, NAME)
            ))
        );
    }

    #[test]
    fn get_used_cells_and_allocated_size_valid() {
        let builtin = SignatureBuiltinRunner::new(&EcdsaInstanceDef::new(10), true);
        let mut vm = vm!();
        vm.current_step = 110;
        vm.segments.segment_used_sizes = Some(vec![1]);
        assert_eq!(builtin.get_used_cells_and_allocated_size(&vm), Ok((1, 22)));
    }

    #[test]
    fn initialize_segments_for_ecdsa() {
        let mut builtin = SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true);
        let mut segments = MemorySegmentManager::new();
        builtin.initialize_segments(&mut segments);
        assert_eq!(builtin.base, 0);
    }

    #[test]
    fn get_used_instances() {
        let builtin: BuiltinRunner =
            SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true).into();

        let mut vm = vm!();
        vm.segments.segment_used_sizes = Some(vec![1]);

        assert_eq!(builtin.get_used_instances(&vm.segments), Ok(1));
    }

    #[test]
    fn final_stack() {
        let mut builtin: BuiltinRunner =
            SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true).into();

        let mut vm = vm!();

        vm.segments = segments![
            ((0, 0), (0, 0)),
            ((0, 1), (0, 1)),
            ((2, 0), (0, 0)),
            ((2, 1), (0, 0))
        ];

        vm.segments.segment_used_sizes = Some(vec![0]);

        let pointer = Relocatable::from((2, 2));

        assert_eq!(
            builtin.final_stack(&vm.segments, pointer).unwrap(),
            Relocatable::from((2, 1))
        );
    }

    #[test]
    fn final_stack_error_stop_pointer() {
        let mut builtin: BuiltinRunner =
            SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true).into();

        let mut vm = vm!();

        vm.segments = segments![
            ((0, 0), (0, 0)),
            ((0, 1), (0, 1)),
            ((2, 0), (0, 0)),
            ((2, 1), (0, 0))
        ];

        vm.segments.segment_used_sizes = Some(vec![999]);

        let pointer = Relocatable::from((2, 2));

        assert_eq!(
            builtin.final_stack(&vm.segments, pointer),
            Err(RunnerError::InvalidStopPointer(
                NAME,
                relocatable!(0, 999),
                relocatable!(0, 0)
            ))
        );
    }

    #[test]
    fn final_stack_error_non_relocatable() {
        let mut builtin: BuiltinRunner =
            SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true).into();

        let mut vm = vm!();

        vm.segments = segments![
            ((0, 0), (0, 0)),
            ((0, 1), (0, 1)),
            ((2, 0), (0, 0)),
            ((2, 1), 2)
        ];

        vm.segments.segment_used_sizes = Some(vec![0]);

        let pointer = Relocatable::from((2, 2));

        assert_eq!(
            builtin.final_stack(&vm.segments, pointer),
            Err(RunnerError::NoStopPointer(NAME))
        );
    }

    #[test]
    fn get_memory_segment_addresses() {
        let builtin = SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true);

        assert_eq!(builtin.get_memory_segment_addresses(), (0, None));
    }

    #[test]
    fn get_memory_accesses_missing_segment_used_sizes() {
        let builtin = BuiltinRunner::Signature(SignatureBuiltinRunner::new(
            &EcdsaInstanceDef::default(),
            true,
        ));
        let vm = vm!();

        assert_eq!(
            builtin.get_memory_accesses(&vm),
            Err(MemoryError::MissingSegmentUsedSizes),
        );
    }

    #[test]
    fn get_memory_accesses_empty() {
        let builtin = BuiltinRunner::Signature(SignatureBuiltinRunner::new(
            &EcdsaInstanceDef::default(),
            true,
        ));
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![0]);
        assert_eq!(builtin.get_memory_accesses(&vm), Ok(vec![]));
    }

    #[test]
    fn get_memory_accesses() {
        let builtin = BuiltinRunner::Signature(SignatureBuiltinRunner::new(
            &EcdsaInstanceDef::default(),
            true,
        ));
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
    fn get_used_cells_missing_segment_used_sizes() {
        let builtin = BuiltinRunner::Signature(SignatureBuiltinRunner::new(
            &EcdsaInstanceDef::default(),
            true,
        ));
        let vm = vm!();

        assert_eq!(
            builtin.get_used_cells(&vm.segments),
            Err(MemoryError::MissingSegmentUsedSizes)
        );
    }

    #[test]
    fn get_used_cells_empty() {
        let builtin = BuiltinRunner::Signature(SignatureBuiltinRunner::new(
            &EcdsaInstanceDef::default(),
            true,
        ));
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![0]);
        assert_eq!(builtin.get_used_cells(&vm.segments), Ok(0));
    }

    #[test]
    fn get_used_cells() {
        let builtin = BuiltinRunner::Signature(SignatureBuiltinRunner::new(
            &EcdsaInstanceDef::default(),
            true,
        ));
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![4]);
        assert_eq!(builtin.get_used_cells(&vm.segments), Ok(4));
    }

    #[test]
    fn get_initial_stack_for_range_check_with_base() {
        let mut builtin = SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true);
        builtin.base = 1;
        let initial_stack = builtin.initial_stack();
        assert_eq!(
            initial_stack[0].clone(),
            MaybeRelocatable::RelocatableValue((builtin.base(), 0).into())
        );
        assert_eq!(initial_stack.len(), 1);
    }

    #[test]
    fn initial_stack_not_included_test() {
        let ecdsa_builtin = SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), false);
        assert_eq!(ecdsa_builtin.initial_stack(), Vec::new())
    }

    #[test]
    fn deduce_memory_cell_test() {
        let memory = Memory::new();
        let builtin = SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true);
        let result = builtin.deduce_memory_cell(&Relocatable::from((0, 5)), &memory);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn test_ratio() {
        let builtin = SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true);
        assert_eq!(builtin.ratio(), 512);
    }

    #[test]
    fn test_base() {
        let builtin = SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true);
        assert_eq!(builtin.base(), 0);
    }

    #[test]
    fn test_get_memory_segment_addresses() {
        let builtin = SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true);

        assert_eq!(builtin.get_memory_segment_addresses(), (0, None));
    }

    #[test]
    fn deduce_memory_cell() {
        let memory = Memory::new();
        let builtin = SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true);
        let result = builtin.deduce_memory_cell(&Relocatable::from((0, 5)), &memory);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn get_allocated_memory_units_safe_div_fail() {
        let builtin = SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true);
        let mut vm = vm!();
        vm.current_step = 500;
        assert_eq!(
            builtin.get_allocated_memory_units(&vm),
            Err(MemoryError::ErrorCalculatingMemoryUnits)
        )
    }

    #[test]
    fn get_used_cells_and_allocated_size_safe_div_fail() {
        let builtin = SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true);
        let mut vm = vm!();
        vm.segments.segment_used_sizes = Some(vec![600]);
        vm.current_step = 551;
        assert_eq!(
            builtin.get_used_cells_and_allocated_size(&vm),
            Err(MemoryError::InsufficientAllocatedCells(
                InsufficientAllocatedCellsError::CurrentStepNotDivisibleByBuiltinRatio(
                    NAME,
                    551,
                    builtin.ratio as usize
                )
            ))
        )
    }

    #[test]
    fn get_used_cells_and_allocated_size_insufficient_allocated() {
        let builtin = SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true);
        let mut vm = vm!();
        vm.segments.segment_used_sizes = Some(vec![50]);
        vm.current_step = 512;
        assert_eq!(
            builtin.get_used_cells_and_allocated_size(&vm),
            Err(MemoryError::InsufficientAllocatedCells(
                InsufficientAllocatedCellsError::BuiltinCells(NAME, 50, 2)
            ))
        )
    }

    #[test]
    fn final_stack_invalid_stop_pointer() {
        let mut builtin: BuiltinRunner =
            SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true).into();
        let mut vm = vm!();
        vm.segments = segments![((0, 0), (1, 0))];
        assert_eq!(
            builtin.final_stack(&vm.segments, (0, 1).into()),
            Err(RunnerError::InvalidStopPointerIndex(
                NAME,
                relocatable!(1, 0),
                0
            ))
        )
    }

    #[test]
    fn final_stack_no_used_instances() {
        let mut builtin: BuiltinRunner =
            SignatureBuiltinRunner::new(&EcdsaInstanceDef::default(), true).into();
        let mut vm = vm!();
        vm.segments = segments![((0, 0), (0, 0))];
        assert_eq!(
            builtin.final_stack(&vm.segments, (0, 1).into()),
            Err(RunnerError::MemoryError(
                MemoryError::MissingSegmentUsedSizes
            ))
        )
    }
}
