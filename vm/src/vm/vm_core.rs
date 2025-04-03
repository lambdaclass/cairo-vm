use crate::math_utils::signed_felt;
use crate::stdlib::{any::Any, borrow::Cow, collections::HashMap, prelude::*};
use crate::types::builtin_name::BuiltinName;
#[cfg(feature = "extensive_hints")]
use crate::types::program::HintRange;
use crate::{
    hint_processor::{
        builtin_hint_processor::blake2s_hash::blake2s_compress,
        hint_processor_definition::HintProcessor,
    },
    typed_operations::{typed_add, typed_div, typed_mul, typed_sub},
    types::{
        errors::math_errors::MathError,
        exec_scope::ExecutionScopes,
        instruction::{
            is_call_instruction, ApUpdate, FpUpdate, Instruction, Opcode, OpcodeExtension,
            PcUpdate, Res,
        },
        relocatable::{MaybeRelocatable, Relocatable},
    },
    vm::{
        context::run_context::RunContext,
        decoding::decoder::decode_instruction,
        errors::{
            exec_scope_errors::ExecScopeError, memory_errors::MemoryError,
            vm_errors::VirtualMachineError,
        },
        runners::builtin_runner::{
            BuiltinRunner, OutputBuiltinRunner, RangeCheckBuiltinRunner, SignatureBuiltinRunner,
        },
        trace::trace_entry::TraceEntry,
        vm_memory::memory_segments::MemorySegmentManager,
    },
};

use crate::Felt;
use core::cmp::Ordering;
#[cfg(feature = "extensive_hints")]
use core::num::NonZeroUsize;
use num_traits::{ToPrimitive, Zero};

use super::errors::runner_errors::RunnerError;
use super::runners::builtin_runner::{ModBuiltinRunner, RC_N_PARTS_STANDARD};
use super::runners::cairo_pie::CairoPie;

const MAX_TRACEBACK_ENTRIES: u32 = 20;

#[derive(PartialEq, Eq, Debug)]
pub struct Operands {
    dst: MaybeRelocatable,
    res: Option<MaybeRelocatable>,
    op0: MaybeRelocatable,
    op1: MaybeRelocatable,
}

#[derive(PartialEq, Eq, Debug)]
pub struct OperandsAddresses {
    dst_addr: Relocatable,
    op0_addr: Relocatable,
    op1_addr: Relocatable,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct DeducedOperands(u8);

impl DeducedOperands {
    fn set_dst(&mut self, value: bool) {
        self.0 |= value as u8;
    }
    fn set_op0(&mut self, value: bool) {
        self.0 |= (value as u8) << 1;
    }
    fn set_op1(&mut self, value: bool) {
        self.0 |= (value as u8) << 2;
    }

    fn was_dest_deducted(&self) -> bool {
        self.0 & 1 != 0
    }
    fn was_op0_deducted(&self) -> bool {
        self.0 & (1 << 1) != 0
    }
    fn was_op1_deducted(&self) -> bool {
        self.0 & (1 << 2) != 0
    }
}

pub struct VirtualMachine {
    pub(crate) run_context: RunContext,
    pub builtin_runners: Vec<BuiltinRunner>,
    pub simulated_builtin_runners: Vec<BuiltinRunner>,
    pub segments: MemorySegmentManager,
    pub(crate) trace: Option<Vec<TraceEntry>>,
    pub(crate) current_step: usize,
    pub(crate) rc_limits: Option<(isize, isize)>,
    skip_instruction_execution: bool,
    run_finished: bool,
    // This flag is a parallel to the one in `struct CairoRunConfig`.
    pub(crate) disable_trace_padding: bool,
    instruction_cache: Vec<Option<Instruction>>,
    #[cfg(feature = "test_utils")]
    pub(crate) hooks: crate::vm::hooks::Hooks,
    pub(crate) relocation_table: Option<Vec<usize>>,
}

impl VirtualMachine {
    pub fn new(trace_enabled: bool, disable_trace_padding: bool) -> VirtualMachine {
        let run_context = RunContext {
            pc: Relocatable::from((0, 0)),
            ap: 0,
            fp: 0,
        };

        let trace = if trace_enabled {
            Some(Vec::<TraceEntry>::new())
        } else {
            None
        };

        VirtualMachine {
            run_context,
            builtin_runners: Vec::new(),
            simulated_builtin_runners: Vec::new(),
            trace,
            current_step: 0,
            skip_instruction_execution: false,
            segments: MemorySegmentManager::new(),
            rc_limits: None,
            run_finished: false,
            disable_trace_padding,
            instruction_cache: Vec::new(),
            #[cfg(feature = "test_utils")]
            hooks: Default::default(),
            relocation_table: None,
        }
    }

    pub fn compute_segments_effective_sizes(&mut self) {
        self.segments.compute_effective_sizes();
    }

    fn update_fp(
        &mut self,
        instruction: &Instruction,
        operands: &Operands,
    ) -> Result<(), VirtualMachineError> {
        let new_fp_offset: usize = match instruction.fp_update {
            FpUpdate::APPlus2 => self.run_context.ap + 2,
            FpUpdate::Dst => match operands.dst {
                MaybeRelocatable::RelocatableValue(ref rel) => rel.offset,
                MaybeRelocatable::Int(ref num) => num
                    .to_usize()
                    .ok_or_else(|| MathError::FeltToUsizeConversion(Box::new(*num)))?,
            },
            FpUpdate::Regular => return Ok(()),
        };
        self.run_context.fp = new_fp_offset;
        Ok(())
    }

    fn update_ap(
        &mut self,
        instruction: &Instruction,
        operands: &Operands,
    ) -> Result<(), VirtualMachineError> {
        let new_apset: usize = match instruction.ap_update {
            ApUpdate::Add => match &operands.res {
                Some(res) => (self.run_context.get_ap() + res)?.offset,
                None => return Err(VirtualMachineError::UnconstrainedResAdd),
            },
            ApUpdate::Add1 => self.run_context.ap + 1,
            ApUpdate::Add2 => self.run_context.ap + 2,
            ApUpdate::Regular => return Ok(()),
        };
        self.run_context.ap = new_apset;
        Ok(())
    }

    fn update_pc(
        &mut self,
        instruction: &Instruction,
        operands: &Operands,
    ) -> Result<(), VirtualMachineError> {
        let new_pc: Relocatable = match instruction.pc_update {
            PcUpdate::Regular => (self.run_context.pc + instruction.size())?,
            PcUpdate::Jump => match operands.res.as_ref().and_then(|x| x.get_relocatable()) {
                Some(ref res) => *res,
                None => return Err(VirtualMachineError::UnconstrainedResJump),
            },
            PcUpdate::JumpRel => match &operands.res {
                Some(res) => match res {
                    MaybeRelocatable::Int(num_res) => (self.run_context.pc + num_res)?,
                    _ => return Err(VirtualMachineError::JumpRelNotInt),
                },
                None => return Err(VirtualMachineError::UnconstrainedResJumpRel),
            },
            PcUpdate::Jnz => match VirtualMachine::is_zero(&operands.dst) {
                true => (self.run_context.pc + instruction.size())?,
                false => (self.run_context.pc + &operands.op1)?,
            },
        };
        self.run_context.pc = new_pc;
        Ok(())
    }

    fn update_registers(
        &mut self,
        instruction: &Instruction,
        operands: Operands,
    ) -> Result<(), VirtualMachineError> {
        self.update_fp(instruction, &operands)?;
        self.update_ap(instruction, &operands)?;
        self.update_pc(instruction, &operands)?;
        Ok(())
    }

    /// Returns true if the value is zero
    /// Used for JNZ instructions
    fn is_zero(addr: &MaybeRelocatable) -> bool {
        match addr {
            MaybeRelocatable::Int(num) => num.is_zero(),
            _ => false,
        }
    }

    ///Returns a tuple (deduced_op0, deduced_res).
    ///Deduces the value of op0 if possible (based on dst and op1). Otherwise, returns None.
    ///If res was already deduced, returns its deduced value as well.
    fn deduce_op0(
        &self,
        instruction: &Instruction,
        dst: Option<&MaybeRelocatable>,
        op1: Option<&MaybeRelocatable>,
    ) -> Result<(Option<MaybeRelocatable>, Option<MaybeRelocatable>), VirtualMachineError> {
        match instruction.opcode {
            Opcode::Call => Ok((
                Some(MaybeRelocatable::from(
                    (self.run_context.pc + instruction.size())?,
                )),
                None,
            )),
            Opcode::AssertEq => match (&instruction.res, dst, op1) {
                (Res::Add, Some(dst_addr), Some(op1_addr)) => Ok((
                    Some(typed_sub(dst_addr, op1_addr, instruction.opcode_extension)?),
                    dst.cloned(),
                )),
                (
                    Res::Mul,
                    Some(MaybeRelocatable::Int(num_dst)),
                    Some(MaybeRelocatable::Int(num_op1)),
                ) if !num_op1.is_zero() => {
                    let num_op0 = typed_div(num_dst, num_op1, instruction.opcode_extension)?;
                    Ok((Some(MaybeRelocatable::Int(num_op0)), dst.cloned()))
                }
                _ => Ok((None, None)),
            },
            _ => Ok((None, None)),
        }
    }

    /// Returns a tuple (deduced_op1, deduced_res).
    ///Deduces the value of op1 if possible (based on dst and op0). Otherwise, returns None.
    ///If res was already deduced, returns its deduced value as well.
    fn deduce_op1(
        &self,
        instruction: &Instruction,
        dst: Option<&MaybeRelocatable>,
        op0: Option<MaybeRelocatable>,
    ) -> Result<(Option<MaybeRelocatable>, Option<MaybeRelocatable>), VirtualMachineError> {
        if let Opcode::AssertEq = instruction.opcode {
            match instruction.res {
                Res::Op1 => return Ok((dst.cloned(), dst.cloned())),
                Res::Add => {
                    return Ok((
                        dst.zip(op0).and_then(|(dst, op0)| {
                            typed_sub(dst, &op0, instruction.opcode_extension).ok()
                        }),
                        dst.cloned(),
                    ))
                }
                Res::Mul => match (dst, op0) {
                    (
                        Some(MaybeRelocatable::Int(num_dst)),
                        Some(MaybeRelocatable::Int(num_op0)),
                    ) if !num_op0.is_zero() => {
                        let num_op1 = typed_div(num_dst, &num_op0, instruction.opcode_extension)?;
                        return Ok((Some(MaybeRelocatable::Int(num_op1)), dst.cloned()));
                    }
                    _ => (),
                },
                _ => (),
            };
        };
        Ok((None, None))
    }

    fn deduce_memory_cell(
        &self,
        address: Relocatable,
    ) -> Result<Option<MaybeRelocatable>, VirtualMachineError> {
        let memory = &self.segments.memory;

        for runner in self
            .builtin_runners
            .iter()
            .chain(self.simulated_builtin_runners.iter())
        {
            if runner.base() as isize == address.segment_index {
                return runner
                    .deduce_memory_cell(address, memory)
                    .map_err(VirtualMachineError::RunnerError);
            }
        }
        Ok(None)
    }

    ///Computes the value of res if possible
    fn compute_res(
        &self,
        instruction: &Instruction,
        op0: &MaybeRelocatable,
        op1: &MaybeRelocatable,
    ) -> Result<Option<MaybeRelocatable>, VirtualMachineError> {
        match instruction.res {
            Res::Op1 => Ok(Some(op1.clone())),
            Res::Add => Ok(Some(typed_add(op0, op1, instruction.opcode_extension)?)),
            Res::Mul => Ok(Some(typed_mul(op0, op1, instruction.opcode_extension)?)),
            Res::Unconstrained => Ok(None),
        }
    }

    fn deduce_dst(
        &self,
        instruction: &Instruction,
        res: &Option<MaybeRelocatable>,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
        let dst = match (instruction.opcode, res) {
            (Opcode::AssertEq, Some(res)) => res.clone(),
            (Opcode::Call, _) => MaybeRelocatable::from(self.run_context.get_fp()),
            _ => return Err(VirtualMachineError::NoDst),
        };
        Ok(dst)
    }

    fn opcode_assertions(
        &self,
        instruction: &Instruction,
        operands: &Operands,
    ) -> Result<(), VirtualMachineError> {
        match instruction.opcode {
            Opcode::AssertEq => match &operands.res {
                None => Err(VirtualMachineError::UnconstrainedResAssertEq),
                Some(res) if res != &operands.dst => Err(VirtualMachineError::DiffAssertValues(
                    Box::new((operands.dst.clone(), res.clone())),
                )),
                _ => Ok(()),
            },
            Opcode::Call => {
                let return_pc = MaybeRelocatable::from((self.run_context.pc + instruction.size())?);
                if operands.op0 != return_pc {
                    return Err(VirtualMachineError::CantWriteReturnPc(Box::new((
                        operands.op0.clone(),
                        return_pc,
                    ))));
                };

                if MaybeRelocatable::from(self.run_context.get_fp()) != operands.dst {
                    return Err(VirtualMachineError::CantWriteReturnFp(Box::new((
                        operands.dst.clone(),
                        MaybeRelocatable::from(self.run_context.get_fp()),
                    ))));
                };
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn insert_deduced_operands(
        &mut self,
        deduced_operands: DeducedOperands,
        operands: &Operands,
        operands_addresses: &OperandsAddresses,
    ) -> Result<(), VirtualMachineError> {
        if deduced_operands.was_op0_deducted() {
            self.segments
                .memory
                .insert(operands_addresses.op0_addr, &operands.op0)
                .map_err(VirtualMachineError::Memory)?;
        }
        if deduced_operands.was_op1_deducted() {
            self.segments
                .memory
                .insert(operands_addresses.op1_addr, &operands.op1)
                .map_err(VirtualMachineError::Memory)?;
        }
        if deduced_operands.was_dest_deducted() {
            self.segments
                .memory
                .insert(operands_addresses.dst_addr, &operands.dst)
                .map_err(VirtualMachineError::Memory)?;
        }

        Ok(())
    }

    fn run_instruction(&mut self, instruction: &Instruction) -> Result<(), VirtualMachineError> {
        let (operands, operands_addresses, deduced_operands) =
            self.compute_operands(instruction)?;
        self.insert_deduced_operands(deduced_operands, &operands, &operands_addresses)?;
        self.opcode_assertions(instruction, &operands)?;

        if let Some(ref mut trace) = &mut self.trace {
            trace.push(TraceEntry {
                pc: self.run_context.pc,
                ap: self.run_context.ap,
                fp: self.run_context.fp,
            });
        }

        // Update range check limits
        const OFFSET_BITS: u32 = 16;
        let (off0, off1, off2) = (
            instruction.off0 + (1_isize << (OFFSET_BITS - 1)),
            instruction.off1 + (1_isize << (OFFSET_BITS - 1)),
            instruction.off2 + (1_isize << (OFFSET_BITS - 1)),
        );
        let (min, max) = self.rc_limits.unwrap_or((off0, off0));
        self.rc_limits = Some((
            min.min(off0).min(off1).min(off2),
            max.max(off0).max(off1).max(off2),
        ));

        self.segments
            .memory
            .mark_as_accessed(operands_addresses.dst_addr);
        self.segments
            .memory
            .mark_as_accessed(operands_addresses.op0_addr);
        self.segments
            .memory
            .mark_as_accessed(operands_addresses.op1_addr);

        if instruction.opcode_extension == OpcodeExtension::Blake
            || instruction.opcode_extension == OpcodeExtension::BlakeFinalize
        {
            self.handle_blake2s_instruction(
                &operands_addresses,
                instruction.opcode_extension == OpcodeExtension::BlakeFinalize,
            )?;
        }

        self.update_registers(instruction, operands)?;
        self.current_step += 1;

        Ok(())
    }

    /// Executes a Blake2s or Blake2sLastBlock instruction.
    /// Expects operands to be RelocatableValue and to point to segments of memory.
    /// op0 is expected to point to a sequence of 8 u32 values (state).
    /// op1 is expected to point to a sequence of 16 u32 values (message).
    /// dst is expected hold the u32 value of the counter (t).
    /// [ap] is expected to point to a sequence of 8 cells each being either unitialised or
    /// containing the Blake2s compression output at that index.
    /// Deviation from the aforementioned expectations will result in an error.
    /// The instruction will update the memory segment pointed by [ap] with the new state.
    /// Note: the byte counter should count the number of message bytes processed so far including
    /// the current portion of the message (i.e. it starts at 64, not 0).
    fn handle_blake2s_instruction(
        &mut self,
        operands_addresses: &OperandsAddresses,
        is_last_block: bool,
    ) -> Result<(), VirtualMachineError> {
        let counter = self.segments.memory.get_u32(operands_addresses.dst_addr)?;

        let state: [u32; 8] = (self.get_u32_range(
            self.segments
                .memory
                .get_relocatable(operands_addresses.op0_addr)?,
            8,
        )?)
        .try_into()
        .map_err(|_| VirtualMachineError::Blake2sInvalidOperand(0, 8))?;

        let message: [u32; 16] = (self.get_u32_range(
            self.segments
                .memory
                .get_relocatable(operands_addresses.op1_addr)?,
            16,
        )?)
        .try_into()
        .map_err(|_| VirtualMachineError::Blake2sInvalidOperand(1, 16))?;

        let f0 = if is_last_block { 0xffffffff } else { 0 };

        let ap = self.run_context.get_ap();
        let output_address = self.segments.memory.get_relocatable(ap)?;

        let new_state = blake2s_compress(&state, &message, counter, 0, f0, 0);

        for (i, &val) in new_state.iter().enumerate() {
            self.segments.memory.insert_as_accessed(
                (output_address + i)?,
                MaybeRelocatable::Int(Felt::from(val)),
            )?;
        }

        Ok(())
    }

    fn decode_current_instruction(&self) -> Result<Instruction, VirtualMachineError> {
        let instruction = self
            .segments
            .memory
            .get_integer(self.run_context.pc)?
            .to_u128()
            .ok_or(VirtualMachineError::InvalidInstructionEncoding)?;
        decode_instruction(instruction)
    }

    #[cfg(not(feature = "extensive_hints"))]
    pub fn step_hint(
        &mut self,
        hint_processor: &mut dyn HintProcessor,
        exec_scopes: &mut ExecutionScopes,
        hint_datas: &[Box<dyn Any>],
        constants: &HashMap<String, Felt>,
    ) -> Result<(), VirtualMachineError> {
        for (hint_index, hint_data) in hint_datas.iter().enumerate() {
            hint_processor
                .execute_hint(self, exec_scopes, hint_data, constants)
                .map_err(|err| VirtualMachineError::Hint(Box::new((hint_index, err))))?
        }
        Ok(())
    }

    #[cfg(feature = "extensive_hints")]
    pub fn step_hint(
        &mut self,
        hint_processor: &mut dyn HintProcessor,
        exec_scopes: &mut ExecutionScopes,
        hint_datas: &mut Vec<Box<dyn Any>>,
        hint_ranges: &mut HashMap<Relocatable, HintRange>,
        constants: &HashMap<String, Felt>,
    ) -> Result<(), VirtualMachineError> {
        // Check if there is a hint range for the current pc
        if let Some((s, l)) = hint_ranges.get(&self.run_context.pc) {
            // Re-binding to avoid mutability problems
            let s = *s;
            // Execute each hint for the given range
            for idx in s..(s + l.get()) {
                let hint_extension = hint_processor
                    .execute_hint_extensive(
                        self,
                        exec_scopes,
                        hint_datas.get(idx).ok_or(VirtualMachineError::Unexpected)?,
                        constants,
                    )
                    .map_err(|err| VirtualMachineError::Hint(Box::new((idx - s, err))))?;
                // Update the hint_ranges & hint_datas with the hints added by the executed hint
                for (hint_pc, hints) in hint_extension {
                    if let Ok(len) = NonZeroUsize::try_from(hints.len()) {
                        hint_ranges.insert(hint_pc, (hint_datas.len(), len));
                        hint_datas.extend(hints);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn step_instruction(&mut self) -> Result<(), VirtualMachineError> {
        if self.run_context.pc.segment_index == 0 {
            // Run instructions from program segment, using instruction cache
            let pc = self.run_context.pc.offset;

            if self.segments.memory.data[0].len() <= pc {
                return Err(MemoryError::UnknownMemoryCell(Box::new((0, pc).into())))?;
            }

            let mut inst_cache = core::mem::take(&mut self.instruction_cache);
            inst_cache.resize((pc + 1).max(inst_cache.len()), None);

            let instruction = inst_cache.get_mut(pc).unwrap();
            if instruction.is_none() {
                *instruction = Some(self.decode_current_instruction()?);
            }
            let instruction = instruction.as_ref().unwrap();

            if !self.skip_instruction_execution {
                self.run_instruction(instruction)?;
            } else {
                self.run_context.pc += instruction.size();
                self.skip_instruction_execution = false;
            }
            self.instruction_cache = inst_cache;
        } else {
            // Run instructions from programs loaded in other segments, without instruction cache
            let instruction = self.decode_current_instruction()?;

            if !self.skip_instruction_execution {
                self.run_instruction(&instruction)?;
            } else {
                self.run_context.pc += instruction.size();
                self.skip_instruction_execution = false;
            }
        }
        Ok(())
    }

    pub fn step(
        &mut self,
        hint_processor: &mut dyn HintProcessor,
        exec_scopes: &mut ExecutionScopes,
        #[cfg(feature = "extensive_hints")] hint_datas: &mut Vec<Box<dyn Any>>,
        #[cfg(not(feature = "extensive_hints"))] hint_datas: &[Box<dyn Any>],
        #[cfg(feature = "extensive_hints")] hint_ranges: &mut HashMap<Relocatable, HintRange>,
        constants: &HashMap<String, Felt>,
    ) -> Result<(), VirtualMachineError> {
        self.step_hint(
            hint_processor,
            exec_scopes,
            hint_datas,
            #[cfg(feature = "extensive_hints")]
            hint_ranges,
            constants,
        )?;

        #[cfg(feature = "test_utils")]
        self.execute_pre_step_instruction(hint_processor, exec_scopes, hint_datas, constants)?;
        self.step_instruction()?;
        #[cfg(feature = "test_utils")]
        self.execute_post_step_instruction(hint_processor, exec_scopes, hint_datas, constants)?;

        Ok(())
    }

    fn compute_op0_deductions(
        &self,
        op0_addr: Relocatable,
        res: &mut Option<MaybeRelocatable>,
        instruction: &Instruction,
        dst_op: &Option<MaybeRelocatable>,
        op1_op: &Option<MaybeRelocatable>,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
        let op0_op = match self.deduce_memory_cell(op0_addr)? {
            None => {
                let op0;
                (op0, *res) = self.deduce_op0(instruction, dst_op.as_ref(), op1_op.as_ref())?;
                op0
            }
            deduced_memory_cell => deduced_memory_cell,
        };
        let op0 = op0_op.ok_or_else(|| {
            VirtualMachineError::FailedToComputeOperands(Box::new(("op0".to_string(), op0_addr)))
        })?;
        Ok(op0)
    }

    fn compute_op1_deductions(
        &self,
        op1_addr: Relocatable,
        res: &mut Option<MaybeRelocatable>,
        instruction: &Instruction,
        dst_op: &Option<MaybeRelocatable>,
        op0: &MaybeRelocatable,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
        let op1_op = match self.deduce_memory_cell(op1_addr)? {
            None => {
                let (op1, deduced_res) =
                    self.deduce_op1(instruction, dst_op.as_ref(), Some(op0.clone()))?;
                if res.is_none() {
                    *res = deduced_res
                }
                op1
            }
            deduced_memory_cell => deduced_memory_cell,
        };
        let op1 = op1_op.ok_or_else(|| {
            VirtualMachineError::FailedToComputeOperands(Box::new(("op1".to_string(), op1_addr)))
        })?;
        Ok(op1)
    }

    /// Compute operands and result, trying to deduce them if normal memory access returns a None
    /// value.
    pub fn compute_operands(
        &self,
        instruction: &Instruction,
    ) -> Result<(Operands, OperandsAddresses, DeducedOperands), VirtualMachineError> {
        //Get operands from memory
        let dst_addr = self.run_context.compute_dst_addr(instruction)?;
        let dst_op = self.segments.memory.get(&dst_addr).map(Cow::into_owned);

        let op0_addr = self.run_context.compute_op0_addr(instruction)?;
        let op0_op = self.segments.memory.get(&op0_addr).map(Cow::into_owned);

        let op1_addr = self
            .run_context
            .compute_op1_addr(instruction, op0_op.as_ref())?;
        let op1_op = self.segments.memory.get(&op1_addr).map(Cow::into_owned);

        let mut res: Option<MaybeRelocatable> = None;

        let mut deduced_operands = DeducedOperands::default();

        //Deduce op0 if it wasnt previously computed
        let op0 = match op0_op {
            Some(op0) => op0,
            None => {
                deduced_operands.set_op0(true);
                self.compute_op0_deductions(op0_addr, &mut res, instruction, &dst_op, &op1_op)?
            }
        };

        //Deduce op1 if it wasnt previously computed
        let op1 = match op1_op {
            Some(op1) => op1,
            None => {
                deduced_operands.set_op1(true);
                self.compute_op1_deductions(op1_addr, &mut res, instruction, &dst_op, &op0)?
            }
        };

        //Compute res if it wasnt previously deduced
        if res.is_none() {
            res = self.compute_res(instruction, &op0, &op1)?;
        }

        //Deduce dst if it wasnt previously computed
        let dst = match dst_op {
            Some(dst) => dst,
            None => {
                deduced_operands.set_dst(true);
                self.deduce_dst(instruction, &res)?
            }
        };
        let accessed_addresses = OperandsAddresses {
            dst_addr,
            op0_addr,
            op1_addr,
        };
        Ok((
            Operands { dst, op0, op1, res },
            accessed_addresses,
            deduced_operands,
        ))
    }

    ///Makes sure that all assigned memory cells are consistent with their auto deduction rules.
    pub fn verify_auto_deductions(&self) -> Result<(), VirtualMachineError> {
        for builtin in self.builtin_runners.iter() {
            let index: usize = builtin.base();
            for (offset, value) in self.segments.memory.data[index].iter().enumerate() {
                if let Some(deduced_memory_cell) = builtin
                    .deduce_memory_cell(
                        Relocatable::from((index as isize, offset)),
                        &self.segments.memory,
                    )
                    .map_err(VirtualMachineError::RunnerError)?
                {
                    let value = value.get_value();
                    if Some(&deduced_memory_cell) != value.as_ref() && value.is_some() {
                        return Err(VirtualMachineError::InconsistentAutoDeduction(Box::new((
                            builtin.name(),
                            deduced_memory_cell,
                            value,
                        ))));
                    }
                }
            }
        }
        Ok(())
    }

    //Makes sure that the value at the given address is consistent with the auto deduction rules.
    pub fn verify_auto_deductions_for_addr(
        &self,
        addr: Relocatable,
        builtin: &BuiltinRunner,
    ) -> Result<(), VirtualMachineError> {
        let value = match builtin.deduce_memory_cell(addr, &self.segments.memory)? {
            Some(value) => value,
            None => return Ok(()),
        };
        let current_value = match self.segments.memory.get(&addr) {
            Some(value) => value.into_owned(),
            None => return Ok(()),
        };
        if value != current_value {
            return Err(VirtualMachineError::InconsistentAutoDeduction(Box::new((
                builtin.name(),
                value,
                Some(current_value),
            ))));
        }
        Ok(())
    }

    pub fn end_run(&mut self, exec_scopes: &ExecutionScopes) -> Result<(), VirtualMachineError> {
        self.verify_auto_deductions()?;
        self.run_finished = true;
        match exec_scopes.data.len() {
            1 => Ok(()),
            _ => Err(ExecScopeError::NoScopeError.into()),
        }
    }

    pub fn mark_address_range_as_accessed(
        &mut self,
        base: Relocatable,
        len: usize,
    ) -> Result<(), VirtualMachineError> {
        if !self.run_finished {
            return Err(VirtualMachineError::RunNotFinished);
        }
        for i in 0..len {
            self.segments.memory.mark_as_accessed((base + i)?);
        }
        Ok(())
    }

    // Returns the values (fp, pc) corresponding to each call instruction in the traceback.
    // Returns the most recent call last.
    pub(crate) fn get_traceback_entries(&self) -> Vec<(Relocatable, Relocatable)> {
        let mut entries = Vec::<(Relocatable, Relocatable)>::new();
        let mut fp = Relocatable::from((1, self.run_context.fp));
        // Fetch the fp and pc traceback entries
        for _ in 0..MAX_TRACEBACK_ENTRIES {
            // Get return pc
            let ret_pc = match (fp - 1)
                .ok()
                .map(|r| self.segments.memory.get_relocatable(r))
            {
                Some(Ok(opt_pc)) => opt_pc,
                _ => break,
            };
            // Get fp traceback
            match (fp - 2)
                .ok()
                .map(|r| self.segments.memory.get_relocatable(r))
            {
                Some(Ok(opt_fp)) if opt_fp != fp => fp = opt_fp,
                _ => break,
            }
            // Try to check if the call instruction is (instruction0, instruction1) or just
            // instruction1 (with no immediate).
            let call_pc = match (ret_pc - 1)
                .ok()
                .map(|r| self.segments.memory.get_integer(r))
            {
                Some(Ok(instruction1)) => {
                    match is_call_instruction(&instruction1) {
                        true => (ret_pc - 1).unwrap(), // This unwrap wont fail as it is checked before
                        false => {
                            match (ret_pc - 2)
                                .ok()
                                .map(|r| self.segments.memory.get_integer(r))
                            {
                                Some(Ok(instruction0)) => {
                                    match is_call_instruction(&instruction0) {
                                        true => (ret_pc - 2).unwrap(), // This unwrap wont fail as it is checked before
                                        false => break,
                                    }
                                }
                                _ => break,
                            }
                        }
                    }
                }
                _ => break,
            };
            // Append traceback entries
            entries.push((fp, call_pc))
        }
        entries.reverse();
        entries
    }

    ///Adds a new segment and to the memory and returns its starting location as a Relocatable value.
    pub fn add_memory_segment(&mut self) -> Relocatable {
        self.segments.add()
    }

    pub fn get_ap(&self) -> Relocatable {
        self.run_context.get_ap()
    }

    pub fn get_fp(&self) -> Relocatable {
        self.run_context.get_fp()
    }

    pub fn get_pc(&self) -> Relocatable {
        self.run_context.get_pc()
    }

    pub fn get_current_step(&self) -> usize {
        self.current_step
    }

    ///Gets the integer value corresponding to the Relocatable address
    pub fn get_integer(&self, key: Relocatable) -> Result<Cow<Felt>, MemoryError> {
        self.segments.memory.get_integer(key)
    }

    ///Gets the relocatable value corresponding to the Relocatable address
    pub fn get_relocatable(&self, key: Relocatable) -> Result<Relocatable, MemoryError> {
        self.segments.memory.get_relocatable(key)
    }

    ///Gets a MaybeRelocatable value from memory indicated by a generic address
    pub fn get_maybe<'a, 'b: 'a, K: 'a>(&'b self, key: &'a K) -> Option<MaybeRelocatable>
    where
        Relocatable: TryFrom<&'a K>,
    {
        self.segments.memory.get(key).map(|x| x.into_owned())
    }

    /// Returns a reference to the vector with all builtins present in the virtual machine
    pub fn get_builtin_runners(&self) -> &Vec<BuiltinRunner> {
        &self.builtin_runners
    }

    /// Returns a mutable reference to the vector with all builtins present in the virtual machine
    pub fn get_builtin_runners_as_mut(&mut self) -> &mut Vec<BuiltinRunner> {
        &mut self.builtin_runners
    }

    /// Returns a mutable iterator over all builtin runners used. That is, both builtin_runners and
    /// simulated_builtin_runners.
    pub fn get_all_builtin_runners_as_mut_iter(
        &mut self,
    ) -> impl Iterator<Item = &mut BuiltinRunner> {
        self.builtin_runners
            .iter_mut()
            .chain(self.simulated_builtin_runners.iter_mut())
    }

    ///Inserts a value into a memory address given by a Relocatable value
    pub fn insert_value<T: Into<MaybeRelocatable>>(
        &mut self,
        key: Relocatable,
        val: T,
    ) -> Result<(), MemoryError> {
        self.segments.memory.insert_value(key, val)
    }

    ///Writes data into the memory from address ptr and returns the first address after the data.
    pub fn load_data(
        &mut self,
        ptr: Relocatable,
        data: &[MaybeRelocatable],
    ) -> Result<Relocatable, MemoryError> {
        if ptr.segment_index == 0 {
            self.instruction_cache.resize(data.len(), None);
        }
        self.segments.load_data(ptr, data)
    }

    /// Writes args into the memory from address ptr and returns the first address after the data.
    pub fn write_arg(
        &mut self,
        ptr: Relocatable,
        arg: &dyn Any,
    ) -> Result<MaybeRelocatable, MemoryError> {
        self.segments.write_arg(ptr, arg)
    }

    pub fn memcmp(&self, lhs: Relocatable, rhs: Relocatable, len: usize) -> (Ordering, usize) {
        self.segments.memory.memcmp(lhs, rhs, len)
    }

    pub fn mem_eq(&self, lhs: Relocatable, rhs: Relocatable, len: usize) -> bool {
        self.segments.memory.mem_eq(lhs, rhs, len)
    }

    pub fn is_accessed(&self, addr: &Relocatable) -> Result<bool, MemoryError> {
        self.segments.is_accessed(addr)
    }

    ///Gets `n_ret` return values from memory
    pub fn get_return_values(&self, n_ret: usize) -> Result<Vec<MaybeRelocatable>, MemoryError> {
        let addr = (self.run_context.get_ap() - n_ret)
            .map_err(|_| MemoryError::FailedToGetReturnValues(Box::new((n_ret, self.get_ap()))))?;
        self.segments.memory.get_continuous_range(addr, n_ret)
    }

    ///Gets n elements from memory starting from addr (n being size)
    pub fn get_range(&self, addr: Relocatable, size: usize) -> Vec<Option<Cow<MaybeRelocatable>>> {
        self.segments.memory.get_range(addr, size)
    }

    ///Gets n elements from memory starting from addr (n being size)
    pub fn get_continuous_range(
        &self,
        addr: Relocatable,
        size: usize,
    ) -> Result<Vec<MaybeRelocatable>, MemoryError> {
        self.segments.memory.get_continuous_range(addr, size)
    }

    ///Gets n integer values from memory starting from addr (n being size),
    pub fn get_integer_range(
        &self,
        addr: Relocatable,
        size: usize,
    ) -> Result<Vec<Cow<Felt>>, MemoryError> {
        self.segments.memory.get_integer_range(addr, size)
    }

    /// Gets n u32 values from memory starting from addr (n being size).
    /// Returns an error if any of the values inside the range is missing (memory gap) or is not a u32.
    pub fn get_u32_range(&self, addr: Relocatable, size: usize) -> Result<Vec<u32>, MemoryError> {
        self.segments.memory.get_u32_range(addr, size)
    }

    pub fn get_range_check_builtin(
        &self,
    ) -> Result<&RangeCheckBuiltinRunner<RC_N_PARTS_STANDARD>, VirtualMachineError> {
        for builtin in &self.builtin_runners {
            if let BuiltinRunner::RangeCheck(range_check_builtin) = builtin {
                return Ok(range_check_builtin);
            };
        }
        Err(VirtualMachineError::NoRangeCheckBuiltin)
    }

    pub fn get_signature_builtin(
        &mut self,
    ) -> Result<&mut SignatureBuiltinRunner, VirtualMachineError> {
        for builtin in self.get_all_builtin_runners_as_mut_iter() {
            if let BuiltinRunner::Signature(signature_builtin) = builtin {
                return Ok(signature_builtin);
            };
        }

        Err(VirtualMachineError::NoSignatureBuiltin)
    }

    pub fn get_output_builtin_mut(
        &mut self,
    ) -> Result<&mut OutputBuiltinRunner, VirtualMachineError> {
        for builtin in self.get_builtin_runners_as_mut() {
            if let BuiltinRunner::Output(output_builtin) = builtin {
                return Ok(output_builtin);
            };
        }

        Err(VirtualMachineError::NoOutputBuiltin)
    }

    #[cfg(feature = "tracer")]
    pub fn relocate_segments(&self) -> Result<Vec<usize>, MemoryError> {
        self.segments.relocate_segments()
    }

    #[doc(hidden)]
    pub fn skip_next_instruction_execution(&mut self) {
        self.skip_instruction_execution = true;
    }

    #[doc(hidden)]
    pub fn set_ap(&mut self, ap: usize) {
        self.run_context.set_ap(ap)
    }

    #[doc(hidden)]
    pub fn set_fp(&mut self, fp: usize) {
        self.run_context.set_fp(fp)
    }

    #[doc(hidden)]
    pub fn set_pc(&mut self, pc: Relocatable) {
        self.run_context.set_pc(pc)
    }

    pub fn get_segment_used_size(&self, index: usize) -> Option<usize> {
        self.segments.get_segment_used_size(index)
    }

    pub fn get_segment_size(&self, index: usize) -> Option<usize> {
        self.segments.get_segment_size(index)
    }

    pub fn add_temporary_segment(&mut self) -> Relocatable {
        self.segments.add_temporary_segment()
    }

    /// Add a new relocation rule.
    ///
    /// When using feature "extensive_hints" the destination is allowed to be an Integer (via
    /// MaybeRelocatable). Relocating memory to anything other than a `Relocatable` is generally
    /// not useful, but it does make the implementation consistent with the pythonic version.
    ///
    /// Will return an error if any of the following conditions are not met:
    ///   - Source address's segment must be negative (temporary).
    ///   - Source address's offset must be zero.
    ///   - There shouldn't already be relocation at the source segment.
    pub fn add_relocation_rule(
        &mut self,
        src_ptr: Relocatable,
        #[cfg(not(feature = "extensive_hints"))] dst_ptr: Relocatable,
        #[cfg(feature = "extensive_hints")] dst_ptr: MaybeRelocatable,
    ) -> Result<(), MemoryError> {
        self.segments.memory.add_relocation_rule(src_ptr, dst_ptr)
    }

    pub fn gen_arg(&mut self, arg: &dyn Any) -> Result<MaybeRelocatable, MemoryError> {
        self.segments.gen_arg(arg)
    }

    /// Write the values hosted in the output builtin's segment.
    /// Does nothing if the output builtin is not present in the program.
    pub fn write_output(
        &mut self,
        writer: &mut impl core::fmt::Write,
    ) -> Result<(), VirtualMachineError> {
        let builtin = match self
            .builtin_runners
            .iter()
            .find(|b| b.name() == BuiltinName::output)
        {
            Some(x) => x,
            _ => return Ok(()),
        };

        let segment_used_sizes = self.segments.compute_effective_sizes();
        let segment_index = builtin.base();
        for i in 0..segment_used_sizes[segment_index] {
            let formatted_value = match self
                .segments
                .memory
                .get(&Relocatable::from((segment_index as isize, i)))
            {
                Some(val) => match val.as_ref() {
                    MaybeRelocatable::Int(num) => format!("{}", signed_felt(*num)),
                    MaybeRelocatable::RelocatableValue(rel) => format!("{}", rel),
                },
                _ => "<missing>".to_string(),
            };
            writeln!(writer, "{formatted_value}")
                .map_err(|_| VirtualMachineError::FailedToWriteOutput)?;
        }

        Ok(())
    }

    /// Returns a list of addresses of memory cells that constitute the public memory.
    pub fn get_public_memory_addresses(&self) -> Result<Vec<(usize, usize)>, VirtualMachineError> {
        if let Some(relocation_table) = &self.relocation_table {
            self.segments
                .get_public_memory_addresses(relocation_table)
                .map_err(VirtualMachineError::Memory)
        } else {
            Err(MemoryError::UnrelocatedMemory.into())
        }
    }

    #[doc(hidden)]
    pub fn builtins_final_stack_from_stack_pointer_dict(
        &mut self,
        builtin_name_to_stack_pointer: &HashMap<BuiltinName, Relocatable>,
        skip_output: bool,
    ) -> Result<(), RunnerError> {
        for builtin in self.builtin_runners.iter_mut() {
            if matches!(builtin, BuiltinRunner::Output(_)) && skip_output {
                continue;
            }
            builtin.final_stack(
                &self.segments,
                builtin_name_to_stack_pointer
                    .get(&builtin.name())
                    .cloned()
                    .unwrap_or_default(),
            )?;
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn set_output_stop_ptr_offset(&mut self, offset: usize) {
        if let Some(BuiltinRunner::Output(builtin)) = self.builtin_runners.first_mut() {
            builtin.set_stop_ptr_offset(offset);
            if let Some(segment_used_sizes) = &mut self.segments.segment_used_sizes {
                segment_used_sizes[builtin.base()] = offset;
            }
        }
    }

    /// Fetches add_mod & mul_mod builtins according to the optional arguments and executes `fill_memory`
    /// Returns an error if either of this optional parameters is true but the corresponding builtin is not present
    /// Verifies that both builtin's (if present) batch sizes match the batch_size arg if set
    // This method is needed as running `fill_memory` direclty from outside the vm struct would require cloning the builtin runners to avoid double borrowing
    pub fn mod_builtin_fill_memory(
        &mut self,
        add_mod_ptr_n: Option<(Relocatable, usize)>,
        mul_mod_ptr_n: Option<(Relocatable, usize)>,
        batch_size: Option<usize>,
    ) -> Result<(), VirtualMachineError> {
        let fetch_builtin_params = |mod_params: Option<(Relocatable, usize)>,
                                    mod_name: BuiltinName|
         -> Result<
            Option<(Relocatable, &ModBuiltinRunner, usize)>,
            VirtualMachineError,
        > {
            if let Some((ptr, n)) = mod_params {
                let mod_builtin = self
                    .builtin_runners
                    .iter()
                    .find_map(|b| match b {
                        BuiltinRunner::Mod(b) if b.name() == mod_name => Some(b),
                        _ => None,
                    })
                    .ok_or_else(|| VirtualMachineError::NoModBuiltin(mod_name))?;
                if let Some(batch_size) = batch_size {
                    if mod_builtin.batch_size() != batch_size {
                        return Err(VirtualMachineError::ModBuiltinBatchSize(Box::new((
                            mod_builtin.name(),
                            batch_size,
                        ))));
                    }
                }
                Ok(Some((ptr, mod_builtin, n)))
            } else {
                Ok(None)
            }
        };

        ModBuiltinRunner::fill_memory(
            &mut self.segments.memory,
            fetch_builtin_params(add_mod_ptr_n, BuiltinName::add_mod)?,
            fetch_builtin_params(mul_mod_ptr_n, BuiltinName::mul_mod)?,
        )
        .map_err(VirtualMachineError::RunnerError)
    }

    pub(crate) fn finalize_segments_by_cairo_pie(&mut self, pie: &CairoPie) {
        let mut segment_infos = vec![
            &pie.metadata.program_segment,
            &pie.metadata.execution_segment,
            &pie.metadata.ret_fp_segment,
            &pie.metadata.ret_pc_segment,
        ];
        segment_infos.extend(pie.metadata.builtin_segments.values());
        segment_infos.extend(pie.metadata.extra_segments.iter());
        for info in segment_infos {
            self.segments
                .finalize(Some(info.size), info.index as usize, None)
        }
    }
}

pub struct VirtualMachineBuilder {
    pub(crate) run_context: RunContext,
    pub(crate) builtin_runners: Vec<BuiltinRunner>,
    pub(crate) segments: MemorySegmentManager,
    pub(crate) trace: Option<Vec<TraceEntry>>,
    pub(crate) current_step: usize,
    skip_instruction_execution: bool,
    run_finished: bool,
    #[cfg(feature = "test_utils")]
    pub(crate) hooks: crate::vm::hooks::Hooks,
}

impl Default for VirtualMachineBuilder {
    fn default() -> Self {
        let run_context = RunContext {
            pc: Relocatable::from((0, 0)),
            ap: 0,
            fp: 0,
        };

        VirtualMachineBuilder {
            run_context,
            builtin_runners: Vec::new(),
            trace: None,
            current_step: 0,
            skip_instruction_execution: false,
            segments: MemorySegmentManager::new(),
            run_finished: false,
            #[cfg(feature = "test_utils")]
            hooks: Default::default(),
        }
    }
}

impl VirtualMachineBuilder {
    pub fn run_context(mut self, run_context: RunContext) -> VirtualMachineBuilder {
        self.run_context = run_context;
        self
    }

    pub fn builtin_runners(mut self, builtin_runners: Vec<BuiltinRunner>) -> VirtualMachineBuilder {
        self.builtin_runners = builtin_runners;
        self
    }

    pub fn segments(mut self, segments: MemorySegmentManager) -> VirtualMachineBuilder {
        self.segments = segments;
        self
    }

    pub fn trace(mut self, trace: Option<Vec<TraceEntry>>) -> VirtualMachineBuilder {
        self.trace = trace;
        self
    }

    pub fn current_step(mut self, current_step: usize) -> VirtualMachineBuilder {
        self.current_step = current_step;
        self
    }

    pub fn skip_instruction_execution(
        mut self,
        skip_instruction_execution: bool,
    ) -> VirtualMachineBuilder {
        self.skip_instruction_execution = skip_instruction_execution;
        self
    }

    pub fn run_finished(mut self, run_finished: bool) -> VirtualMachineBuilder {
        self.run_finished = run_finished;
        self
    }

    #[cfg(feature = "test_utils")]
    pub fn hooks(mut self, hooks: crate::vm::hooks::Hooks) -> VirtualMachineBuilder {
        self.hooks = hooks;
        self
    }

    pub fn build(self) -> VirtualMachine {
        VirtualMachine {
            run_context: self.run_context,
            builtin_runners: self.builtin_runners,
            simulated_builtin_runners: Vec::new(),
            trace: self.trace,
            current_step: self.current_step,
            skip_instruction_execution: self.skip_instruction_execution,
            segments: self.segments,
            rc_limits: None,
            run_finished: self.run_finished,
            instruction_cache: Vec::new(),
            #[cfg(feature = "test_utils")]
            hooks: self.hooks,
            relocation_table: None,
            disable_trace_padding: false,
        }
    }
}
