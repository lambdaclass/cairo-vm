use core::array;
use core::borrow::Borrow;

use crate::stdlib::borrow::Cow;

use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use crate::vm::errors::memory_errors::MemoryError;
use crate::vm::errors::runner_errors::RunnerError;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::vm_memory::memory::Memory;
use crate::vm::vm_memory::memory_segments::MemorySegmentManager;
use crate::Felt252;

use crate::types::instance_definitions::mod_instance_def::ModInstanceDef;

//The maximum n value that the function fill_memory accepts.
const FILL_MEMORY_MAX: usize = 100000;

const INPUT_NAMES: [&str; 7] = ["p0", "p1", "p2", "p3", "values_ptr", "offsets_ptr", "n"];

const MEMORY_VAR_NAMES: [&str; 15] = [
    "a_offset", "b_offset", "c_offset", "a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3", "c0", "c1",
    "c2", "c3",
];

const INPUT_CELLS: usize = INPUT_NAMES.len();
const ADDITIONAL_MEMORY_UNITS: usize = MEMORY_VAR_NAMES.len();

#[derive(Debug, Clone)]
pub struct ModBuiltinRunner {
    builtin_type: ModBuiltinType,
    base: usize,
    instance_def: ModInstanceDef,
    included: bool,
    zero_segment_index: usize,
    zero_segment_size: usize,
    // Precomputed powers used for reading and writing values that are represented as n_words words of word_bit_len bits each.
    shift: Felt252,
    shift_powers: Vec<Felt252>,
}

#[derive(Debug, Clone)]
pub enum ModBuiltinType {
    Mul,
    Add,
}

impl ModBuiltinRunner {
    pub fn new_add_mod(instance_def: ModInstanceDef, included: bool) -> Self {
        Self::new(instance_def, included, ModBuiltinType::Add)
    }

    pub fn new_mul_mod(instance_def: ModInstanceDef, included: bool) -> Self {
        Self::new(instance_def, included, ModBuiltinType::Mul)
    }

    fn new(instance_def: ModInstanceDef, included: bool, builtin_type: ModBuiltinType) -> Self {
        let shift = Felt252::TWO.pow(instance_def.word_bit_len);
        let shift_powers = (0..instance_def.n_words).map(|i| shift.pow(i)).collect();
        let zero_segment_size =
            core::cmp::max(instance_def.n_words, instance_def.batch_size * 3) as usize;
        Self {
            builtin_type,
            base: 0,
            instance_def,
            included,
            zero_segment_index: 0,
            zero_segment_size,
            shift,
            shift_powers,
        }
    }

    pub fn initialize_segments(&mut self, segments: &mut MemorySegmentManager) {
        self.base = segments.add().segment_index as usize; // segments.add() always returns a positive index
        self.zero_segment_index = segments.add_zero_segment(self.zero_segment_size)
    }

    // Reads self.instance_def.n_words from memory, starting at address=addr.
    // Returns the words and the value if all words are in memory.
    // Verifies that all words are integers and are bounded by 2**self.instance_def.word_bit_len.
    fn read_n_words_value(
        &mut self,
        memory: &mut Memory,
        addr: Relocatable,
    ) -> Result<(Vec<Felt252>, Option<Felt252>), RunnerError> {
        let mut words = Vec::new();
        let mut value = Felt252::ZERO;
        for i in 0..self.instance_def.n_words {
            let addr_i = (addr + i)?;
            match memory.get(&addr_i).map(Cow::into_owned) {
                None => return Ok((vec![], None)),
                Some(MaybeRelocatable::RelocatableValue(f)) => {
                    return Err(MemoryError::ExpectedInteger(Box::new(addr_i)).into())
                }
                Some(MaybeRelocatable::Int(word)) => {
                    if word >= self.shift {
                        return Err(RunnerError::WordExceedsModBuiltinWordBitLen(
                            addr_i,
                            self.instance_def.word_bit_len,
                            word,
                        ));
                    }
                    words.push(word);
                    value += word * self.shift_powers[i as usize];
                }
            }
        }
        Ok((words, Some(value)))
    }
}
