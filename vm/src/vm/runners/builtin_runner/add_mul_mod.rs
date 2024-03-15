use core::array;
use core::borrow::Borrow;

use crate::stdlib::{borrow::Cow, collections::HashMap};

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

    pub fn name(&self) -> &str {
        match self.builtin_type {
            ModBuiltinType::Mul => super::MUL_MOD_BUILTIN_NAME,
            ModBuiltinType::Add => super::ADD_MOD_BUILTIN_NAME,
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
        &self,
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

    // Reads the inputs to the builtin (see INPUT_NAMES) from the memory at address=addr.
    // Returns a dictionary from input name to its value. Asserts that it exists in memory.
    // Returns also the value of p, not just its words.
    fn read_inputs(
        &mut self,
        memory: &mut Memory,
        addr: Relocatable,
    ) -> Result<HashMap<&str, MaybeRelocatable>, RunnerError> {
        let mut inputs = HashMap::new();
        // values_ptr
        inputs.insert(INPUT_NAMES[4], memory.get_relocatable((addr + 4)?)?.into());
        // offsets_ptr
        inputs.insert(INPUT_NAMES[5], memory.get_relocatable((addr + 5)?)?.into());
        // n
        let n = memory.get_integer((addr + 6)?)?.into_owned();
        if n < Felt252::ONE {
            return Err(RunnerError::ModBuiltinNLessThanOne(
                self.name().to_string(),
                n,
            ));
        }
        inputs.insert(INPUT_NAMES[6], n.into());
        // p
        let (words, value) = self.read_n_words_value(memory, addr)?;
        let value = value.ok_or_else(|| {
            RunnerError::ModBuiltinMissingValue(
                self.name().to_string(),
                (addr + words.len()).unwrap_or_default(),
            )
        })?;
        inputs.insert("p", value.into());
        for (i, word) in words.iter().enumerate() {
            // pi
            inputs.insert(INPUT_NAMES[i], word.into());
        }
        Ok(inputs)
    }

    // Reads the memory variables to the builtin (see MEMORY_VAR_NAMES) from the memory given
    // the inputs (specifically, values_ptr and offsets_ptr).
    // Returns a dictionary from memory variable name to its value. Asserts if it doesn't exist in
    // memory. Returns also the values of a, b, and c, not just their words.
    fn read_memory_vars(
        &self,
        memory: &mut Memory,
        values_ptr: Relocatable,
        offsets_ptr: Relocatable,
        index_in_batch: usize,
    ) -> Result<HashMap<&str, Felt252>, RunnerError> {
        let mut memory_vars = HashMap::new();
        // abc
        for i in 0..3 {
            let offset = memory
                .get_integer((offsets_ptr + (i + 3 * index_in_batch))?)?
                .into_owned();
            memory_vars.insert(MEMORY_VAR_NAMES[i], offset);

            let value_addr = (values_ptr + &offset)?;
            let (words, value) = self.read_n_words_value(memory, value_addr)?;
            let value = value.ok_or_else(|| {
                RunnerError::ModBuiltinMissingValue(
                    self.name().to_string(),
                    (value_addr + words.len()).unwrap_or_default(),
                )
            })?;
            for (j, word) in words.iter().enumerate() {
                // a0 a1 a2 a3 b0 b1 ... c3
                memory_vars.insert(MEMORY_VAR_NAMES[3 + i * 4 + j], *word);
            }
        }

        Ok(memory_vars)
    }
}
