use crate::math_utils::{ec_add, ec_double};
use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use crate::vm::errors::memory_errors::MemoryError;
use crate::vm::errors::runner_errors::RunnerError;
use crate::vm::vm_memory::memory::{Memory, ValidationRule};
use crate::vm::vm_memory::memory_segments::MemorySegmentManager;
use crate::{bigint, bigint_str};
use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};
use starknet_crypto::{pedersen_hash, FieldElement};
use std::any::Any;
use std::ops::Shl;

pub struct RangeCheckBuiltinRunner {
    _ratio: BigInt,
    base: usize,
    _stop_ptr: Option<Relocatable>,
    _cells_per_instance: i32,
    _n_input_cells: i32,
    _inner_rc_bound: BigInt,
    pub _bound: BigInt,
    _n_parts: u32,
}
pub struct OutputBuiltinRunner {
    base: usize,
    _stop_ptr: Option<Relocatable>,
}

pub struct HashBuiltinRunner {
    pub base: usize,
    _ratio: usize,
    cells_per_instance: usize,
    _n_input_cells: usize,
    _stop_ptr: Option<Relocatable>,
    verified_addresses: Vec<MaybeRelocatable>,
}

pub struct BitwiseBuiltinRunner {
    _ratio: usize,
    pub base: usize,
    cells_per_instance: usize,
    _n_input_cells: usize,
    total_n_bits: u32,
}

pub struct EcOpBuiltinRunner {
    _ratio: usize,
    pub base: usize,
    cells_per_instance: usize,
    n_input_cells: usize,
    scalar_height: usize,
    _scalar_bits: usize,
    scalar_limit: BigInt,
}

pub trait BuiltinRunner {
    ///Creates the necessary segments for the builtin in the MemorySegmentManager and stores the first address on the builtin's base
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager, memory: &mut Memory);
    fn initial_stack(&self) -> Vec<MaybeRelocatable>;
    ///Returns the builtin's base
    fn base(&self) -> Relocatable;
    fn add_validation_rule(&self, memory: &mut Memory);
    fn deduce_memory_cell(
        &mut self,
        address: &MaybeRelocatable,
        memory: &Memory,
    ) -> Result<Option<MaybeRelocatable>, RunnerError>;
    fn as_any(&self) -> &dyn Any;
}

impl RangeCheckBuiltinRunner {
    pub fn new(ratio: BigInt, n_parts: u32) -> RangeCheckBuiltinRunner {
        let inner_rc_bound = bigint!(1i32 << 16);
        RangeCheckBuiltinRunner {
            _ratio: ratio,
            base: 0,
            _stop_ptr: None,
            _cells_per_instance: 1,
            _n_input_cells: 1,
            _inner_rc_bound: inner_rc_bound.clone(),
            _bound: inner_rc_bound.pow(n_parts),
            _n_parts: n_parts,
        }
    }
}
impl BuiltinRunner for RangeCheckBuiltinRunner {
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager, memory: &mut Memory) {
        self.base = segments.add(memory).segment_index
    }

    fn initial_stack(&self) -> Vec<MaybeRelocatable> {
        vec![MaybeRelocatable::from((self.base, 0))]
    }

    fn base(&self) -> Relocatable {
        Relocatable::from((self.base, 0))
    }

    fn add_validation_rule(&self, memory: &mut Memory) {
        let rule: ValidationRule = ValidationRule(Box::new(
            |memory: &Memory,
             address: &MaybeRelocatable|
             -> Result<MaybeRelocatable, MemoryError> {
                if let Some(MaybeRelocatable::Int(ref num)) = memory.get(address)? {
                    if &BigInt::zero() <= num && num < &BigInt::one().shl(128u8) {
                        Ok(address.to_owned())
                    } else {
                        Err(MemoryError::NumOutOfBounds)
                    }
                } else {
                    Err(MemoryError::FoundNonInt)
                }
            },
        ));
        memory.add_validation_rule(self.base, rule);
    }

    fn deduce_memory_cell(
        &mut self,
        _address: &MaybeRelocatable,
        _memory: &Memory,
    ) -> Result<Option<MaybeRelocatable>, RunnerError> {
        Ok(None)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl OutputBuiltinRunner {
    pub fn new() -> OutputBuiltinRunner {
        OutputBuiltinRunner {
            base: 0,
            _stop_ptr: None,
        }
    }
}

impl BuiltinRunner for OutputBuiltinRunner {
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager, memory: &mut Memory) {
        self.base = segments.add(memory).segment_index
    }

    fn initial_stack(&self) -> Vec<MaybeRelocatable> {
        vec![MaybeRelocatable::from((self.base, 0))]
    }

    fn base(&self) -> Relocatable {
        Relocatable::from((self.base, 0))
    }

    fn add_validation_rule(&self, _memory: &mut Memory) {}

    fn deduce_memory_cell(
        &mut self,
        _address: &MaybeRelocatable,
        _memory: &Memory,
    ) -> Result<Option<MaybeRelocatable>, RunnerError> {
        Ok(None)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl HashBuiltinRunner {
    pub fn new(ratio: usize) -> Self {
        HashBuiltinRunner {
            base: 0,

            _ratio: ratio,
            cells_per_instance: 3,
            _n_input_cells: 2,
            _stop_ptr: None,
            verified_addresses: Vec::new(),
        }
    }
}

impl BuiltinRunner for HashBuiltinRunner {
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager, memory: &mut Memory) {
        self.base = segments.add(memory).segment_index
    }

    fn initial_stack(&self) -> Vec<MaybeRelocatable> {
        vec![MaybeRelocatable::from((self.base, 0))]
    }

    fn base(&self) -> Relocatable {
        Relocatable::from((self.base, 0))
    }

    fn add_validation_rule(&self, _memory: &mut Memory) {}

    fn deduce_memory_cell(
        &mut self,
        address: &MaybeRelocatable,
        memory: &Memory,
    ) -> Result<Option<MaybeRelocatable>, RunnerError> {
        if let &MaybeRelocatable::RelocatableValue(ref relocatable) = address {
            if relocatable.offset.mod_floor(&self.cells_per_instance) != 2
                || self.verified_addresses.contains(address)
            {
                return Ok(None);
            };
            if let (
                Ok(Some(MaybeRelocatable::Int(num_a))),
                Ok(Some(MaybeRelocatable::Int(num_b))),
            ) = (
                memory.get(&MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: relocatable.segment_index,
                    offset: relocatable.offset - 1,
                })),
                memory.get(&MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: relocatable.segment_index,
                    offset: relocatable.offset - 2,
                })),
            ) {
                self.verified_addresses.push(address.clone());

                //Convert MaybeRelocatable to FieldElement
                let a_string = num_a.to_str_radix(10);
                let b_string = num_b.to_str_radix(10);
                let (y, x) = match (
                    FieldElement::from_dec_str(&a_string),
                    FieldElement::from_dec_str(&b_string),
                ) {
                    (Ok(field_element_a), Ok(field_element_b)) => {
                        (field_element_a, field_element_b)
                    }
                    _ => return Err(RunnerError::FailedStringConversion),
                };
                //Compute pedersen Hash
                let fe_result = pedersen_hash(&x, &y);
                //Convert result from FieldElement to MaybeRelocatable
                let r_byte_slice = fe_result.to_bytes_be();
                let result = BigInt::from_bytes_be(Sign::Plus, &r_byte_slice);
                return Ok(Some(MaybeRelocatable::from(result)));
            }
            Ok(None)
        } else {
            Err(RunnerError::NonRelocatableAddress)
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl BitwiseBuiltinRunner {
    pub fn new(ratio: usize) -> Self {
        BitwiseBuiltinRunner {
            base: 0,

            _ratio: ratio,
            cells_per_instance: 5,
            _n_input_cells: 2,
            total_n_bits: 251,
        }
    }
}

impl BuiltinRunner for BitwiseBuiltinRunner {
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager, memory: &mut Memory) {
        self.base = segments.add(memory).segment_index
    }

    fn initial_stack(&self) -> Vec<MaybeRelocatable> {
        vec![MaybeRelocatable::from((self.base, 0))]
    }

    fn base(&self) -> Relocatable {
        Relocatable::from((self.base, 0))
    }

    fn add_validation_rule(&self, _memory: &mut Memory) {}

    fn deduce_memory_cell(
        &mut self,
        address: &MaybeRelocatable,
        memory: &Memory,
    ) -> Result<Option<MaybeRelocatable>, RunnerError> {
        if let &MaybeRelocatable::RelocatableValue(ref relocatable) = address {
            let index = relocatable.offset.mod_floor(&self.cells_per_instance);
            if index == 0 || index == 1 {
                return Ok(None);
            }
            let x_addr =
                MaybeRelocatable::from((relocatable.segment_index, relocatable.offset - index));
            let y_addr = x_addr.add_usize_mod(1, None);
            if let (
                Ok(Some(MaybeRelocatable::Int(num_x))),
                Ok(Some(MaybeRelocatable::Int(num_y))),
            ) = (memory.get(&x_addr), memory.get(&y_addr))
            {
                let _2_pow_bits = bigint!(1).shl(self.total_n_bits);
                if num_x >= &_2_pow_bits {
                    return Err(RunnerError::IntegerBiggerThanPowerOfTwo(
                        x_addr,
                        self.total_n_bits,
                        num_x.clone(),
                    ));
                };
                if num_y >= &_2_pow_bits {
                    return Err(RunnerError::IntegerBiggerThanPowerOfTwo(
                        y_addr,
                        self.total_n_bits,
                        num_y.clone(),
                    ));
                };
                let res = match index {
                    2 => Some(MaybeRelocatable::from(num_x & num_y)),
                    3 => Some(MaybeRelocatable::from(num_x ^ num_y)),
                    4 => Some(MaybeRelocatable::from(num_x | num_y)),
                    _ => None,
                };
                return Ok(res);
            }
            Ok(None)
        } else {
            Err(RunnerError::NonRelocatableAddress)
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
impl Default for OutputBuiltinRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl EcOpBuiltinRunner {
    pub fn new(ratio: usize) -> Self {
        EcOpBuiltinRunner {
            base: 0,
            _ratio: ratio,
            n_input_cells: 5,
            cells_per_instance: 7,
            scalar_height: 256,
            _scalar_bits: 252,
            scalar_limit: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
        }
    }
    ///Returns True if the point (x, y) is on the elliptic curve defined as
    ///y^2 = x^3 + alpha * x + beta (mod p)
    ///or False otherwise.
    fn point_on_curve(
        x: &BigInt,
        y: &BigInt,
        alpha: &BigInt,
        beta: &BigInt,
        prime: &BigInt,
    ) -> bool {
        (y.pow(2).mod_floor(prime)) == (x.pow(3) + alpha * x + beta).mod_floor(prime)
    }

    ///Returns the result of the EC operation P + m * Q.
    /// where P = (p_x, p_y), Q = (q_x, q_y) are points on the elliptic curve defined as
    /// y^2 = x^3 + alpha * x + beta (mod prime).
    /// Mimics the operation of the AIR, so that this function fails whenever the builtin AIR
    /// would not yield a correct result, i.e. when any part of the computation attempts to add
    /// two points with the same x coordinate.
    fn ec_op_impl(
        mut partial_sum: (BigInt, BigInt),
        mut doubled_point: (BigInt, BigInt),
        m: &BigInt,
        alpha: &BigInt,
        prime: &BigInt,
        height: usize,
    ) -> Result<(BigInt, BigInt), RunnerError> {
        let mut slope = m.clone();
        for _ in 0..height {
            if (doubled_point.0.clone() - partial_sum.0.clone()) % prime == bigint!(0) {
                return Err(RunnerError::EcOpSameXCoordinate(
                    partial_sum,
                    m.clone(),
                    doubled_point,
                ));
            };
            if slope.clone() & bigint!(1) != bigint!(0) {
                partial_sum = ec_add(partial_sum, doubled_point.clone(), prime);
            }
            doubled_point = ec_double(doubled_point, alpha, prime);
            slope = slope.clone() >> 1_i32;
        }
        Ok(partial_sum)
    }
}

impl BuiltinRunner for EcOpBuiltinRunner {
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager, memory: &mut Memory) {
        self.base = segments.add(memory).segment_index
    }

    fn initial_stack(&self) -> Vec<MaybeRelocatable> {
        vec![MaybeRelocatable::from((self.base, 0))]
    }

    fn base(&self) -> Relocatable {
        Relocatable::from((self.base, 0))
    }
    fn add_validation_rule(&self, _memory: &mut Memory) {}

    fn deduce_memory_cell(
        &mut self,
        address: &MaybeRelocatable,
        memory: &Memory,
    ) -> Result<Option<MaybeRelocatable>, RunnerError> {
        if let &MaybeRelocatable::RelocatableValue(ref relocatable) = address {
            //Constant values declared here
            const EC_POINT_INDICES: [(usize, usize); 3] = [(0, 1), (2, 3), (5, 6)];
            const M_INDEX: usize = 4;
            const OUTPUT_INDICES: (usize, usize) = EC_POINT_INDICES[2];
            let alpha: BigInt = bigint!(1);
            let beta: BigInt = bigint_str!(
                b"3141592653589793238462643383279502884197169399375105820974944592307816406665"
            );
            let field_prime = bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            );

            let index = relocatable.offset.mod_floor(&self.cells_per_instance);
            //Index should be an output cell
            if index != OUTPUT_INDICES.0 && index != OUTPUT_INDICES.1 {
                return Ok(None);
            }
            let instance =
                MaybeRelocatable::from((relocatable.segment_index, relocatable.offset - index));
            //All input cells should be filled, and be integer values
            //If an input cell is not filled, return None
            let mut input_cells = Vec::<&BigInt>::with_capacity(self.n_input_cells);
            for i in 0..self.n_input_cells {
                match memory
                    .get(&instance.add_usize_mod(i, None))
                    .map_err(RunnerError::FailedMemoryGet)?
                {
                    None => return Ok(None),
                    Some(addr) => {
                        if let &MaybeRelocatable::Int(ref num) = addr {
                            input_cells.push(num);
                        } else {
                            return Err(RunnerError::ExpectedInteger(
                                instance.add_usize_mod(i, None),
                            ));
                        }
                    }
                };
            }
            //Assert that m is under the limit defined by scalar_limit.
            if input_cells[M_INDEX] >= &self.scalar_limit {
                return Err(RunnerError::EcOpBuiltinScalarLimit(
                    self.scalar_limit.clone(),
                ));
            }

            // Assert that if the current address is part of a point, the point is on the curve
            for pair in &EC_POINT_INDICES[0..1] {
                if !EcOpBuiltinRunner::point_on_curve(
                    input_cells[pair.0],
                    input_cells[pair.1],
                    &alpha,
                    &beta,
                    &field_prime,
                ) {
                    return Err(RunnerError::PointNotOnCurve(*pair));
                };
            }
            let result = EcOpBuiltinRunner::ec_op_impl(
                (input_cells[0].clone(), input_cells[1].clone()),
                (input_cells[2].clone(), input_cells[3].clone()),
                input_cells[4],
                &alpha,
                &field_prime,
                self.scalar_height,
            )?;
            match index - self.n_input_cells {
                0 => Ok(Some(MaybeRelocatable::Int(result.0))),
                _ => Ok(Some(MaybeRelocatable::Int(result.1))),
                //Default case corresponds to 1, as there are no other possible cases
            }
        } else {
            Err(RunnerError::NonRelocatableAddress)
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bigint, bigint_str, utils::test_utils::*, vm::vm_memory::memory::Memory};

    #[test]
    fn initialize_segments_for_output() {
        let mut builtin = OutputBuiltinRunner::new();
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        builtin.initialize_segments(&mut segments, &mut memory);
        assert_eq!(builtin.base, 0);
    }

    #[test]
    fn initialize_segments_for_range_check() {
        let mut builtin = RangeCheckBuiltinRunner::new(bigint!(8), 8);
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        builtin.initialize_segments(&mut segments, &mut memory);
        assert_eq!(builtin.base, 0);
    }

    #[test]
    fn get_initial_stack_for_range_check_with_base() {
        let mut builtin = RangeCheckBuiltinRunner::new(bigint!(8), 8);
        builtin.base = 1;
        let initial_stack = builtin.initial_stack();
        assert_eq!(
            initial_stack[0].clone(),
            MaybeRelocatable::RelocatableValue(builtin.base())
        );
        assert_eq!(initial_stack.len(), 1);
    }

    #[test]
    fn get_initial_stack_for_output_with_base() {
        let mut builtin = OutputBuiltinRunner::new();
        builtin.base = 1;
        let initial_stack = builtin.initial_stack();
        assert_eq!(
            initial_stack[0].clone(),
            MaybeRelocatable::RelocatableValue(builtin.base())
        );
        assert_eq!(initial_stack.len(), 1);
    }

    #[test]
    fn deduce_memory_cell_pedersen_for_preset_memory_valid() {
        let memory = memory![((0, 3), 32), ((0, 4), 72), ((0, 5), 0)];
        let mut builtin = HashBuiltinRunner::new(8);

        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from((0, 5)), &memory);
        assert_eq!(
            result,
            Ok(Some(MaybeRelocatable::from(bigint_str!(
                b"3270867057177188607814717243084834301278723532952411121381966378910183338911"
            ))))
        );
        assert_eq!(
            builtin.verified_addresses,
            vec![MaybeRelocatable::from((0, 5))]
        );
    }

    #[test]
    fn deduce_memory_cell_pedersen_for_preset_memory_incorrect_offset() {
        let memory = memory![((0, 4), 32), ((0, 5), 72), ((0, 6), 0)];
        let mut builtin = HashBuiltinRunner::new(8);
        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from((0, 6)), &memory);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn deduce_memory_cell_pedersen_for_preset_memory_no_values_to_hash() {
        let memory = memory![((0, 4), 72), ((0, 5), 0)];
        let mut builtin = HashBuiltinRunner::new(8);
        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from((0, 5)), &memory);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn deduce_memory_cell_pedersen_for_preset_memory_already_computed() {
        let memory = memory![((0, 3), 32), ((0, 4), 72), ((0, 5), 0)];
        let mut builtin = HashBuiltinRunner::new(8);
        builtin.verified_addresses = vec![MaybeRelocatable::from((0, 5))];
        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from((0, 5)), &memory);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn deduce_memory_cell_pedersen_for_no_relocatable_address() {
        let memory = Memory::new();
        let mut builtin = HashBuiltinRunner::new(8);
        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from(bigint!(5)), &memory);
        assert_eq!(result, Err(RunnerError::NonRelocatableAddress));
    }

    #[test]
    fn deduce_memory_cell_bitwise_for_preset_memory_valid_and() {
        let memory = memory![((0, 5), 10), ((0, 6), 12), ((0, 7), 0)];
        let mut builtin = BitwiseBuiltinRunner::new(256);
        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from((0, 7)), &memory);
        assert_eq!(result, Ok(Some(MaybeRelocatable::from(bigint!(8)))));
    }

    #[test]
    fn deduce_memory_cell_bitwise_for_preset_memory_valid_xor() {
        let memory = memory![((0, 5), 10), ((0, 6), 12), ((0, 8), 0)];
        let mut builtin = BitwiseBuiltinRunner::new(256);
        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from((0, 8)), &memory);
        assert_eq!(result, Ok(Some(MaybeRelocatable::from(bigint!(6)))));
    }

    #[test]
    fn deduce_memory_cell_bitwise_for_preset_memory_valid_or() {
        let memory = memory![((0, 5), 10), ((0, 6), 12), ((0, 9), 0)];
        let mut builtin = BitwiseBuiltinRunner::new(256);
        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from((0, 9)), &memory);
        assert_eq!(result, Ok(Some(MaybeRelocatable::from(bigint!(14)))));
    }

    #[test]
    fn deduce_memory_cell_bitwise_for_preset_memory_incorrect_offset() {
        let memory = memory![((0, 3), 10), ((0, 4), 12), ((0, 5), 0)];
        let mut builtin = BitwiseBuiltinRunner::new(256);
        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from((0, 5)), &memory);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn deduce_memory_cell_bitwise_for_preset_memory_no_values_to_operate() {
        let memory = memory![((0, 5), 12), ((0, 7), 0)];
        let mut builtin = BitwiseBuiltinRunner::new(256);
        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from((0, 5)), &memory);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn deduce_memory_cell_bitwise_for_no_relocatable_address() {
        let memory = Memory::new();
        let mut builtin = BitwiseBuiltinRunner::new(256);
        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from(bigint!(5)), &memory);
        assert_eq!(result, Err(RunnerError::NonRelocatableAddress));
    }

    #[test]
    fn point_is_on_curve_a() {
        let x = bigint_str!(
            b"874739451078007766457464989774322083649278607533249481151382481072868806602"
        );
        let y = bigint_str!(
            b"152666792071518830868575557812948353041420400780739481342941381225525861407"
        );
        let alpha = bigint!(1);
        let beta = bigint_str!(
            b"3141592653589793238462643383279502884197169399375105820974944592307816406665"
        );
        let prime = bigint_str!(
            b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        assert!(EcOpBuiltinRunner::point_on_curve(
            &x, &y, &alpha, &beta, &prime
        ));
    }

    #[test]
    fn point_is_on_curve_b() {
        let x = bigint_str!(
            b"3139037544796708144595053687182055617920475701120786241351436619796497072089"
        );
        let y = bigint_str!(
            b"2119589567875935397690285099786081818522144748339117565577200220779667999801"
        );
        let alpha = bigint!(1);
        let beta = bigint_str!(
            b"3141592653589793238462643383279502884197169399375105820974944592307816406665"
        );
        let prime = bigint_str!(
            b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        assert!(EcOpBuiltinRunner::point_on_curve(
            &x, &y, &alpha, &beta, &prime
        ));
    }

    #[test]
    fn point_is_not_on_curve_a() {
        let x = bigint_str!(
            b"874739454078007766457464989774322083649278607533249481151382481072868806602"
        );
        let y = bigint_str!(
            b"152666792071518830868575557812948353041420400780739481342941381225525861407"
        );
        let alpha = bigint!(1);
        let beta = bigint_str!(
            b"3141592653589793238462643383279502884197169399375105820974944592307816406665"
        );
        let prime = bigint_str!(
            b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        assert!(!EcOpBuiltinRunner::point_on_curve(
            &x, &y, &alpha, &beta, &prime
        ));
    }

    #[test]
    fn point_is_not_on_curve_b() {
        let x = bigint_str!(
            b"3139037544756708144595053687182055617927475701120786241351436619796497072089"
        );
        let y = bigint_str!(
            b"2119589567875935397690885099786081818522144748339117565577200220779667999801"
        );
        let alpha = bigint!(1);
        let beta = bigint_str!(
            b"3141592653589793238462643383279502884197169399375105820974944592307816406665"
        );
        let prime = bigint_str!(
            b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        assert!(!EcOpBuiltinRunner::point_on_curve(
            &x, &y, &alpha, &beta, &prime
        ));
    }

    #[test]
    fn compute_ec_op_impl_valid_a() {
        let partial_sum = (
            bigint_str!(
                b"3139037544796708144595053687182055617920475701120786241351436619796497072089"
            ),
            bigint_str!(
                b"2119589567875935397690285099786081818522144748339117565577200220779667999801"
            ),
        );
        let doubled_point = (
            bigint_str!(
                b"874739451078007766457464989774322083649278607533249481151382481072868806602"
            ),
            bigint_str!(
                b"152666792071518830868575557812948353041420400780739481342941381225525861407"
            ),
        );
        let m = bigint!(34);
        let alpha = bigint!(1);
        let height = 256;
        let prime = bigint_str!(
            b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        let result =
            EcOpBuiltinRunner::ec_op_impl(partial_sum, doubled_point, &m, &alpha, &prime, height);
        assert_eq!(
            result,
            Ok((
                bigint_str!(
                    b"1977874238339000383330315148209250828062304908491266318460063803060754089297"
                ),
                bigint_str!(
                    b"2969386888251099938335087541720168257053975603483053253007176033556822156706"
                )
            ))
        );
    }

    #[test]
    fn compute_ec_op_impl_valid_b() {
        let partial_sum = (
            bigint_str!(
                b"2962412995502985605007699495352191122971573493113767820301112397466445942584"
            ),
            bigint_str!(
                b"214950771763870898744428659242275426967582168179217139798831865603966154129"
            ),
        );
        let doubled_point = (
            bigint_str!(
                b"874739451078007766457464989774322083649278607533249481151382481072868806602"
            ),
            bigint_str!(
                b"152666792071518830868575557812948353041420400780739481342941381225525861407"
            ),
        );
        let m = bigint!(34);
        let alpha = bigint!(1);
        let height = 256;
        let prime = bigint_str!(
            b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        let result =
            EcOpBuiltinRunner::ec_op_impl(partial_sum, doubled_point, &m, &alpha, &prime, height);
        assert_eq!(
            result,
            Ok((
                bigint_str!(
                    b"2778063437308421278851140253538604815869848682781135193774472480292420096757"
                ),
                bigint_str!(
                    b"3598390311618116577316045819420613574162151407434885460365915347732568210029"
                )
            ))
        );
    }

    #[test]
    /* Data taken from this program execution:
       %builtins output ec_op
       from starkware.cairo.common.cairo_builtins import EcOpBuiltin
       from starkware.cairo.common.serialize import serialize_word
       from starkware.cairo.common.ec_point import EcPoint
       from starkware.cairo.common.ec import ec_op

       func main{output_ptr: felt*, ec_op_ptr: EcOpBuiltin*}():
           let x: EcPoint = EcPoint(2089986280348253421170679821480865132823066470938446095505822317253594081284, 1713931329540660377023406109199410414810705867260802078187082345529207694986)

           let y: EcPoint = EcPoint(874739451078007766457464989774322083649278607533249481151382481072868806602,152666792071518830868575557812948353041420400780739481342941381225525861407)
           let z: EcPoint = ec_op(x,34, y)
           serialize_word(z.x)
           return()
           end
    */
    fn deduce_memory_cell_ec_op_for_preset_memory_valid() {
        let memory = memory![
            (
                (3, 0),
                (
                    b"2962412995502985605007699495352191122971573493113767820301112397466445942584",
                    10
                )
            ),
            (
                (3, 1),
                (
                    b"214950771763870898744428659242275426967582168179217139798831865603966154129",
                    10
                )
            ),
            (
                (3, 2),
                (
                    b"874739451078007766457464989774322083649278607533249481151382481072868806602",
                    10
                )
            ),
            (
                (3, 3),
                (
                    b"152666792071518830868575557812948353041420400780739481342941381225525861407",
                    10
                )
            ),
            ((3, 4), 34),
            (
                (3, 5),
                (
                    b"2778063437308421278851140253538604815869848682781135193774472480292420096757",
                    10
                )
            )
        ];
        let mut builtin = EcOpBuiltinRunner::new(256);

        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from((3, 6)), &memory);
        assert_eq!(
            result,
            Ok(Some(MaybeRelocatable::from(bigint_str!(
                b"3598390311618116577316045819420613574162151407434885460365915347732568210029"
            ))))
        );
    }

    #[test]
    fn deduce_memory_cell_ec_op_for_preset_memory_unfilled_input_cells() {
        let memory = memory![
            (
                (3, 1),
                (
                    b"214950771763870898744428659242275426967582168179217139798831865603966154129",
                    10
                )
            ),
            (
                (3, 2),
                (
                    b"874739451078007766457464989774322083649278607533249481151382481072868806602",
                    10
                )
            ),
            (
                (3, 3),
                (
                    b"152666792071518830868575557812948353041420400780739481342941381225525861407",
                    10
                )
            ),
            ((3, 4), 34),
            (
                (3, 5),
                (
                    b"2778063437308421278851140253538604815869848682781135193774472480292420096757",
                    10
                )
            )
        ];

        let mut builtin = EcOpBuiltinRunner::new(256);
        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from((3, 6)), &memory);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn deduce_memory_cell_ec_op_for_preset_memory_addr_not_an_output_cell() {
        let memory = memory![
            (
                (3, 0),
                (
                    b"2962412995502985605007699495352191122971573493113767820301112397466445942584",
                    10
                )
            ),
            (
                (3, 1),
                (
                    b"214950771763870898744428659242275426967582168179217139798831865603966154129",
                    10
                )
            ),
            (
                (3, 2),
                (
                    b"874739451078007766457464989774322083649278607533249481151382481072868806602",
                    10
                )
            ),
            (
                (3, 3),
                (
                    b"152666792071518830868575557812948353041420400780739481342941381225525861407",
                    10
                )
            ),
            ((3, 4), 34),
            (
                (3, 5),
                (
                    b"2778063437308421278851140253538604815869848682781135193774472480292420096757",
                    10
                )
            )
        ];
        let mut builtin = EcOpBuiltinRunner::new(256);

        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from((3, 3)), &memory);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn deduce_memory_cell_ec_op_for_preset_memory_non_integer_input() {
        let memory = memory![
            (
                (3, 0),
                (
                    b"2962412995502985605007699495352191122971573493113767820301112397466445942584",
                    10
                )
            ),
            (
                (3, 1),
                (
                    b"214950771763870898744428659242275426967582168179217139798831865603966154129",
                    10
                )
            ),
            (
                (3, 2),
                (
                    b"874739451078007766457464989774322083649278607533249481151382481072868806602",
                    10
                )
            ),
            ((3, 3), (1, 2)),
            ((3, 4), 34),
            (
                (3, 5),
                (
                    b"2778063437308421278851140253538604815869848682781135193774472480292420096757",
                    10
                )
            )
        ];
        let mut builtin = EcOpBuiltinRunner::new(256);

        assert_eq!(
            builtin.deduce_memory_cell(&MaybeRelocatable::from((3, 6)), &memory),
            Err(RunnerError::ExpectedInteger(MaybeRelocatable::from((3, 3))))
        );
    }

    #[test]
    fn deduce_memory_cell_ec_op_for_preset_memory_m_over_scalar_limit() {
        let memory = memory![
            (
                (3, 0),
                (
                    b"2962412995502985605007699495352191122971573493113767820301112397466445942584",
                    10
                )
            ),
            (
                (3, 1),
                (
                    b"214950771763870898744428659242275426967582168179217139798831865603966154129",
                    10
                )
            ),
            (
                (3, 2),
                (
                    b"874739451078007766457464989774322083649278607533249481151382481072868806602",
                    10
                )
            ),
            (
                (3, 3),
                (
                    b"152666792071518830868575557812948353041420400780739481342941381225525861407",
                    10
                )
            ),
            //Scalar Limit + 1
            (
                (3, 4),
                (
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020482",
                    10
                )
            ),
            (
                (3, 5),
                (
                    b"2778063437308421278851140253538604815869848682781135193774472480292420096757",
                    10
                )
            )
        ];
        let mut builtin = EcOpBuiltinRunner::new(256);

        let error = builtin.deduce_memory_cell(&MaybeRelocatable::from((3, 6)), &memory);
        assert_eq!(
            error,
            Err(RunnerError::EcOpBuiltinScalarLimit(
                builtin.scalar_limit.clone()
            ))
        );
    }
}
