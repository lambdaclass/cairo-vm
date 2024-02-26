use cairo_vm::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{errors::memory_errors::MemoryError, vm_core::VirtualMachine},
    Felt252,
};
use itertools::Itertools;
use std::{collections::HashMap, iter::Peekable, slice::Iter};

#[derive(Debug)]
pub(crate) enum Output {
    Felt(Felt252),
    FeltSpan(Vec<Output>),
    FeltDict(HashMap<Felt252, Output>),
    CannotBeFormatted,
}

impl Output {
    pub fn from_memory(vm: &VirtualMachine, relocatable: &Relocatable) -> Self {
        match vm.get_relocatable(*relocatable) {
            Ok(relocatable_value) => {
                let segment_size = vm
                    .get_segment_size(relocatable_value.segment_index as usize)
                    .unwrap();
                let segment_data = vm
                    .get_continuous_range(relocatable_value, segment_size)
                    .unwrap();

                // check if the segment data is a valid array of felts
                if segment_data
                    .iter()
                    .all(|v| matches!(v, MaybeRelocatable::Int(_)))
                {
                    let span_segment: Vec<Output> = segment_data
                        .iter()
                        .map(|v| Output::Felt(v.get_int().unwrap()))
                        .collect();
                    Output::FeltSpan(span_segment)
                } else {
                    Output::CannotBeFormatted
                }
            }
            Err(MemoryError::UnknownMemoryCell(relocatable_value)) => {
                // here we assume that the value is a dictionary
                let mut felt252dict: HashMap<Felt252, Output> = HashMap::new();

                let segment_size = vm
                    .get_segment_size(relocatable_value.segment_index as usize)
                    .unwrap();
                let mut segment_start = relocatable_value.clone();
                segment_start.offset = 0;
                let segment_data = vm
                    .get_continuous_range(*segment_start, segment_size)
                    .unwrap();
                dbg!(&segment_data);

                // chunk by tuples of 3 elements
                segment_data
                    .iter()
                    .tuples()
                    .for_each(|(dict_key, _, value_relocatable)| {
                        let key = dict_key.get_int().unwrap();
                        let value_segment = value_relocatable.get_relocatable().unwrap();
                        let value = Output::from_memory(vm, &value_segment);
                        dbg!(&value);
                        felt252dict.insert(key, value);
                    });
                Output::FeltDict(felt252dict)
            }
            _ => Output::CannotBeFormatted,
        }
    }
}

impl std::fmt::Display for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Output::Felt(felt) => write!(f, "{}", felt.to_hex_string()),
            Output::FeltSpan(span) => {
                write!(f, "[")?;
                for elem in span {
                    write!(f, "{}", elem)?;
                    write!(f, ",")?;
                }
                writeln!(f, "]")?;
                Ok(())
            }
            Output::FeltDict(felt_dict) => {
                let mut keys: Vec<_> = felt_dict.keys().collect();
                keys.sort();
                writeln!(f, "{{")?;
                for key in keys {
                    writeln!(f, "{}: {}", key.to_hex_string(), felt_dict[key])?;
                }
                writeln!(f, "}}")?;
                Ok(())
            }
            Output::CannotBeFormatted => write!(f, "Output cannot be formatted"),
        }
    }
}

pub(crate) fn serialize_output(vm: &VirtualMachine, return_values: &[MaybeRelocatable]) -> String {
    let mut output_string = String::new();
    let mut return_values_iter: Peekable<Iter<MaybeRelocatable>> = return_values.iter().peekable();
    serialize_output_inner(&mut return_values_iter, &mut output_string, vm);

    output_string
}

fn maybe_add_whitespace(string: &mut String) {
    if !string.is_empty() && !string.ends_with('[') {
        string.push(' ');
    }
}

fn serialize_output_inner(
    iter: &mut Peekable<Iter<MaybeRelocatable>>,
    output_string: &mut String,
    vm: &VirtualMachine,
) {
    while let Some(val) = iter.next() {
        match val {
            MaybeRelocatable::Int(x) => {
                maybe_add_whitespace(output_string);
                output_string.push_str(&x.to_string());
                continue;
            }
            MaybeRelocatable::RelocatableValue(x) if iter.len() == 2 /* felt array */ => {
                // Check if the next value is a relocatable of the same index
                let y = iter.next().unwrap().get_relocatable().unwrap();
                // Check if the two relocatable values represent a valid array in memory
                if x.segment_index == y.segment_index && x.offset <= y.offset {
                        // Fetch the y value from the iterator so we don't serialize it twice
                        iter.next();
                        // Fetch array
                        maybe_add_whitespace(output_string);
                        output_string.push('[');
                        let array = vm.get_continuous_range(*x, y.offset - x.offset).unwrap();
                        let mut array_iter: Peekable<Iter<MaybeRelocatable>> =
                            array.iter().peekable();
                        serialize_output_inner(&mut array_iter, output_string, vm);
                        output_string.push(']');
                        continue;
                    }
                },
            MaybeRelocatable::RelocatableValue(x) => {
                let output = Output::from_memory(vm, x);
                output_string.push_str(format!("{}", output).as_str())
            }
        }
    }
}
