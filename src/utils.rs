use crate::types::relocatable::Relocatable;
use num_bigint::BigInt;
use num_integer::Integer;
use std::ops::Shr;

#[macro_export]
macro_rules! bigint {
    ($val : expr) => {
        Into::<BigInt>::into($val)
    };
}

#[macro_export]
macro_rules! bigint_str {
    ($val: expr) => {
        BigInt::parse_bytes($val, 10).unwrap()
    };
    ($val: expr, $opt: expr) => {
        BigInt::parse_bytes($val, $opt).unwrap()
    };
}

#[macro_export]
macro_rules! relocatable {
    ($val1 : expr, $val2 : expr) => {
        Relocatable {
            segment_index: ($val1),
            offset: ($val2),
        }
    };
}

#[macro_export]
macro_rules! any_box {
    ($val : expr) => {
        Box::new($val) as Box<dyn Any>
    };
}

pub fn is_subsequence<T: PartialEq>(subsequence: &[T], mut sequence: &[T]) -> bool {
    for search in subsequence {
        if let Some(index) = sequence.iter().position(|element| search == element) {
            sequence = &sequence[index + 1..];
        } else {
            return false;
        }
    }
    true
}

pub fn from_relocatable_to_indexes(relocatable: &Relocatable) -> (usize, usize) {
    (relocatable.segment_index.abs() as usize, relocatable.offset)
}

///Converts val to an integer in the range (-prime/2, prime/2) which is
///equivalent to val modulo prime.
pub fn to_field_element(num: BigInt, prime: BigInt) -> BigInt {
    let half_prime = prime.clone().shr(1_usize);
    ((num + &half_prime).mod_floor(&prime)) - half_prime
}

#[cfg(test)]
#[macro_use]
pub mod test_utils {
    use lazy_static::lazy_static;
    use num_bigint::BigInt;

    lazy_static! {
        pub static ref VM_PRIME: BigInt = BigInt::parse_bytes(
            b"3618502788666131213697322783095070105623107215331596699973092056135872020481",
            10,
        )
        .unwrap();
    }

    macro_rules! memory {
        ( $( (($si:expr, $off:expr), $val:tt) ),* ) => {
            {
                let mut memory = Memory::new();
                memory_from_memory!(memory, ( $( (($si, $off), $val) ),* ));
                memory
            }
        };
    }
    pub(crate) use memory;

    macro_rules! memory_from_memory {
        ($mem: expr, ( $( (($si:expr, $off:expr), $val:tt) ),* )) => {
            {
                $(
                    memory_inner!($mem, ($si, $off), $val);
                )*
            }
        };
    }
    pub(crate) use memory_from_memory;

    macro_rules! memory_inner {
        ($mem:expr, ($si:expr, $off:expr), ($sival:expr, $offval: expr)) => {
            let (k, v) = (
                &mayberelocatable!($si, $off),
                &mayberelocatable!($sival, $offval),
            );
            let mut res = $mem.insert(k, v);
            while matches!(res, Err(MemoryError::UnallocatedSegment(_, _))) {
                $mem.data.push(Vec::new());
                res = $mem.insert(k, v);
            }
        };
        ($mem:expr, ($si:expr, $off:expr), $val:expr) => {
            let (k, v) = (&mayberelocatable!($si, $off), &mayberelocatable!($val));
            let mut res = $mem.insert(k, v);
            while matches!(res, Err(MemoryError::UnallocatedSegment(_, _))) {
                $mem.data.push(Vec::new());
                res = $mem.insert(k, v);
            }
        };
    }
    pub(crate) use memory_inner;

    macro_rules! check_memory {
        ( $mem: expr, $( (($si:expr, $off:expr), $val:tt) ),* ) => {
            $(
                check_memory_address!($mem, ($si, $off), $val);
            )*
        };
    }
    pub(crate) use check_memory;

    macro_rules! check_memory_address {
        ($mem:expr, ($si:expr, $off:expr), ($sival:expr, $offval: expr)) => {
            assert_eq!(
                $mem.get(&mayberelocatable!($si, $off)),
                Ok(Some(&mayberelocatable!($sival, $offval)))
            )
        };
        ($mem:expr, ($si:expr, $off:expr), $val:expr) => {
            assert_eq!(
                $mem.get(&mayberelocatable!($si, $off)),
                Ok(Some(&mayberelocatable!($val)))
            )
        };
    }
    pub(crate) use check_memory_address;

    macro_rules! mayberelocatable {
        ($val1 : expr, $val2 : expr) => {
            MaybeRelocatable::from(($val1, $val2))
        };
        ($val1 : expr) => {
            MaybeRelocatable::from((bigint!($val1)))
        };
    }
    pub(crate) use mayberelocatable;

    macro_rules! from_bigint_str {
        ( $( $val: expr ),* ) => {
            $(
                impl From<(&[u8; $val], u32)> for MaybeRelocatable {
                    fn from(val_base: (&[u8; $val], u32)) -> Self {
                        MaybeRelocatable::from(bigint_str!(val_base.0, val_base.1))
                    }
                }
            )*
        }
    }
    pub(crate) use from_bigint_str;

    macro_rules! references {
        ($num: expr) => {{
            let mut references = HashMap::<usize, HintReference>::new();
            for i in 0..$num {
                references.insert(i as usize, HintReference::new_simple((i as i32 - $num)));
            }
            references
        }};
    }
    pub(crate) use references;

    macro_rules! vm_with_range_check {
        () => {{
            let mut vm = VirtualMachine::new(
                BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
                false,
            );
            vm.builtin_runners = vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(bigint!(8), 8)),
            )];
            vm
        }};
    }
    pub(crate) use vm_with_range_check;

    macro_rules! vm {
        () => {{
            VirtualMachine::new(
                BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
                false,
            )
        }};

        ($use_trace:expr) => {{
            VirtualMachine::new(
                BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
                $use_trace,
            )
        }};
    }
    pub(crate) use vm;

    macro_rules! run_context {
        ( $vm: expr, $pc_off: expr, $ap_off: expr, $fp_off: expr ) => {
            $vm.run_context.pc = Relocatable::from((0, $pc_off));
            $vm.run_context.ap = $ap_off;
            $vm.run_context.fp = $fp_off;
        };
    }
    pub(crate) use run_context;

    macro_rules! ids_data {
        ( $( $name: expr ),* ) => {
            {
                let ids_names = vec![$( $name ),*];
                let references = references!(ids_names.len() as i32);
                let mut ids_data = HashMap::<String, HintReference>::new();
                for (i, name) in ids_names.iter().enumerate() {
                    ids_data.insert(name.to_string(), references.get(&i).unwrap().clone());
                }
                ids_data
            }
        };
    }
    pub(crate) use ids_data;

    macro_rules! non_continuous_ids_data {
        ( $( ($name: expr, $offset:expr) ),* ) => {
            {
                let mut ids_data = HashMap::<String, HintReference>::new();
                $(
                    ids_data.insert(String::from($name), HintReference::new_simple($offset));
                )*
                ids_data
            }
        };
    }
    pub(crate) use non_continuous_ids_data;

    macro_rules! trace_check {
        ( $trace: expr, [ $( (($si_pc:expr, $off_pc:expr), ($si_ap:expr, $off_ap:expr), ($si_fp:expr, $off_fp:expr)) ),+ ] ) => {
            let mut index = -1;
            $(
                index += 1;
                assert_eq!(
                    $trace[index as usize],
                    TraceEntry {
                        pc: Relocatable {
                            segment_index: $si_pc,
                            offset: $off_pc
                        },
                        ap: Relocatable {
                            segment_index: $si_ap,
                            offset: $off_ap
                        },
                        fp: Relocatable {
                            segment_index: $si_fp,
                            offset: $off_fp
                        },
                    }
                );
            )*
        };
    }
    pub(crate) use trace_check;

    macro_rules! exec_scopes_ref {
        () => {
            &mut ExecutionScopes::new()
        };
    }
    pub(crate) use exec_scopes_ref;

    macro_rules! exec_scopes_proxy_ref {
        () => {
            &mut get_exec_scopes_proxy(&mut ExecutionScopes::new())
        };
    }
    pub(crate) use exec_scopes_proxy_ref;

    macro_rules! run_hint {
        ($vm:expr, $ids_data:expr, $hint_code:expr, $exec_proxy:expr) => {{
            let hint_data = HintProcessorData::new_default($hint_code.to_string(), $ids_data);
            let hint_processor = BuiltinHintProcessor::new_empty();
            hint_processor.execute_hint(&mut $vm, $exec_proxy, &any_box!(hint_data))
        }};
        ($vm:expr, $ids_data:expr, $hint_code:expr) => {{
            let hint_data = HintProcessorData::new_default($hint_code.to_string(), $ids_data);
            let hint_processor = BuiltinHintProcessor::new_empty();
            hint_processor.execute_hint(&mut $vm, exec_scopes_proxy_ref!(), &any_box!(hint_data))
        }};
    }
    pub(crate) use run_hint;

    macro_rules! add_segments {
        ($vm:expr, $n:expr) => {
            for _ in 0..$n {
                $vm.segments.add(&mut $vm.memory);
            }
        };
    }
    pub(crate) use add_segments;

    macro_rules! check_scope {
        ( $exec_proxy: expr, [ $( ($name: expr, $val: expr)),* ] ) => {
            $(
                check_scope_value($exec_proxy, $name, $val);
            )*
        };
    }
    pub(crate) use check_scope;

    macro_rules! scope {
        (  $( ($name: expr, $val: expr)),*  ) => {
            {
                let mut exec_scopes = ExecutionScopes::new();
                $(
                    exec_scopes.assign_or_update_variable(
                        $name,
                        any_box!($val),
                    );
                )*
                exec_scopes
            }
        };
    }
    pub(crate) use scope;

    macro_rules! check_dictionary {
        ( $exec_scopes_proxy: expr, $tracker_num:expr, $( ($key:expr, $val:expr )),* ) => {
            $(
                assert_eq!(
                    $exec_scopes_proxy
                        .get_dict_manager()
                        .unwrap()
                        .borrow_mut()
                        .trackers
                        .get_mut(&$tracker_num)
                        .unwrap()
                        .get_value(&bigint!($key)),
                    Ok(&bigint!($val))
                );
            )*
        };
    }
    pub(crate) use check_dictionary;

    macro_rules! check_dict_ptr {
        ($exec_scopes_proxy: expr, $tracker_num: expr, ($i:expr, $off:expr)) => {
            assert_eq!(
                $exec_scopes_proxy
                    .get_dict_manager()
                    .unwrap()
                    .borrow()
                    .trackers
                    .get(&$tracker_num)
                    .unwrap()
                    .current_ptr,
                relocatable!($i, $off)
            );
        };
    }
    pub(crate) use check_dict_ptr;

    macro_rules! dict_manager {
        ($exec_scopes_proxy:expr, $tracker_num:expr, $( ($key:expr, $val:expr )),* ) => {
            let mut tracker = DictTracker::new_empty(&relocatable!($tracker_num, 0));
            $(
            tracker.insert_value(&bigint!($key), &bigint!($val));
            )*
            let mut dict_manager = DictManager::new();
            dict_manager.trackers.insert(2, tracker);
            $exec_scopes_proxy.insert_value("dict_manager", Rc::new(RefCell::new(dict_manager)))
        };
        ($exec_scopes_proxy:expr, $tracker_num:expr) => {
            let  tracker = DictTracker::new_empty(&relocatable!($tracker_num, 0));
            let mut dict_manager = DictManager::new();
            dict_manager.trackers.insert(2, tracker);
            $exec_scopes_proxy.insert_value("dict_manager", Rc::new(RefCell::new(dict_manager)))
        };

    }
    pub(crate) use dict_manager;

    macro_rules! dict_manager_default {
        ($exec_scopes_proxy:expr, $tracker_num:expr,$default:expr, $( ($key:expr, $val:expr )),* ) => {
            let mut tracker = DictTracker::new_default_dict(&relocatable!($tracker_num, 0), &bigint!($default), None);
            $(
            tracker.insert_value(&bigint!($key), &bigint!($val));
            )*
            let mut dict_manager = DictManager::new();
            dict_manager.trackers.insert(2, tracker);
            $exec_scopes_proxy.insert_value("dict_manager", Rc::new(RefCell::new(dict_manager)))
        };
        ($exec_scopes_proxy:expr, $tracker_num:expr,$default:expr) => {
            let tracker = DictTracker::new_default_dict(&relocatable!($tracker_num, 0), &bigint!($default), None);
            let mut dict_manager = DictManager::new();
            dict_manager.trackers.insert(2, tracker);
            $exec_scopes_proxy.insert_value("dict_manager", Rc::new(RefCell::new(dict_manager)))
        };
    }
    pub(crate) use dict_manager_default;

    macro_rules! vec_data {
        ( $( ($val:tt) ),* ) => {
            vec![$( vec_data_inner!($val) ),*]
        };
    }
    pub(crate) use vec_data;

    macro_rules! vec_data_inner {
        (( $val1:expr, $val2:expr )) => {
            mayberelocatable!($val1, $val2)
        };
        ( $val:expr ) => {
            mayberelocatable!($val)
        };
    }
    pub(crate) use vec_data_inner;

    use crate::hint_processor::proxies::exec_scopes_proxy::ExecutionScopesProxy;

    pub fn check_scope_value<T: std::fmt::Debug + std::cmp::PartialEq + 'static>(
        proxy: &ExecutionScopesProxy,
        name: &str,
        value: T,
    ) {
        let scope_value = proxy.get_any_boxed_ref(name).unwrap();
        assert_eq!(scope_value.downcast_ref::<T>(), Some(&value));
    }
}

#[cfg(test)]
mod test {

    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData;
    use crate::hint_processor::builtin_hint_processor::dict_manager::DictManager;
    use crate::hint_processor::builtin_hint_processor::dict_manager::DictTracker;
    use crate::hint_processor::hint_processor_definition::HintProcessor;
    use crate::hint_processor::proxies::exec_scopes_proxy::get_exec_scopes_proxy;
    use crate::types::exec_scope::ExecutionScopes;
    use crate::utils::test_utils::*;
    use std::any::Any;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    use super::*;
    use crate::hint_processor::hint_processor_definition::HintReference;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::trace::trace_entry::TraceEntry;
    use crate::vm::vm_core::VirtualMachine;
    use crate::vm::vm_memory::memory::Memory;
    use num_bigint::Sign;

    #[test]
    fn to_field_element_no_change_a() {
        assert_eq!(
            to_field_element(
                bigint!(1),
                bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
                )
            ),
            bigint!(1)
        );
    }

    #[test]
    fn to_field_element_no_change_b() {
        assert_eq!(
            to_field_element(
                bigint_str!(
                    b"1455766198400600346948407886553099278761386236477570128859274086228078567108"
                ),
                bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
                )
            ),
            bigint_str!(
                b"1455766198400600346948407886553099278761386236477570128859274086228078567108"
            )
        );
    }

    #[test]
    fn to_field_element_num_to_negative_a() {
        assert_eq!(
            to_field_element(
                bigint_str!(
                    b"3270867057177188607814717243084834301278723532952411121381966378910183338911"
                ),
                bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
                )
            ),
            bigint_str!(
                b"-347635731488942605882605540010235804344383682379185578591125677225688681570"
            )
        );
    }

    #[test]
    fn to_field_element_num_to_negative_b() {
        assert_eq!(
            to_field_element(
                bigint_str!(
                    b"3333324623402098338894983297253618187074385014448599840723759915876610845540"
                ),
                bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
                )
            ),
            bigint_str!(
                b"-285178165264032874802339485841451918548722200882996859249332140259261174941"
            )
        );
    }

    #[test]
    fn memory_macro_test() {
        let mut memory = Memory::new();
        for _ in 0..2 {
            memory.data.push(Vec::new());
        }
        memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        let mem = memory![((1, 2), 1), ((1, 1), (1, 0))];
        assert_eq!(memory.data, mem.data);
    }

    #[test]
    fn check_memory_macro_test() {
        let mut memory = Memory::new();
        for _ in 0..2 {
            memory.data.push(Vec::new());
        }
        memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();

        memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        check_memory![memory, ((1, 1), (1, 0)), ((1, 2), 1)];
    }

    #[test]
    fn check_memory_address_macro_test() {
        let mut memory = Memory::new();
        for _ in 0..2 {
            memory.data.push(Vec::new());
        }
        memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();

        memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        check_memory_address!(memory, (1, 1), (1, 0));
        check_memory_address!(memory, (1, 2), 1);
    }

    #[test]
    fn from_bigint_str_test() {
        from_bigint_str![8];
        let may_rel = MaybeRelocatable::from((b"11520396", 10));
        assert_eq!(MaybeRelocatable::from(bigint!(11520396)), may_rel);
    }

    #[test]
    fn create_run_context() {
        let mut vm = vm!();
        run_context!(vm, 2, 6, 10);

        assert_eq!(vm.run_context.pc, Relocatable::from((0, 2)));
        assert_eq!(vm.run_context.ap, 6);
        assert_eq!(vm.run_context.fp, 10);
    }

    #[test]
    fn assert_trace() {
        let trace = vec![
            TraceEntry {
                pc: Relocatable {
                    segment_index: 1,
                    offset: 2,
                },
                ap: Relocatable {
                    segment_index: 3,
                    offset: 7,
                },
                fp: Relocatable {
                    segment_index: 4,
                    offset: 1,
                },
            },
            TraceEntry {
                pc: Relocatable {
                    segment_index: 7,
                    offset: 5,
                },
                ap: Relocatable {
                    segment_index: 4,
                    offset: 1,
                },
                fp: Relocatable {
                    segment_index: 7,
                    offset: 0,
                },
            },
            TraceEntry {
                pc: Relocatable {
                    segment_index: 4,
                    offset: 9,
                },
                ap: Relocatable {
                    segment_index: 5,
                    offset: 5,
                },
                fp: Relocatable {
                    segment_index: 3,
                    offset: 7,
                },
            },
        ];
        trace_check!(
            trace,
            [
                ((1, 2), (3, 7), (4, 1)),
                ((7, 5), (4, 1), (7, 0)),
                ((4, 9), (5, 5), (3, 7))
            ]
        );
    }

    #[test]
    fn test_non_continuous_ids_data() {
        let ids_data_macro = non_continuous_ids_data![("a", -2), ("b", -6)];
        let ids_data_verbose = HashMap::from([
            ("a".to_string(), HintReference::new_simple(-2)),
            ("b".to_string(), HintReference::new_simple(-6)),
        ]);
        assert_eq!(ids_data_macro, ids_data_verbose);
    }

    #[test]
    fn run_hint_alloc() {
        let hint_code = "memory[ap] = segments.add()";
        let mut vm = vm!();
        add_segments!(vm, 1);
        assert_eq!(run_hint!(vm, HashMap::new(), hint_code), Ok(()));
        //A segment is added
        assert_eq!(vm.segments.num_segments, 2);
    }

    #[test]
    fn check_scope_test_pass() {
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("a", any_box!(String::from("Hello")));
        exec_scopes.assign_or_update_variable(
            "b",
            any_box!(Rc::new(RefCell::new(HashMap::<usize, Vec<usize>>::new()))),
        );
        exec_scopes.assign_or_update_variable("c", any_box!(vec![1, 2, 3, 4]));
        let exec_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        check_scope!(
            exec_proxy,
            [
                ("a", String::from("Hello")),
                (
                    "b",
                    Rc::new(RefCell::new(HashMap::<usize, Vec<usize>>::new()))
                ),
                ("c", vec![1, 2, 3, 4])
            ]
        );
    }

    #[test]
    #[should_panic]
    fn check_scope_test_fail() {
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("a", any_box!(String::from("Hello")));
        exec_scopes.assign_or_update_variable(
            "b",
            any_box!(Rc::new(RefCell::new(HashMap::<usize, Vec<usize>>::new()))),
        );
        exec_scopes.assign_or_update_variable("c", any_box!(vec![1, 2, 3, 4]));
        let exec_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        check_scope!(
            exec_proxy,
            [
                ("a", String::from("Hello")),
                (
                    "b",
                    Rc::new(RefCell::new(HashMap::<usize, Vec<usize>>::new()))
                ),
                ("c", vec![1, 2, 3, 5])
            ]
        );
    }

    #[test]
    fn scope_macro_test() {
        let scope_from_macro = scope![("a", bigint!(1))];
        let mut scope_verbose = ExecutionScopes::new();
        scope_verbose.assign_or_update_variable("a", any_box!(bigint!(1)));
        assert_eq!(scope_from_macro.data.len(), scope_verbose.data.len());
        assert_eq!(scope_from_macro.data[0].len(), scope_verbose.data[0].len());
        assert_eq!(
            scope_from_macro.data[0].get("a").unwrap().downcast_ref(),
            Some(&bigint!(1))
        );
    }

    #[test]
    fn check_dictionary_pass() {
        let mut tracker = DictTracker::new_empty(&relocatable!(2, 0));
        tracker.insert_value(&bigint!(5), &bigint!(10));
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(2, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable(
            "dict_manager",
            any_box!(Rc::new(RefCell::new(dict_manager))),
        );
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        check_dictionary!(exec_scopes_proxy, 2, (5, 10));
    }

    #[test]
    #[should_panic]
    fn check_dictionary_fail() {
        let mut tracker = DictTracker::new_empty(&relocatable!(2, 0));
        tracker.insert_value(&bigint!(5), &bigint!(10));
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(2, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable(
            "dict_manager",
            any_box!(Rc::new(RefCell::new(dict_manager))),
        );
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        check_dictionary!(exec_scopes_proxy, 2, (5, 11));
    }

    #[test]
    fn check_dict_ptr_pass() {
        let tracker = DictTracker::new_empty(&relocatable!(2, 0));
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(2, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable(
            "dict_manager",
            any_box!(Rc::new(RefCell::new(dict_manager))),
        );
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        check_dict_ptr!(exec_scopes_proxy, 2, (2, 0));
    }

    #[test]
    #[should_panic]
    fn check_dict_ptr_fail() {
        let tracker = DictTracker::new_empty(&relocatable!(2, 0));
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(2, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable(
            "dict_manager",
            any_box!(Rc::new(RefCell::new(dict_manager))),
        );
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        check_dict_ptr!(exec_scopes_proxy, 2, (3, 0));
    }

    #[test]
    fn dict_manager_macro() {
        let tracker = DictTracker::new_empty(&relocatable!(2, 0));
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(2, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        dict_manager!(exec_scopes_proxy, 2);
        assert_eq!(
            exec_scopes_proxy.get_dict_manager(),
            Ok(Rc::new(RefCell::new(dict_manager)))
        );
    }

    #[test]
    fn dict_manager_default_macro() {
        let tracker = DictTracker::new_default_dict(&relocatable!(2, 0), &bigint!(17), None);
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(2, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        dict_manager_default!(exec_scopes_proxy, 2, 17);
        assert_eq!(
            exec_scopes_proxy.get_dict_manager(),
            Ok(Rc::new(RefCell::new(dict_manager)))
        );
    }

    #[test]
    fn data_vec_test() {
        let data = vec_data!((1), ((2, 2)), ((b"49128305", 10)), ((b"3b6f00a9", 16)));
        assert_eq!(data[0], mayberelocatable!(1));
        assert_eq!(data[1], mayberelocatable!(2, 2));
        assert_eq!(data[2], mayberelocatable!(49128305));
        assert_eq!(data[3], mayberelocatable!(997130409));
    }
}
