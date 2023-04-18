use crate::{
    any_box,
    hint_processor::{
        builtin_hint_processor::{
            hint_utils::{
                get_integer_from_var_name, get_relocatable_from_var_name,
                insert_value_from_var_name, insert_value_into_ap,
            },
            secp::{
                bigint_utils::BigInt3,
                secp_utils::{pack, SECP_P},
            },
        },
        hint_processor_definition::HintReference,
    },
    math_utils::{ec_double_slope, line_slope},
    serde::deserialize_program::ApTracking,
    stdlib::{collections::HashMap, ops::BitAnd, prelude::*},
    types::exec_scope::ExecutionScopes,
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};
use felt::Felt252;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};

#[derive(Debug, PartialEq)]
struct EcPoint<'a> {
    x: BigInt3<'a>,
    y: BigInt3<'a>,
}
impl EcPoint<'_> {
    fn from_var_name<'a>(
        name: &'a str,
        vm: &'a VirtualMachine,
        ids_data: &'a HashMap<String, HintReference>,
        ap_tracking: &'a ApTracking,
    ) -> Result<EcPoint<'a>, HintError> {
        // Get first addr of EcPoint struct
        let point_addr = get_relocatable_from_var_name(name, vm, ids_data, ap_tracking)?;
        Ok(EcPoint {
            x: BigInt3::from_base_addr(point_addr, &format!("{}.x", name), vm)?,
            y: BigInt3::from_base_addr((point_addr + 3)?, &format!("{}.y", name), vm)?,
        })
    }
}

/*
Implements hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack

    y = pack(ids.point.y, PRIME) % SECP_P
    # The modulo operation in python always returns a nonnegative number.
    value = (-y) % SECP_P
%}
*/
pub fn ec_negate(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    exec_scopes.assign_or_update_variable("SECP_P", any_box!(SECP_P.clone()));
    //ids.point
    let point_y = (get_relocatable_from_var_name("point", vm, ids_data, ap_tracking)? + 3i32)?;
    let y_bigint3 = BigInt3::from_base_addr(point_y, "point.y", vm)?;
    let y = pack(y_bigint3);
    let value = (-y).mod_floor(&SECP_P);
    exec_scopes.insert_value("value", value);
    Ok(())
}

/*
Implements hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack
    from starkware.python.math_utils import ec_double_slope

    # Compute the slope.
    x = pack(ids.point.x, PRIME)
    y = pack(ids.point.y, PRIME)
    value = slope = ec_double_slope(point=(x, y), alpha=0, p=SECP_P)
%}
*/
pub fn compute_doubling_slope(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    point_alias: &str,
) -> Result<(), HintError> {
    exec_scopes.assign_or_update_variable("SECP_P", any_box!(SECP_P.clone()));
    //ids.point
    let point = EcPoint::from_var_name(point_alias, vm, ids_data, ap_tracking)?;

    let value = ec_double_slope(&(pack(point.x), pack(point.y)), &BigInt::zero(), &SECP_P);
    exec_scopes.insert_value("value", value.clone());
    exec_scopes.insert_value("slope", value);
    Ok(())
}

/*
Implements hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack
    from starkware.python.math_utils import line_slope

    # Compute the slope.
    x0 = pack(ids.point0.x, PRIME)
    y0 = pack(ids.point0.y, PRIME)
    x1 = pack(ids.point1.x, PRIME)
    y1 = pack(ids.point1.y, PRIME)
    value = slope = line_slope(point1=(x0, y0), point2=(x1, y1), p=SECP_P)
%}
*/
pub fn compute_slope(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    point0_alias: &str,
    point1_alias: &str,
) -> Result<(), HintError> {
    exec_scopes.assign_or_update_variable("SECP_P", any_box!(SECP_P.clone()));
    //ids.point0
    let point0 = EcPoint::from_var_name(point0_alias, vm, ids_data, ap_tracking)?;
    //ids.point1
    let point1 = EcPoint::from_var_name(point1_alias, vm, ids_data, ap_tracking)?;

    let value = line_slope(
        &(pack(point0.x), pack(point0.y)),
        &(pack(point1.x), pack(point1.y)),
        &SECP_P,
    );
    exec_scopes.insert_value("value", value.clone());
    exec_scopes.insert_value("slope", value);
    Ok(())
}

/*
Implements hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack

    slope = pack(ids.slope, PRIME)
    x = pack(ids.point.x, PRIME)
    y = pack(ids.point.y, PRIME)

    value = new_x = (pow(slope, 2, SECP_P) - 2 * x) % SECP_P
%}
*/
pub fn ec_double_assign_new_x(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    exec_scopes.assign_or_update_variable("SECP_P", any_box!(SECP_P.clone()));
    //ids.slope
    let slope = BigInt3::from_var_name("slope", vm, ids_data, ap_tracking)?;
    //ids.point
    let point = EcPoint::from_var_name("point", vm, ids_data, ap_tracking)?;

    let slope = pack(slope);
    let x = pack(point.x);
    let y = pack(point.y);

    let value = (slope.pow(2) - (&x << 1u32)).mod_floor(&SECP_P);

    //Assign variables to vm scope
    exec_scopes.insert_value("slope", slope);
    exec_scopes.insert_value("x", x);
    exec_scopes.insert_value("y", y);
    exec_scopes.insert_value("value", value.clone());
    exec_scopes.insert_value("new_x", value);
    Ok(())
}

/*
Implements hint:
%{ value = new_y = (slope * (x - new_x) - y) % SECP_P %}
*/
pub fn ec_double_assign_new_y(exec_scopes: &mut ExecutionScopes) -> Result<(), HintError> {
    //Get variables from vm scope
    let (slope, x, new_x, y) = (
        exec_scopes.get::<BigInt>("slope")?,
        exec_scopes.get::<BigInt>("x")?,
        exec_scopes.get::<BigInt>("new_x")?,
        exec_scopes.get::<BigInt>("y")?,
    );

    let value = (slope * (x - new_x) - y).mod_floor(&SECP_P);
    exec_scopes.insert_value("value", value.clone());
    exec_scopes.insert_value("new_y", value);
    Ok(())
}

/*
Implements hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack

    slope = pack(ids.slope, PRIME)
    x0 = pack(ids.point0.x, PRIME)
    x1 = pack(ids.point1.x, PRIME)
    y0 = pack(ids.point0.y, PRIME)

    value = new_x = (pow(slope, 2, SECP_P) - x0 - x1) % SECP_P
%}
*/
pub fn fast_ec_add_assign_new_x(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    exec_scopes.assign_or_update_variable("SECP_P", any_box!(SECP_P.clone()));
    //ids.slope
    let slope = BigInt3::from_var_name("slope", vm, ids_data, ap_tracking)?;
    //ids.point0
    let point0 = EcPoint::from_var_name("point0", vm, ids_data, ap_tracking)?;
    //ids.point1.x
    let point1 = EcPoint::from_var_name("point1", vm, ids_data, ap_tracking)?;

    let slope = pack(slope);
    let x0 = pack(point0.x);
    let x1 = pack(point1.x);
    let y0 = pack(point0.y);

    let value = (&slope * &slope - &x0 - &x1).mod_floor(&SECP_P);
    //Assign variables to vm scope
    exec_scopes.insert_value("slope", slope);
    exec_scopes.insert_value("x0", x0);
    exec_scopes.insert_value("y0", y0);
    exec_scopes.insert_value("value", value.clone());
    exec_scopes.insert_value("new_x", value);

    Ok(())
}

/*
Implements hint:
%{ value = new_y = (slope * (x0 - new_x) - y0) % SECP_P %}
*/
pub fn fast_ec_add_assign_new_y(exec_scopes: &mut ExecutionScopes) -> Result<(), HintError> {
    //Get variables from vm scope
    let (slope, x0, new_x, y0) = (
        exec_scopes.get::<BigInt>("slope")?,
        exec_scopes.get::<BigInt>("x0")?,
        exec_scopes.get::<BigInt>("new_x")?,
        exec_scopes.get::<BigInt>("y0")?,
    );
    let value = (slope * (x0 - new_x) - y0).mod_floor(&SECP_P);
    exec_scopes.insert_value("value", value.clone());
    exec_scopes.insert_value("new_y", value);

    Ok(())
}

/*
Implements hint:
%{ memory[ap] = (ids.scalar % PRIME) % 2 %}
*/
pub fn ec_mul_inner(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    //(ids.scalar % PRIME) % 2
    let scalar = get_integer_from_var_name("scalar", vm, ids_data, ap_tracking)?
        .as_ref()
        .bitand(&Felt252::one());
    insert_value_into_ap(vm, scalar)
}

/*
Implements hint:
%{
    ids.quad_bit = (
        8 * ((ids.scalar_v >> ids.m) & 1)
        + 4 * ((ids.scalar_u >> ids.m) & 1)
        + 2 * ((ids.scalar_v >> (ids.m - 1)) & 1)
        + ((ids.scalar_u >> (ids.m - 1)) & 1)
    )
%}
*/
pub fn quad_bit(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let scalar_v_cow = get_integer_from_var_name("scalar_v", vm, ids_data, ap_tracking)?;
    let scalar_u_cow = get_integer_from_var_name("scalar_u", vm, ids_data, ap_tracking)?;
    let m_cow = get_integer_from_var_name("m", vm, ids_data, ap_tracking)?;

    let scalar_v = scalar_v_cow.as_ref();
    let scalar_u = scalar_u_cow.as_ref();

    // If m is too high the shift result will always be zero
    let m = m_cow.as_ref().to_u32().unwrap_or(253);
    if m >= 253 {
        return insert_value_from_var_name("quad_bit", 0, vm, ids_data, ap_tracking);
    }

    let one = &Felt252::one();

    // 8 * ((ids.scalar_v >> ids.m) & 1)
    let quad_bit_3 = ((scalar_v >> m) & one) << 3u32;
    // 4 * ((ids.scalar_u >> ids.m) & 1)
    let quad_bit_2 = ((scalar_u >> m) & one) << 2u32;
    // 2 * ((ids.scalar_v >> (ids.m - 1)) & 1)
    let quad_bit_1 = ((scalar_v >> (m - 1)) & one) << 1u32;
    // 1 * ((ids.scalar_u >> (ids.m - 1)) & 1)
    let quad_bit_0 = (scalar_u >> (m - 1)) & one;

    let res = quad_bit_0 + quad_bit_1 + quad_bit_2 + quad_bit_3;

    insert_value_from_var_name("quad_bit", res, vm, ids_data, ap_tracking)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::string::ToString;
    use crate::vm::vm_memory::memory_segments::MemorySegmentManager;
    use crate::{
        any_box,
        hint_processor::{
            builtin_hint_processor::builtin_hint_processor_definition::{
                BuiltinHintProcessor, HintProcessorData,
            },
            hint_processor_definition::HintProcessor,
        },
        types::{
            exec_scope::ExecutionScopes,
            relocatable::{MaybeRelocatable, Relocatable},
        },
        utils::test_utils::*,
        vm::{
            errors::memory_errors::MemoryError, runners::builtin_runner::RangeCheckBuiltinRunner,
            vm_core::VirtualMachine, vm_memory::memory::Memory,
        },
    };
    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_ec_negate_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\ny = pack(ids.point.y, PRIME) % SECP_P\n# The modulo operation in python always returns a nonnegative number.\nvalue = (-y) % SECP_P";
        let mut vm = vm_with_range_check!();

        vm.segments = segments![((1, 3), 2645i32), ((1, 4), 454i32), ((1, 5), 206i32)];
        //Initialize fp
        vm.run_context.fp = 1;
        //Create hint_data
        let ids_data = ids_data!["point"];
        let mut exec_scopes = ExecutionScopes::new();
        //Execute the hint
        assert_matches!(run_hint!(vm, ids_data, hint_code, &mut exec_scopes), Ok(()));
        //Check 'value' is defined in the vm scope
        assert_matches!(
            exec_scopes.get::<BigInt>("value"),
            Ok(x) if x == bigint_str!(
                "115792089237316195423569751828682367333329274433232027476421668138471189901786"
            )
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_compute_doubling_slope_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\nfrom starkware.python.math_utils import ec_double_slope\n\n# Compute the slope.\nx = pack(ids.point.x, PRIME)\ny = pack(ids.point.y, PRIME)\nvalue = slope = ec_double_slope(point=(x, y), alpha=0, p=SECP_P)";
        let mut vm = vm_with_range_check!();
        vm.segments = segments![
            ((1, 0), 614323u64),
            ((1, 1), 5456867u64),
            ((1, 2), 101208u64),
            ((1, 3), 773712524u64),
            ((1, 4), 77371252u64),
            ((1, 5), 5298795u64)
        ];

        //Initialize fp
        vm.run_context.fp = 1;

        let ids_data = ids_data!["point"];
        let mut exec_scopes = ExecutionScopes::new();

        //Execute the hint
        assert_matches!(run_hint!(vm, ids_data, hint_code, &mut exec_scopes), Ok(()));
        check_scope!(
            &exec_scopes,
            [
                (
                    "value",
                    bigint_str!(
            "40442433062102151071094722250325492738932110061897694430475034100717288403728"
        )
                ),
                (
                    "slope",
                    bigint_str!(
            "40442433062102151071094722250325492738932110061897694430475034100717288403728"
        )
                )
            ]
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_compute_doubling_slope_wdivmod_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\nfrom starkware.python.math_utils import div_mod\n\n# Compute the slope.\nx = pack(ids.pt.x, PRIME)\ny = pack(ids.pt.y, PRIME)\nvalue = slope = div_mod(3 * x ** 2, 2 * y, SECP_P)";
        let mut vm = vm_with_range_check!();
        vm.segments = segments![
            ((1, 0), 614323u64),
            ((1, 1), 5456867u64),
            ((1, 2), 101208u64),
            ((1, 3), 773712524u64),
            ((1, 4), 77371252u64),
            ((1, 5), 5298795u64)
        ];

        //Initialize fp
        vm.run_context.fp = 1;

        let ids_data = ids_data!["pt"];
        let mut exec_scopes = ExecutionScopes::new();

        //Execute the hint
        assert_matches!(run_hint!(vm, ids_data, hint_code, &mut exec_scopes), Ok(()));
        check_scope!(
            &exec_scopes,
            [
                (
                    "value",
                    bigint_str!(
            "40442433062102151071094722250325492738932110061897694430475034100717288403728"
        )
                ),
                (
                    "slope",
                    bigint_str!(
            "40442433062102151071094722250325492738932110061897694430475034100717288403728"
        )
                )
            ]
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_compute_slope_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\nfrom starkware.python.math_utils import line_slope\n\n# Compute the slope.\nx0 = pack(ids.point0.x, PRIME)\ny0 = pack(ids.point0.y, PRIME)\nx1 = pack(ids.point1.x, PRIME)\ny1 = pack(ids.point1.y, PRIME)\nvalue = slope = line_slope(point1=(x0, y0), point2=(x1, y1), p=SECP_P)";
        let mut vm = vm_with_range_check!();

        //Insert ids.point0 and ids.point1 into memory
        vm.segments = segments![
            ((1, 0), 134),
            ((1, 1), 5123),
            ((1, 2), 140),
            ((1, 3), 1232),
            ((1, 4), 4652),
            ((1, 5), 720),
            ((1, 6), 156),
            ((1, 7), 6545),
            ((1, 8), 100010),
            ((1, 9), 1123),
            ((1, 10), 1325),
            ((1, 11), 910)
        ];

        //Initialize fp
        vm.run_context.fp = 14;
        let ids_data = HashMap::from([
            ("point0".to_string(), HintReference::new_simple(-14)),
            ("point1".to_string(), HintReference::new_simple(-8)),
        ]);
        let mut exec_scopes = ExecutionScopes::new();

        //Execute the hint
        assert_matches!(run_hint!(vm, ids_data, hint_code, &mut exec_scopes), Ok(()));
        check_scope!(
            &exec_scopes,
            [
                (
                    "value",
                    bigint_str!(
            "41419765295989780131385135514529906223027172305400087935755859001910844026631"
        )
                ),
                (
                    "slope",
                    bigint_str!(
            "41419765295989780131385135514529906223027172305400087935755859001910844026631"
        )
                )
            ]
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_compute_slope_wdivmod_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\nfrom starkware.python.math_utils import div_mod\n\n# Compute the slope.\nx0 = pack(ids.pt0.x, PRIME)\ny0 = pack(ids.pt0.y, PRIME)\nx1 = pack(ids.pt1.x, PRIME)\ny1 = pack(ids.pt1.y, PRIME)\nvalue = slope = div_mod(y0 - y1, x0 - x1, SECP_P)";
        let mut vm = vm_with_range_check!();

        // Insert ids.pt0 and ids.pt1 into memory
        vm.segments = segments![
            ((1, 0), 134),
            ((1, 1), 5123),
            ((1, 2), 140),
            ((1, 3), 1232),
            ((1, 4), 4652),
            ((1, 5), 720),
            ((1, 6), 156),
            ((1, 7), 6545),
            ((1, 8), 100010),
            ((1, 9), 1123),
            ((1, 10), 1325),
            ((1, 11), 910)
        ];

        // Initialize fp
        vm.run_context.fp = 14;
        let ids_data = HashMap::from([
            ("pt0".to_string(), HintReference::new_simple(-14)),
            ("pt1".to_string(), HintReference::new_simple(-8)),
        ]);
        let mut exec_scopes = ExecutionScopes::new();

        // Execute the hint
        assert_matches!(run_hint!(vm, ids_data, hint_code, &mut exec_scopes), Ok(()));
        check_scope!(
            &exec_scopes,
            [
                (
                    "value",
                    bigint_str!(
            "41419765295989780131385135514529906223027172305400087935755859001910844026631"
        )
                ),
                (
                    "slope",
                    bigint_str!(
            "41419765295989780131385135514529906223027172305400087935755859001910844026631"
        )
                )
            ]
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_ec_double_assign_new_x_ok() {
        let hint_codes = vec!["from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nslope = pack(ids.slope, PRIME)\nx = pack(ids.point.x, PRIME)\ny = pack(ids.point.y, PRIME)\n\nvalue = new_x = (pow(slope, 2, SECP_P) - 2 * x) % SECP_P", "from starkware.cairo.common.cairo_secp.secp_utils import pack\n\nslope = pack(ids.slope, PRIME)\nx = pack(ids.point.x, PRIME)\ny = pack(ids.point.y, PRIME)\n\nvalue = new_x = (pow(slope, 2, SECP_P) - 2 * x) % SECP_P"];

        for hint_code in hint_codes {
            let mut vm = vm_with_range_check!();

            //Insert ids.point and ids.slope into memory
            vm.segments = segments![
                ((1, 0), 134),
                ((1, 1), 5123),
                ((1, 2), 140),
                ((1, 3), 1232),
                ((1, 4), 4652),
                ((1, 5), 720),
                ((1, 6), 44186171158942157784255469_i128),
                ((1, 7), 54173758974262696047492534_i128),
                ((1, 8), 8106299688661572814170174_i128)
            ];

            //Initialize fp
            vm.run_context.fp = 10;
            let ids_data = HashMap::from([
                ("point".to_string(), HintReference::new_simple(-10)),
                ("slope".to_string(), HintReference::new_simple(-4)),
            ]);
            let mut exec_scopes = ExecutionScopes::new();

            //Execute the hint
            assert_matches!(run_hint!(vm, ids_data, hint_code, &mut exec_scopes), Ok(()));

            check_scope!(
                &exec_scopes,
                [
                    (
                        "slope",
                        bigint_str!(
                            "48526828616392201132917323266456307435009781900148206102108934970258721901549"
                        )
                    ),
                    (
                        "x",
                        bigint_str!("838083498911032969414721426845751663479194726707495046")
                    ),
                    (
                        "y",
                        bigint_str!("4310143708685312414132851373791311001152018708061750480")
                    ),
                    (
                        "value",
                        bigint_str!(
                            "59479631769792988345961122678598249997181612138456851058217178025444564264149"
                        )
                    ),
                    (
                        "new_x",
                        bigint_str!(
                            "59479631769792988345961122678598249997181612138456851058217178025444564264149"
                        )
                    )
                ]
            );
        }
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_ec_double_assign_new_y_ok() {
        let hint_code = "value = new_y = (slope * (x - new_x) - y) % SECP_P";
        let mut vm = vm_with_range_check!();
        let mut exec_scopes = scope![
            (
                "slope",
                bigint_str!(
                    "48526828616392201132917323266456307435009781900148206102108934970258721901549"
                )
            ),
            (
                "x",
                bigint_str!("838083498911032969414721426845751663479194726707495046")
            ),
            (
                "new_x",
                bigint_str!(
                    "59479631769792988345961122678598249997181612138456851058217178025444564264149"
                )
            ),
            (
                "y",
                bigint_str!("4310143708685312414132851373791311001152018708061750480")
            )
        ];
        //Execute the hint
        assert_matches!(
            run_hint!(vm, HashMap::new(), hint_code, &mut exec_scopes),
            Ok(())
        );

        check_scope!(
            &exec_scopes,
            [
                (
                    "value",
                    bigint_str!(
            "7948634220683381957329555864604318996476649323793038777651086572350147290350"
        )
                ),
                (
                    "new_y",
                    bigint_str!(
            "7948634220683381957329555864604318996476649323793038777651086572350147290350"
        )
                )
            ]
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_fast_ec_add_assign_new_x_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nslope = pack(ids.slope, PRIME)\nx0 = pack(ids.point0.x, PRIME)\nx1 = pack(ids.point1.x, PRIME)\ny0 = pack(ids.point0.y, PRIME)\n\nvalue = new_x = (pow(slope, 2, SECP_P) - x0 - x1) % SECP_P";
        let mut vm = vm_with_range_check!();

        //Insert ids.point0, ids.point1.x and ids.slope into memory
        vm.segments = segments![
            //ids.point0
            ((1, 0), 89712),
            ((1, 1), 56),
            ((1, 2), 1233409),
            ((1, 3), 980126),
            ((1, 4), 10),
            ((1, 5), 8793),
            //ids.point0.x
            ((1, 6), 1235216451),
            ((1, 7), 5967),
            ((1, 8), 2171381),
            //ids.slope
            ((1, 9), 67470097831679799377177424_i128),
            ((1, 10), 43370026683122492246392730_i128),
            ((1, 11), 16032182557092050689870202_i128)
        ];

        //Initialize run_context
        run_context!(vm, 0, 20, 15);

        let ids_data = HashMap::from([
            ("point0".to_string(), HintReference::new_simple(-15)),
            ("point1".to_string(), HintReference::new_simple(-9)),
            ("slope".to_string(), HintReference::new_simple(-6)),
        ]);
        let mut exec_scopes = ExecutionScopes::new();

        //Execute the hint
        assert_matches!(run_hint!(vm, ids_data, hint_code, &mut exec_scopes), Ok(()));

        check_scope!(
            &exec_scopes,
            [
                (
                    "value",
                    bigint_str!(
            "8891838197222656627233627110766426698842623939023296165598688719819499152657"
        )
                ),
                (
                    "new_x",
                    bigint_str!(
            "8891838197222656627233627110766426698842623939023296165598688719819499152657"
        )
                )
            ]
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_fast_ec_add_assign_new_y_ok() {
        let hint_code = "value = new_y = (slope * (x0 - new_x) - y0) % SECP_P";
        let mut vm = vm_with_range_check!();

        let mut exec_scopes = scope![
            (
                "slope",
                bigint_str!(
                    "48526828616392201132917323266456307435009781900148206102108934970258721901549"
                )
            ),
            (
                "x0",
                bigint_str!("838083498911032969414721426845751663479194726707495046")
            ),
            (
                "new_x",
                bigint_str!(
                    "59479631769792988345961122678598249997181612138456851058217178025444564264149"
                )
            ),
            (
                "y0",
                bigint_str!("4310143708685312414132851373791311001152018708061750480")
            )
        ];

        //Execute the hint
        assert_matches!(
            run_hint!(vm, HashMap::new(), hint_code, &mut exec_scopes),
            Ok(())
        );

        check_scope!(
            &exec_scopes,
            [
                (
                    "value",
                    bigint_str!(
            "7948634220683381957329555864604318996476649323793038777651086572350147290350"
        )
                ),
                (
                    "new_y",
                    bigint_str!(
            "7948634220683381957329555864604318996476649323793038777651086572350147290350"
        )
                )
            ]
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_ec_mul_inner_ok() {
        let hint_code = "memory[ap] = (ids.scalar % PRIME) % 2";
        let mut vm = vm_with_range_check!();

        let scalar = 89712_i32;
        //Insert ids.scalar into memory
        vm.segments = segments![((1, 0), scalar)];

        //Initialize RunContext
        run_context!(vm, 0, 2, 1);

        let ids_data = ids_data!["scalar"];

        //Execute the hint
        assert_matches!(run_hint!(vm, ids_data, hint_code), Ok(()));

        //Check hint memory inserts
        check_memory![vm.segments.memory, ((1, 2), 0)];
    }

    #[test]
    fn get_ec_point_from_var_name_ok() {
        /*EcPoint {
            x: (1,2,3)
            y: (4,5,6)
        }*/
        let mut vm = vm!();
        vm.set_fp(1);
        vm.segments = segments![
            ((1, 0), 1),
            ((1, 1), 2),
            ((1, 2), 3),
            ((1, 3), 4),
            ((1, 4), 5),
            ((1, 5), 6)
        ];
        let ids_data = ids_data!["e"];
        let ap_tracking = ApTracking::default();
        let e = EcPoint::from_var_name("e", &vm, &ids_data, &ap_tracking).unwrap();
        assert_eq!(e.x.d0.as_ref(), &Felt252::one());
        assert_eq!(e.x.d1.as_ref(), &Felt252::from(2));
        assert_eq!(e.x.d2.as_ref(), &Felt252::from(3));
        assert_eq!(e.y.d0.as_ref(), &Felt252::from(4));
        assert_eq!(e.y.d1.as_ref(), &Felt252::from(5));
        assert_eq!(e.y.d2.as_ref(), &Felt252::from(6));
    }

    #[test]
    fn get_ec_point_from_var_name_missing_member() {
        /*EcPoint {
            x: (1,2,3)
            y: (4,_,_)
        }*/
        let mut vm = vm!();
        vm.set_fp(1);
        vm.segments = segments![((1, 0), 1), ((1, 1), 2), ((1, 2), 3), ((1, 3), 4)];
        let ids_data = ids_data!["e"];
        let ap_tracking = ApTracking::default();
        let r = EcPoint::from_var_name("e", &vm, &ids_data, &ap_tracking);
        assert_matches!(r, Err(HintError::IdentifierHasNoMember(x, y)) if x == "e.y" && y == "d1")
    }

    #[test]
    fn get_ec_point_from_var_name_invalid_reference() {
        let mut vm = vm!();
        vm.segments = segments![((1, 0), 1), ((1, 1), 2)];
        let ids_data = ids_data!["e"];
        let ap_tracking = ApTracking::default();
        let r = EcPoint::from_var_name("e", &vm, &ids_data, &ap_tracking);
        assert_matches!(r, Err(HintError::UnknownIdentifier(x)) if x == "e")
    }

    #[test]
    fn run_quad_bit_ok() {
        let hint_code = "ids.quad_bit = (\n    8 * ((ids.scalar_v >> ids.m) & 1)\n    + 4 * ((ids.scalar_u >> ids.m) & 1)\n    + 2 * ((ids.scalar_v >> (ids.m - 1)) & 1)\n    + ((ids.scalar_u >> (ids.m - 1)) & 1)\n)";
        let mut vm = vm_with_range_check!();

        let scalar_u = 89712;
        let scalar_v = 1478396;
        let m = 4;
        // Insert ids.scalar into memory
        vm.segments = segments![((1, 0), scalar_u), ((1, 1), scalar_v), ((1, 2), m)];

        // Initialize RunContext
        run_context!(vm, 0, 4, 4);

        let ids_data = ids_data!["scalar_u", "scalar_v", "m", "quad_bit"];

        // Execute the hint
        assert_matches!(run_hint!(vm, ids_data, hint_code), Ok(()));

        // Check hint memory inserts
        check_memory![vm.segments.memory, ((1, 3), 14)];
    }

    #[test]
    fn run_quad_bit_with_max_m_ok() {
        let hint_code = "ids.quad_bit = (\n    8 * ((ids.scalar_v >> ids.m) & 1)\n    + 4 * ((ids.scalar_u >> ids.m) & 1)\n    + 2 * ((ids.scalar_v >> (ids.m - 1)) & 1)\n    + ((ids.scalar_u >> (ids.m - 1)) & 1)\n)";
        let mut vm = vm_with_range_check!();

        let scalar_u = 89712;
        let scalar_v = 1478396;
        // Value is so high the result will always be zero
        let m = i128::MAX;
        // Insert ids.scalar into memory
        vm.segments = segments![((1, 0), scalar_u), ((1, 1), scalar_v), ((1, 2), m)];

        // Initialize RunContext
        run_context!(vm, 0, 4, 4);

        let ids_data = ids_data!["scalar_u", "scalar_v", "m", "quad_bit"];

        // Execute the hint
        assert_matches!(run_hint!(vm, ids_data, hint_code), Ok(()));

        // Check hint memory inserts
        check_memory![vm.segments.memory, ((1, 3), 0)];
    }
}
