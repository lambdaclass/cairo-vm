from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bool import FALSE, TRUE

func main{}() {
    alloc_locals;
    // x*y coordinates_to_packed([947980980, 1510986506, 623360030, 1260310989]),
    // x+y coordinates_to_packed([526650964, 1026816730, 1318309406, 1181635724]),
    // x coordinates_to_packed([1414213562, 1732050807, 1618033988, 1234567890]),
    // y coordinates_to_packed([1259921049, 1442249570, 1847759065, 2094551481]),
    let (local qm31_op0_coordinates) = alloc();
    assert qm31_op0_coordinates[0] =  1414213562;
    assert qm31_op0_coordinates[1] =  1732050807;
    assert qm31_op0_coordinates[2] =  1618033988;
    assert qm31_op0_coordinates[3] =  1234567890;
    let qm31_op0 = qm31_op0_coordinates[0] + qm31_op0_coordinates[1]*(2**36) + qm31_op0_coordinates[2]*(2**72) + qm31_op0_coordinates[3]*(2**108);

    let (local qm31_op1_coordinates) = alloc();
    assert qm31_op1_coordinates[0] =  1259921049;
    assert qm31_op1_coordinates[1] =  1442249570;
    assert qm31_op1_coordinates[2] =  1847759065;
    assert qm31_op1_coordinates[3] =  2094551481;
    let qm31_op1 = qm31_op1_coordinates[0] + qm31_op1_coordinates[1]*(2**36) + qm31_op1_coordinates[2]*(2**72) + qm31_op1_coordinates[3]*(2**108);

    let (local qm31_add_dst_coordinates) = alloc();
    assert qm31_add_dst_coordinates[0] =  526650964;
    assert qm31_add_dst_coordinates[1] =  1026816730;
    assert qm31_add_dst_coordinates[2] =  1318309406;
    assert qm31_add_dst_coordinates[3] =  1181635724;
    let qm31_add_dst = qm31_add_dst_coordinates[0] + qm31_add_dst_coordinates[1]*(2**36) + qm31_add_dst_coordinates[2]*(2**72) + qm31_add_dst_coordinates[3]*(2**108);

    let (local qm31_mul_dst_coordinates) = alloc();
    assert qm31_mul_dst_coordinates[0] =  947980980;
    assert qm31_mul_dst_coordinates[1] =  1510986506;
    assert qm31_mul_dst_coordinates[2] =  623360030;
    assert qm31_mul_dst_coordinates[3] =  1260310989;
    let qm31_mul_dst = qm31_mul_dst_coordinates[0] + qm31_mul_dst_coordinates[1]*(2**36) + qm31_mul_dst_coordinates[2]*(2**72) + qm31_mul_dst_coordinates[3]*(2**108);

    let runner_output_mul_dst = run_qm31_operation_get_dst(is_mul=TRUE, op0=qm31_op0, op1=qm31_op1);
    assert runner_output_mul_dst = qm31_mul_dst;
    let runner_output_add_dst = run_qm31_operation_get_dst(is_mul=FALSE, op0=qm31_op0, op1=qm31_op1);
    assert runner_output_add_dst = qm31_add_dst;
    //let runner_output_mul_dst = run_qm31_operation_get_dst(is_mul=TRUE, op0=qm31_op0, op1=qm31_op1);
    // assert runner_output_mul_dst = qm31_mul_dst;

    let runner_output_mul_op1 = run_qm31_operation_get_op1(is_mul=TRUE, dst=qm31_mul_dst, op0=qm31_op0);
    assert runner_output_mul_op1 = qm31_op1;
    let runner_output_add_op1 = run_qm31_operation_get_op1(is_mul=FALSE, dst=qm31_add_dst, op0=qm31_op0);
    assert runner_output_add_op1 = qm31_op1;

    let runner_output_mul_op0 = run_qm31_operation_get_op0(is_mul=TRUE, dst=qm31_mul_dst, op1=qm31_op1);
    assert runner_output_mul_op0 = qm31_op0;
    let runner_output_add_op0 = run_qm31_operation_get_op0(is_mul=FALSE, dst=qm31_add_dst, op1=qm31_op1);
    assert runner_output_add_op0 = qm31_op0;

    // let runner_output_mul_op0 = run_qm31_operation_get_op0(is_mul=TRUE, dst=qm31_mul_dst, op1=qm31_op1);
    // //assert qm31_op1 = qm31_op0;
    // assert runner_output_mul_op0 = qm31_op0;
    // let runner_output_mul_op1 = run_qm31_operation_get_op1(is_mul=TRUE, dst=qm31_mul_dst, op0=qm31_op0);
    // assert runner_output_mul_op1 = qm31_op1;

    return ();
}

// missing_operand_index
func run_qm31_operation_get_dst(
    is_mul: felt,
    op0: felt,
    op1: felt,
) -> felt {
    //alloc_locals;

    let offset0 = 2**15;
    let offset1 = (2**15)-4;
    let offset2 = (2**15)-3;
    
    let flag_dst_base_fp = 0;
    let flag_op0_base_fp = 1;
    let flag_op1_imm = 0;
    let flag_op1_base_fp = 1;
    let flag_op1_base_ap = 0;
    let flag_res_add = 0;
    let flag_res_mul = is_mul; //
    let flag_PC_update_jump = 0;
    let flag_PC_update_jump_rel = 0;
    let flag_PC_update_jnz = 0;
    let flag_ap_update_add = 0;
    let flag_ap_update_add_1 = 0;
    let flag_opcode_call = 0;
    let flag_opcode_ret = 0;
    let flag_opcode_assert_eq = 1;

    let flag_num_qm31_add = flag_dst_base_fp+flag_op0_base_fp*(2**1)+flag_op1_imm*(2**2)+flag_op1_base_fp*(2**3)+flag_op1_base_ap*(2**4)+0*(2**6)+flag_opcode_assert_eq*(2**14);
    let flag_num_qm31_mul = flag_dst_base_fp+flag_op0_base_fp*(2**1)+flag_op1_imm*(2**2)+flag_op1_base_fp*(2**3)+flag_op1_base_ap*(2**4)+1*(2**6)+flag_opcode_assert_eq*(2**14);
    let qm31_opcode_extension_num = 3;
    let qm31_add_instruction_num = offset0 + offset1*(2**16) + offset2*(2**32) + flag_num_qm31_add*(2**48) + qm31_opcode_extension_num*(2**63);
    let qm31_mul_instruction_num = offset0 + offset1*(2**16) + offset2*(2**32) + flag_num_qm31_mul*(2**48) + qm31_opcode_extension_num*(2**63);
    static_assert qm31_mul_instruction_num==32302772004019011584;
    static_assert qm31_add_instruction_num==32284757605509529600;

    if (is_mul == TRUE) {
        dw 32302772004019011584;
        [ap - 1] = [ap -1];
    } else {
        dw 32284757605509529600;
    }
    // dw 32302772004019011584;
    return [ap];
}

// offset0 = 0;
// offset1 = (2**15)-4
// offset2 = (2**15)-3

// flag_dst_base_fp = 0
// flag_op0_base_fp = 1
// flag_op1_imm = 0
// flag_op1_base_fp = 1
// flag_op1_base_ap = 0
// flag_res_add = 0
// flag_res_mul = is_mul #
// flag_PC_update_jump = 0
// flag_PC_update_jump_rel = 0
// flag_PC_update_jnz = 0
// flag_ap_update_add = 0
// flag_ap_update_add_1 = 0
// flag_opcode_call = 0
// flag_opcode_ret = 0
// flag_opcode_assert_eq = 1

// flag_num_qm31_add = flag_dst_base_fp+flag_op0_base_fp*(2**1)+flag_op1_imm*(2**2)+flag_op1_base_fp*(2**3)+0*(2**6)+flag_opcode_assert_eq*(2**14)
// flag_num_qm31_mul = flag_dst_base_fp+flag_op0_base_fp*(2**1)+flag_op1_imm*(2**2)+flag_op1_base_fp*(2**3)+1*(2**6)+flag_opcode_assert_eq*(2**14)
// qm31_opcode_extension_num = 3
// qm31_add_instruction_num = offset0 + offset1*(2**16) + offset2*(2**32) + flag_num_qm31_add*(2**48) + qm31_opcode_extension_num*(2**63)
// qm31_mul_instruction_num = offset0 + offset1*(2**16) + offset2*(2**32) + flag_num_qm31_mul*(2**48) + qm31_opcode_extension_num*(2**63)

func run_qm31_operation_get_op1(
    is_mul: felt,
    dst: felt,
    op0: felt,
) -> felt {
    //alloc_locals;

    let offset0 = (2**15)-4;
    let offset1 = (2**15)-3;
    let offset2 = 2**15;
    
    let flag_dst_base_fp = 1;
    let flag_op0_base_fp = 1;
    let flag_op1_imm = 0;
    let flag_op1_base_fp = 0;
    let flag_op1_base_ap = 1;
    let flag_res_add = 0;
    let flag_res_mul = is_mul; //
    let flag_PC_update_jump = 0;
    let flag_PC_update_jump_rel = 0;
    let flag_PC_update_jnz = 0;
    let flag_ap_update_add = 0;
    let flag_ap_update_add_1 = 0;
    let flag_opcode_call = 0;
    let flag_opcode_ret = 0;
    let flag_opcode_assert_eq = 1;

    let flag_num_qm31_add = flag_dst_base_fp+flag_op0_base_fp*(2**1)+flag_op1_imm*(2**2)+flag_op1_base_fp*(2**3)+flag_op1_base_ap*(2**4)+0*(2**6)+flag_opcode_assert_eq*(2**14);
    let flag_num_qm31_mul = flag_dst_base_fp+flag_op0_base_fp*(2**1)+flag_op1_imm*(2**2)+flag_op1_base_fp*(2**3)+flag_op1_base_ap*(2**4)+1*(2**6)+flag_opcode_assert_eq*(2**14);
    let qm31_opcode_extension_num = 3;
    let qm31_add_instruction_num = offset0 + offset1*(2**16) + offset2*(2**32) + flag_num_qm31_add*(2**48) + qm31_opcode_extension_num*(2**63);
    let qm31_mul_instruction_num = offset0 + offset1*(2**16) + offset2*(2**32) + flag_num_qm31_mul*(2**48) + qm31_opcode_extension_num*(2**63);
    static_assert qm31_mul_instruction_num==32305305291694374908;
    static_assert qm31_add_instruction_num==32287290893184892924;

    if (is_mul == TRUE) {
        dw 32305305291694374908;
        [ap - 1] = [ap -1];
    } else {
        dw 32287290893184892924;
    }
    return [ap];
}

// offset0 = (2**15)-4
// offset1 = (2**15)-3
// offset2 = 2**15

// flag_dst_base_fp = 1
// flag_op0_base_fp = 1
// flag_op1_imm = 0
// flag_op1_base_fp = 0
// flag_op1_base_ap = 1
// flag_res_add = 0
// flag_res_mul = is_mul //
// flag_PC_update_jump = 0
// flag_PC_update_jump_rel = 0
// flag_PC_update_jnz = 0
// flag_ap_update_add = 0
// flag_ap_update_add_1 = 0
// flag_opcode_call = 0
// flag_opcode_ret = 0
// flag_opcode_assert_eq = 1

// flag_num_qm31_add = flag_dst_base_fp+flag_op0_base_fp*(2**1)+flag_op1_imm*(2**2)+flag_op1_base_fp*(2**3)+flag_op1_base_ap*(2**4)+0*(2**6)+flag_opcode_assert_eq*(2**14)
// flag_num_qm31_mul = flag_dst_base_fp+flag_op0_base_fp*(2**1)+flag_op1_imm*(2**2)+flag_op1_base_fp*(2**3)+flag_op1_base_ap*(2**4)+1*(2**6)+flag_opcode_assert_eq*(2**14)
// qm31_opcode_extension_num = 3;
// qm31_add_instruction_num = offset0 + offset1*(2**16) + offset2*(2**32) + flag_num_qm31_add*(2**48) + qm31_opcode_extension_num*(2**63);
// qm31_mul_instruction_num = offset0 + offset1*(2**16) + offset2*(2**32) + flag_num_qm31_mul*(2**48) + qm31_opcode_extension_num*(2**63);

func run_qm31_operation_get_op0(
    is_mul: felt,
    dst: felt,
    op1: felt,
) -> felt {
    //alloc_locals;

    let offset0 = (2**15)-4;
    let offset1 = 2**15;
    let offset2 = (2**15)-3;
    
    let flag_dst_base_fp = 1;
    let flag_op0_base_fp = 0;
    let flag_op1_imm = 0;
    let flag_op1_base_fp = 1;
    let flag_op1_base_ap = 0;
    let flag_res_add = 0;
    let flag_res_mul = is_mul; //
    let flag_PC_update_jump = 0;
    let flag_PC_update_jump_rel = 0;
    let flag_PC_update_jnz = 0;
    let flag_ap_update_add = 0;
    let flag_ap_update_add_1 = 0;
    let flag_opcode_call = 0;
    let flag_opcode_ret = 0;
    let flag_opcode_assert_eq = 1;

    let flag_num_qm31_add = flag_dst_base_fp+flag_op0_base_fp*(2**1)+flag_op1_imm*(2**2)+flag_op1_base_fp*(2**3)+flag_op1_base_ap*(2**4)+0*(2**6)+flag_opcode_assert_eq*(2**14);
    let flag_num_qm31_mul = flag_dst_base_fp+flag_op0_base_fp*(2**1)+flag_op1_imm*(2**2)+flag_op1_base_fp*(2**3)+flag_op1_base_ap*(2**4)+1*(2**6)+flag_opcode_assert_eq*(2**14);
    let qm31_opcode_extension_num = 3;
    let qm31_add_instruction_num = offset0 + offset1*(2**16) + offset2*(2**32) + flag_num_qm31_add*(2**48) + qm31_opcode_extension_num*(2**63);
    let qm31_mul_instruction_num = offset0 + offset1*(2**16) + offset2*(2**32) + flag_num_qm31_mul*(2**48) + qm31_opcode_extension_num*(2**63);
    static_assert qm31_mul_instruction_num==32302490529042563068;
    static_assert qm31_add_instruction_num==32284476130533081084;

    if (is_mul == TRUE) {
        dw 32302490529042563068;
        [ap - 1] = [ap -1];
    } else {
        dw 32284476130533081084;
    }
    return [ap];
}

// offset0 = (2**15)-4
// offset1 = 2**15
// offset2 = (2**15)-3

// flag_dst_base_fp = 1
// flag_op0_base_fp = 0
// flag_op1_imm = 0
// flag_op1_base_fp = 1
// flag_op1_base_ap = 0
// flag_res_add = 0
// flag_res_mul = is_mul //
// flag_PC_update_jump = 0
// flag_PC_update_jump_rel = 0
// flag_PC_update_jnz = 0
// flag_ap_update_add = 0
// flag_ap_update_add_1 = 0
// flag_opcode_call = 0
// flag_opcode_ret = 0
// flag_opcode_assert_eq = 1

// flag_num_qm31_add = flag_dst_base_fp+flag_op0_base_fp*(2**1)+flag_op1_imm*(2**2)+flag_op1_base_fp*(2**3)+flag_op1_base_ap*(2**4)+0*(2**6)+flag_opcode_assert_eq*(2**14)
// flag_num_qm31_mul = flag_dst_base_fp+flag_op0_base_fp*(2**1)+flag_op1_imm*(2**2)+flag_op1_base_fp*(2**3)+flag_op1_base_ap*(2**4)+1*(2**6)+flag_opcode_assert_eq*(2**14)
// qm31_opcode_extension_num = 3
// qm31_add_instruction_num = offset0 + offset1*(2**16) + offset2*(2**32) + flag_num_qm31_add*(2**48) + qm31_opcode_extension_num*(2**63)
// qm31_mul_instruction_num = offset0 + offset1*(2**16) + offset2*(2**32) + flag_num_qm31_mul*(2**48) + qm31_opcode_extension_num*(2**63)