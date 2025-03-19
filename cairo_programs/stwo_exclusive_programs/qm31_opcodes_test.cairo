from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bool import FALSE, TRUE

// Tests the QM31_add_mul opcode runners using specific examples as reference.
// The test is comprised of 10 test cases, each of which tests a different combination of missing_operand, is_imm, and is_mul.
// is_mul determines whether the operation is a multiplication or an addition of QM31 elements.
// is_imm determines whether op1 is an immediate.
// missing_operand determines which operand is missing and needs to be computed by the VM (0 for dst, 1 for op0, 2 fo op1).
// the combination of is_imm=TRUE with missig_operand=2 is not tested because we do not use arithmetic opcodes to deduce immediates.
func main{}() {
    let qm31_op0_coordinates_a = 0x544b2fba;
    let qm31_op0_coordinates_b = 0x673cff77;
    let qm31_op0_coordinates_c = 0x60713d44;
    let qm31_op0_coordinates_d = 0x499602d2;
    let qm31_op0 = qm31_op0_coordinates_a + qm31_op0_coordinates_b*(2**36) + qm31_op0_coordinates_c*(2**72) + qm31_op0_coordinates_d*(2**108);

    let qm31_op1_coordinates_a = 0x4b18de99;
    let qm31_op1_coordinates_b = 0x55f6fb62;
    let qm31_op1_coordinates_c = 0x6e2290d9;
    let qm31_op1_coordinates_d = 0x7cd851b9;
    let qm31_op1 = qm31_op1_coordinates_a + qm31_op1_coordinates_b*(2**36) + qm31_op1_coordinates_c*(2**72) + qm31_op1_coordinates_d*(2**108);

    let qm31_add_dst_coordinates_a = 0x1f640e54;
    let qm31_add_dst_coordinates_b = 0x3d33fada;
    let qm31_add_dst_coordinates_c = 0x4e93ce1e;
    let qm31_add_dst_coordinates_d = 0x466e548c;
    let qm31_add_dst = qm31_add_dst_coordinates_a + qm31_add_dst_coordinates_b*(2**36) + qm31_add_dst_coordinates_c*(2**72) + qm31_add_dst_coordinates_d*(2**108);

    let qm31_mul_dst_coordinates_a = 0x38810ab4;
    let qm31_mul_dst_coordinates_b = 0x5a0fd30a;
    let qm31_mul_dst_coordinates_c = 0x2527b81e;
    let qm31_mul_dst_coordinates_d = 0x4b1ed1cd;
    let qm31_mul_dst = qm31_mul_dst_coordinates_a + qm31_mul_dst_coordinates_b*(2**36) + qm31_mul_dst_coordinates_c*(2**72) + qm31_mul_dst_coordinates_d*(2**108);

    let runner_output_mul_dst = run_qm31_operation(missing_operand=0, is_imm=FALSE, is_mul=TRUE, dst_or_op0=qm31_op0, op0_or_op1=qm31_op1);
    assert runner_output_mul_dst = qm31_mul_dst;
    let runner_output_add_dst = run_qm31_operation(missing_operand=0, is_imm=FALSE, is_mul=FALSE, dst_or_op0=qm31_op0, op0_or_op1=qm31_op1);
    assert runner_output_add_dst = qm31_add_dst;

    let runner_output_mul_op0 = run_qm31_operation(missing_operand=1, is_imm=FALSE, is_mul=TRUE, dst_or_op0=qm31_mul_dst, op0_or_op1=qm31_op1);
    assert runner_output_mul_op0 = qm31_op0;
    let runner_output_add_op0 = run_qm31_operation(missing_operand=1, is_imm=FALSE, is_mul=FALSE, dst_or_op0=qm31_add_dst, op0_or_op1=qm31_op1);
    assert runner_output_add_op0 = qm31_op0;

    let runner_output_mul_op1 = run_qm31_operation(missing_operand=2, is_imm=FALSE, is_mul=TRUE, dst_or_op0=qm31_mul_dst, op0_or_op1=qm31_op0);
    assert runner_output_mul_op1 = qm31_op1;
    let runner_output_add_op1 = run_qm31_operation(missing_operand=2, is_imm=FALSE, is_mul=FALSE, dst_or_op0=qm31_add_dst, op0_or_op1=qm31_op0);
    assert runner_output_add_op1 = qm31_op1;

    let runner_output_mul_dst = run_qm31_operation(missing_operand=0, is_imm=TRUE, is_mul=TRUE, dst_or_op0=qm31_op0, op0_or_op1=qm31_op1);
    assert runner_output_mul_dst = qm31_mul_dst;
    let runner_output_add_dst = run_qm31_operation(missing_operand=0, is_imm=TRUE, is_mul=FALSE, dst_or_op0=qm31_op0, op0_or_op1=qm31_op1);
    assert runner_output_add_dst = qm31_add_dst;

    let runner_output_mul_op0 = run_qm31_operation(missing_operand=1, is_imm=TRUE, is_mul=TRUE, dst_or_op0=qm31_mul_dst, op0_or_op1=qm31_op1);
    assert runner_output_mul_op0 = qm31_op0;
    let runner_output_add_op0 = run_qm31_operation(missing_operand=1, is_imm=TRUE, is_mul=FALSE, dst_or_op0=qm31_add_dst, op0_or_op1=qm31_op1);
    assert runner_output_add_op0 = qm31_op0;

    return ();
}

// Forces the runner to execute the QM31_add_mul opcode with the given operands.
// missing_operand, is_imm, is_mul determine the configuration of the operation as described above.
// dst_or_op0 is a felt representing the value of either the op0 (if missing_operand=0) or dst (otherwise) operand.
// op0_or_op1 is a felt representing the value of either the op0 (if missing_operand=2) or op1 (otherwise) operand.
// dst_or_op0 and op0_or_op1 are stored within addresses fp-4 and fp-3 respectively, they are passed to the instruction
// using offsets wrt fp (unless is_imm=TRUE, in which case op1 has offset 1 relative to pc).
// The missing operand has offset 0 relative to ap.
// An instruction encoding with the appropriate flags and offsets is built, then written to [pc] and the runner is forced to execute QM31_add_mul.
// The missing operand is deduced to [ap] and returned.
func run_qm31_operation(
    missing_operand: felt,
    is_imm: felt,
    is_mul: felt,
    dst_or_op0: felt,
    op0_or_op1: felt,
) -> felt {
    alloc_locals;

    // Set flags and offsets.
    let (local offsets) = alloc();
    let (local flags) = alloc();

    assert offsets[missing_operand] = 2**15; // the missing operand will be written to [ap]

    assert flags[2] = is_imm; // flag_op1_imm = 0;
    assert flags[5] = 1-is_mul; // flag_res_add = 1-is_mul;
    assert flags[6] = is_mul; // flag_res_mul = is_mul;
    assert flags[7] = 0; // flag_PC_update_jump = 0;
    assert flags[8] = 0; // flag_PC_update_jump_rel = 0;
    assert flags[9] = 0; // flag_PC_update_jnz = 0;
    assert flags[10] = 0; // flag_ap_update_add = 0;
    assert flags[11] = 0; // flag_ap_update_add_1 = 0;
    assert flags[12] = 0; // flag_opcode_call = 0;
    assert flags[13] = 0; // flag_opcode_ret = 0;
    assert flags[14] = 1; // flag_opcode_assert_eq = 1;

    if (missing_operand == 0) {
        assert offsets[1] = 2**15 - 4;
        assert offsets[2] = 2**15 - 3 + 4 * is_imm;
        assert flags[0] = 0; // flag_dst_base_fp
        assert flags[1] = 1; // flag_op0_base_fp
    }
    if (missing_operand == 1) {
        assert offsets[0] = 2**15 - 4;
        assert offsets[2] = 2**15 - 3 + 4 * is_imm;
        assert flags[0] = 1; // flag_dst_base_fp
        assert flags[1] = 0; // flag_op0_base_fp
    }
    if (missing_operand == 2) {
        assert is_imm = FALSE;
        assert offsets[0] = 2**15 - 4;
        assert offsets[1] = 2**15 - 3;
        assert flags[0] = 1; // flag_dst_base_fp
        assert flags[1] = 1; // flag_op0_base_fp
    }
    assert flags[3] = (2 - flags[0] - flags[1]) * (1 - is_imm); // flag_op1_base_fp
    assert flags[4] = 1 - is_imm - flags[3]; // flag_op1_base_ap

    // Compute the instruction encoding.
    let flag_num = flags[0] + flags[1]*(2**1) + flags[2]*(2**2) + flags[3]*(2**3) + flags[4]*(2**4) + flags[5]*(2**5) + flags[6]*(2**6) + flags[14]*(2**14);
    let qm31_opcode_extension_num = 3;
    let instruction_encoding = offsets[0] + offsets[1]*(2**16) + offsets[2]*(2**32) + flag_num*(2**48) + qm31_opcode_extension_num*(2**63);

    // Run the instruction and return the result.
    if (is_imm == TRUE) {
        assert op0_or_op1 = 0x7cd851b906e2290d9055f6fb6204b18de99;
        if (missing_operand == 0) {
            if (is_mul == TRUE) {
                assert instruction_encoding=0x1c04680017ffc8000;
                dw 0x1c04680017ffc8000;
                dw 0x7cd851b906e2290d9055f6fb6204b18de99;
                return [ap];
            }
            assert instruction_encoding=0x1c02680017ffc8000;
            dw 0x1c02680017ffc8000;
            dw 0x7cd851b906e2290d9055f6fb6204b18de99;
            return [ap];
        }
        if (missing_operand == 1) {
            if (is_mul == TRUE) {
                assert instruction_encoding=0x1c045800180007ffc;
                dw 0x1c045800180007ffc;
                dw 0x7cd851b906e2290d9055f6fb6204b18de99;
                return [ap];
            }
            assert instruction_encoding=0x1c025800180007ffc;
            dw 0x1c025800180007ffc;
            dw 0x7cd851b906e2290d9055f6fb6204b18de99;
            return [ap];
        }
    }

    if (missing_operand == 0) {
        if (is_mul == TRUE) {
            assert instruction_encoding=0x1c04a7ffd7ffc8000;
            dw 0x1c04a7ffd7ffc8000;
            return [ap];
        }
        assert instruction_encoding=0x1c02a7ffd7ffc8000;
        dw 0x1c02a7ffd7ffc8000;
        return [ap];
    }
    if (missing_operand == 1) {
        if (is_mul == TRUE) {
            assert instruction_encoding=0x1c0497ffd80007ffc;
            dw 0x1c0497ffd80007ffc;
            return [ap];
        }
        assert instruction_encoding=0x1c0297ffd80007ffc;
        dw 0x1c0297ffd80007ffc;
        return [ap];
    }
    if (is_mul == TRUE) {
        assert instruction_encoding=0x1c05380007ffd7ffc;
        dw 0x1c05380007ffd7ffc;
        return [ap];
    }
    assert instruction_encoding=0x1c03380007ffd7ffc;
    dw 0x1c03380007ffd7ffc;
    return [ap];
}
