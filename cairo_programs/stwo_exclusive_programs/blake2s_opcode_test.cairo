%builtins range_check

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_blake2s.blake2s import blake2s_inner, INPUT_BLOCK_BYTES, STATE_SIZE_FELTS, INPUT_BLOCK_FELTS

const COUNTER = 128;

// Tests the Blake2s opcode runner using a preexisting implementation within the repo as reference.
// The initial state, a random message of 68 bytes and counter are used as input.
// Both the opcode and the reference implementation are run on said inputs and outputs are compared.
// Before comparing the outputs, it is verified that the opcode runner has written the output to the correct location.
func main{range_check_ptr}() {
    alloc_locals;

    let (local random_message) = alloc();
    assert random_message[0] =  930933030;
    assert random_message[1] =  1766240503;
    assert random_message[2] =  3660871006;
    assert random_message[3] =  388409270;
    assert random_message[4] =  1948594622;
    assert random_message[5] =  3119396969;
    assert random_message[6] =  3924579183;
    assert random_message[7] =  2089920034;
    assert random_message[8] =  3857888532;
    assert random_message[9] =  929304360;
    assert random_message[10] =  1810891574;
    assert random_message[11] =  860971754;
    assert random_message[12] =  1822893775;
    assert random_message[13] =  2008495810;
    assert random_message[14] =  2958962335;
    assert random_message[15] =  2340515744;
    assert random_message[16] =  1111307871;

    let (local blake2s_ptr_start) = alloc();
    let blake2s_ptr = blake2s_ptr_start;
    // Set the initial state to IV (IV[0] is modified).
    assert blake2s_ptr[0] = 0x6B08E647;  // IV[0] ^ 0x01010020 (config: no key, 32 bytes output).
    assert blake2s_ptr[1] = 0xBB67AE85;
    assert blake2s_ptr[2] = 0x3C6EF372;
    assert blake2s_ptr[3] = 0xA54FF53A;
    assert blake2s_ptr[4] = 0x510E527F;
    assert blake2s_ptr[5] = 0x9B05688C;
    assert blake2s_ptr[6] = 0x1F83D9AB;
    assert blake2s_ptr[7] = 0x5BE0CD19;
    static_assert STATE_SIZE_FELTS == 8;
    let blake2s_ptr = blake2s_ptr + STATE_SIZE_FELTS;

    let (cairo_output) = blake2s_inner{range_check_ptr=range_check_ptr, blake2s_ptr=blake2s_ptr}(data=random_message, n_bytes=INPUT_BLOCK_BYTES+4, counter=COUNTER);

    let (local initial_state) = alloc();
    assert initial_state[0] = 0x6B08E647;  // IV[0] ^ 0x01010020 (config: no key, 32 bytes output).
    assert initial_state[1] = 0xBB67AE85;
    assert initial_state[2] = 0x3C6EF372;
    assert initial_state[3] = 0xA54FF53A;
    assert initial_state[4] = 0x510E527F;
    assert initial_state[5] = 0x9B05688C;
    assert initial_state[6] = 0x1F83D9AB;
    assert initial_state[7] = 0x5BE0CD19;
    assert initial_state[8] = COUNTER;

    let (local vm_output_start) = alloc();

    force_blake2s_non_last_block_opcode(
        dst=vm_output_start,
        op0=initial_state,
        op1=random_message,
    );

    tempvar check_nonempty = vm_output_start[0];
    tempvar check_nonempty = vm_output_start[1];
    tempvar check_nonempty = vm_output_start[2];
    tempvar check_nonempty = vm_output_start[3];
    tempvar check_nonempty = vm_output_start[4];
    tempvar check_nonempty = vm_output_start[5];
    tempvar check_nonempty = vm_output_start[6];
    tempvar check_nonempty = vm_output_start[7];
    tempvar check_nonempty = vm_output_start[8];

    let relevant_output_start = blake2s_ptr_start+INPUT_BLOCK_FELTS+2+STATE_SIZE_FELTS;

    assert vm_output_start[0] = relevant_output_start[0];
    assert vm_output_start[1] = relevant_output_start[1];
    assert vm_output_start[2] = relevant_output_start[2];
    assert vm_output_start[3] = relevant_output_start[3];
    assert vm_output_start[4] = relevant_output_start[4];
    assert vm_output_start[5] = relevant_output_start[5];
    assert vm_output_start[6] = relevant_output_start[6];
    assert vm_output_start[7] = relevant_output_start[7];
    assert vm_output_start[8] = [relevant_output_start-2];

    return ();
}

// pub const FLAG_DST_BASE_FP_INDEX: usize = 0;
// pub const FLAG_OP0_BASE_FP_INDEX: usize = 1;
// pub const FLAG_OP1_IMM_INDEX: usize = 2;
// pub const FLAG_OP1_BASE_FP_INDEX: usize = 3;
// pub const FLAG_OP1_BASE_AP_INDEX: usize = 4;
// pub const FLAG_RES_ADD_INDEX: usize = 5;
// pub const FLAG_RES_MUL_INDEX: usize = 6;
// pub const FLAG_PC_UPDATE_JUMP_INDEX: usize = 7;
// pub const FLAG_PC_UPDATE_JUMP_REL_INDEX: usize = 8;
// pub const FLAG_PC_UPDATE_JNZ_INDEX: usize = 9;
// pub const FLAG_AP_UPDATE_ADD_INDEX: usize = 10;
// pub const FLAG_AP_UPDATE_ADD_1_INDEX: usize = 11;
// pub const FLAG_OPCODE_CALL_INDEX: usize = 12;
// pub const FLAG_OPCODE_RET_INDEX: usize = 13;
// pub const FLAG_OPCODE_ASSERT_EQ_INDEX: usize = 14;
// pub const FLAG_OPCODE_BLAKE2S_INDEX: usize = 15;
// pub const FLAG_OPCODE_BLAKE2S_LAST_BLOCK_INDEX: usize = 16;

// Forces the runner to execute the Blake2s with the given operands.
// op0 is a pointer to an array of 9 felts, 8 as u32 integers of the state and 1 as a u32 of the counter.
// op1 is a pointer to an array of 16 felts as u32 integers of the messsage.
// dst is a pointer to an array of 9 felts, 8 as u32 integers of the output state and 1 as a u32 of the updated counter.
// The values of said pointers are stored within addresses fp-5, fp-4 and fp-3 respectively.
// An instruction encoding is built from offsets -5, -4, -3 and flags which are all 0 except for
// those denoting uses of fp as the base for operand addresses and flag_opcode_blake (16th flag).
// The instruction is then written to [pc] and the runner is forced to execute Blake2s.
func force_blake2s_non_last_block_opcode(
    dst: felt*,
    op0: felt*,
    op1: felt*,
) {
    let offset0 = (2**15)-5;
    let offset1 = (2**15)-4;
    let offset2 = (2**15)-3;

    static_assert dst == [fp -5];
    static_assert op0 == [fp -4];
    static_assert op1 == [fp -3];

    let flag_dst_base_fp = 1;
    let flag_op0_base_fp = 1;
    let flag_op1_imm = 0;
    let flag_op1_base_fp = 1;
    let flag_op1_base_ap = 0;
    let flag_res_add = 0;
    let flag_res_mul = 0;
    let flag_PC_update_jump = 0;
    let flag_PC_update_jump_rel = 0;
    let flag_PC_update_jnz = 0;
    let flag_ap_update_add = 0;
    let flag_ap_update_add_1 = 0;
    let flag_opcode_call = 0;
    let flag_opcode_ret = 0;
    let flag_opcode_assert_eq = 0;
    let flag_opcode_blake2s = 1;

    let flag_num = flag_dst_base_fp+flag_op0_base_fp*(2**1)+flag_op1_imm*(2**2)+flag_op1_base_fp*(2**3)+flag_opcode_blake2s*(2**15);
    let instruction_num = offset0 + offset1*(2**16) + offset2*(2**32) + flag_num*(2**48);
    static_assert instruction_num==9226608988349300731;
    dw 9226608988349300731;
    return ();
}

