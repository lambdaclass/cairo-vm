%builtins pedersen range_check
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.cairo_secp.bigint import uint256_to_bigint
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.math import (
    assert_not_equal,
    assert_not_zero,
    split_felt,
)
from starkware.cairo.common.math_cmp import is_le_felt, is_not_zero
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.uint256 import Uint256, uint256_check
from starkware.cairo.common.cairo_secp.bigint import BigInt3

from cairo_programs.secp256r1.signature import verify_secp256r1_signature  

struct SignerModel {
    signer_0: felt,
    signer_1: felt,
    signer_2: felt,
    signer_3: felt,
    type: felt,
    reserved_0: felt,
    reserved_1: felt,
}
    
    func _is_valid_secp256r1_signature{
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(
        signer: SignerModel,
        hash: felt,
        signature_len: felt, signature: felt*
    ) -> (is_valid: felt) {
        // x,y were verified in add_signer
        let (x) = uint256_to_bigint(Uint256(low=signer.signer_0, high=signer.signer_1));
        let (y) = uint256_to_bigint(Uint256(low=signer.signer_2, high=signer.signer_3));
        // validate r,s
        let r_uint256 = Uint256(low=signature[0], high=signature[1]);
        uint256_check(r_uint256);
        let s_uint256 = Uint256(low=signature[2], high=signature[3]);
        uint256_check(s_uint256);
        let (r_bigint3) = uint256_to_bigint(r_uint256);
        let (s_bigint3) = uint256_to_bigint(s_uint256);
        let (hash_high, hash_low) = split_felt(hash);
        let (hash_bigint3) = uint256_to_bigint(Uint256(low=hash_low, high=hash_high));
        verify_secp256r1_signature(hash_bigint3, r_bigint3, s_bigint3, EcPoint(x=x, y=y));
        return (is_valid=TRUE);
    }

func main{pedersen_ptr: HashBuiltin*, range_check_ptr: felt}() {
    let signer = SignerModel(
    0x000000000000000000000000000000002e6a593388c0f7043f52a49878b56cdc,
    0x00000000000000000000000000000000ee92868aae870033fa9b4056b4a8f336,
    0x00000000000000000000000000000000aa82f77141f9e731f500dce8e9f6036e,
    0x000000000000000000000000000000008db39bd77c7616bb4f1c6998a83ca9ef,
    0x0000000000000000000000000000000000000000000000000000000000000002,
    0x0000000000000000000000000000000000000000000000000000000000000000,
    0x0000000000000000000000000000000000000000000000000000000000000000);
    let hash = 0x06b8601e6783041c7df433213bfb2fa2073b844cda3207c15e44337a0cc5bb6e;
    let signature_len = 5;
    let signature: felt* = alloc();
    assert signature[0] = 0x0000000000000000000000000000000000000000000000000000000000000003;
    assert signature[1] = 0x00000000000000000000000000000000e20a2953777bac007ce8b2ab416111ff;
    assert signature[2] = 0x0000000000000000000000000000000060c6ad9d3ae9719536591416670645ed;
    assert signature[3] = 0x000000000000000000000000000000002046aa4279cc3cc0bce8a5fb296f8a56;
    assert signature[4] = 0x000000000000000000000000000000006381fb017b13876c446706bcda79a7ab;
    _is_valid_secp256r1_signature(signer, hash, signature_len - 1, signature + 1);
    return();
}


