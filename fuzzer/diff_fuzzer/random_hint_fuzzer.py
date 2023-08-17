#!../cairo-vm-env/bin/python3
import sys 
import atheris
import json
from starkware.cairo.lang.compiler.cairo_compile import compile_cairo
from starkware.cairo.lang.instances import LAYOUTS
from starkware.cairo.lang.vm.cairo_runner import CairoRunner
from starkware.cairo.lang.vm.cairo_run import load_program
from starkware.cairo.lang.vm.memory_dict import MemoryDict
from cairo_program_gen import generate_cairo_hint_program, REPLACEABLE_TOKEN
from cairo_vm_rs import cairo_run_dump_mem
from memory_checker import check_mem

PRIME = 2**251 + 17 * 2**192 + 1

@atheris.instrument_func
def generate_limb(fdp):
    range_check_max = 340282366920938463463374607431768211456 
    if fdp.ConsumeProbability() > 0.3:
       return fdp.ConsumeIntInRange(range_check_max >> 1, range_check_max) 
    elif fdp.ConsumeBool():
       return fdp.ConsumeIntInRange(0, 10) 
    else:
       return fdp.ConsumeIntInRange(1, range_check_max)

def load_hints():
    uint256_improvements_hints = json.load(open('../../hint_accountant/whitelists/uint256_improvements.json'))
    uint256_improvements_numbers = [1, 2]
    vrf_hints = json.load(open('../../hint_accountant/whitelists/vrf.json'))
    vrf_numbers = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12]
    latest_hints = json.load(open('../../hint_accountant/whitelists/latest.json'))
    latest_numbers = [4, 5, 6, 26, 27, 29, 30, 32, 38, 49, 55, 72]
    hints = [
        latest_hints["allowed_reference_expressions_for_hint"][hint_number]["hint_lines"]
        for hint_number in latest_numbers
    ]
    hints += [
        vrf_hints["allowed_reference_expressions_for_hint"][hint_number]["hint_lines"]
        for hint_number in vrf_numbers
    ]
    hints += [
        uint256_improvements_hints["allowed_reference_expressions_for_hint"][hint_number]["hint_lines"]
        for hint_number in uint256_improvements_numbers
    ]
    return hints

def write_failing_file(fdp, cairo_program):
    alt_filename = hex(fdp.ConsumeUInt(8))
    with open("failed_input_" + alt_filename + ".cairo", 'w', encoding='utf-8') as file:
        file.write(cairo_program)

@atheris.instrument_func
def diff_fuzzer(data):
    fdp = atheris.FuzzedDataProvider(data)
    hint = fdp.PickValueInList(LOADED_HINTS)

    cairo_program = generate_cairo_hint_program(hint)
    replace_count = cairo_program.count(REPLACEABLE_TOKEN)
    for _ in range(replace_count):
        cairo_program = cairo_program.replace(REPLACEABLE_TOKEN, str(generate_limb(fdp)), 1)
    program = compile_cairo(cairo_program, PRIME)

    # Get Rust implementation memory
    rust_err = False
    try:
        raw_rs_mem = cairo_run_dump_mem(json.dumps(program.dump()))
    except:
        rust_err = True

    # Get Python implementation memory
    python_err = False
    try:
        runner = CairoRunner(
            program=program,
            layout=LAYOUTS["plain"],
            memory=MemoryDict(),
            proof_mode=None,
            allow_missing_builtins=None,
        )
        runner.initialize_segments()
        end = runner.initialize_main_entrypoint()
        runner.initialize_vm(hint_locals={"program_input": {}})
        runner.run_until_pc(end)
        runner.end_run()
        runner.relocate()
        raw_py_mem = list(runner.relocated_memory.serialize(32))
    except:
        python_err = True

    if not (rust_err or python_err):
        try:
            check_mem(raw_py_mem=raw_py_mem, raw_rs_mem=raw_rs_mem)
        except AssertionError:
            write_failing_file(fdp, cairo_program)
            raise 
    elif rust_err != python_err:
        write_failing_file(fdp, cairo_program)
        assert rust_err == python_err, f"Rust is error: {rust_err}, Python is error: {python_err}"
    
LOADED_HINTS = load_hints()
atheris.Setup(sys.argv, diff_fuzzer)
atheris.Fuzz()

