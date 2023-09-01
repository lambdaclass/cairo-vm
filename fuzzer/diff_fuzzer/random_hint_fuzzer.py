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
from cairo_vm_rs import cairo_run_dump_mem, PanicTriggered, VMError
from memory_checker import check_mem
from hint_reader import load_hints

PRIME = 2**251 + 17 * 2**192 + 1

@atheris.instrument_func
def generate_limb(fdp):
    range_check_max = PRIME #340282366920938463463374607431768211456 
    if fdp.ConsumeProbability() > 0.3:
       return fdp.ConsumeIntInRange(range_check_max >> 1, range_check_max) 
    elif fdp.ConsumeBool():
       return fdp.ConsumeIntInRange(0, 10) 
    else:
       return fdp.ConsumeIntInRange(1, range_check_max)

def write_failing_file(fdp, cairo_program):
    alt_filename = hex(fdp.ConsumeUInt(8))
    filename = "failed_input_" + alt_filename + ".cairo"
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(cairo_program)
    return filename

@atheris.instrument_func
def diff_fuzzer(data):
    fdp = atheris.FuzzedDataProvider(data)
    hint = fdp.PickValueInList(LOADED_HINTS)

    try:
        cairo_program = generate_cairo_hint_program(hint)
    except KeyboardInterrupt:
        sys.exit("Fuzzing stopped!")
    except:
        failed_input_name = write_failing_file(fdp, hint)
        sys.exit(f"Failed to generate cairo program from hint. Check file: {failed_input_name}")

    replace_count = cairo_program.count(REPLACEABLE_TOKEN)
    for _ in range(replace_count):
        cairo_program = cairo_program.replace(REPLACEABLE_TOKEN, str(generate_limb(fdp)), 1)
    try:
        program = compile_cairo(cairo_program, PRIME)
    except KeyboardInterrupt:
        sys.exit("Fuzzing stopped!")
    except:
        failed_input_name = write_failing_file(fdp, cairo_program)
        sys.exit(f"Failed to compile cairo program. Check file: {failed_input_name}")

    # Get Rust implementation memory
    rust_err = False
    try:
        raw_rs_mem = cairo_run_dump_mem(json.dumps(program.dump()))
    except KeyboardInterrupt:
        sys.exit("Fuzzing stopped!")
    except PanicTriggered as error:
        failed_input_name = write_failing_file(fdp, cairo_program)
        sys.exit(f"{error}\nCheck file: {failed_input_name}")
    except VMError:
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
    except KeyboardInterrupt:
        sys.exit("Fuzzing stopped!")
    except:
        python_err = True

    if not (rust_err or python_err):
        try:
            check_mem(raw_py_mem=raw_py_mem, raw_rs_mem=raw_rs_mem)
        except AssertionError:
            failed_input_name = write_failing_file(fdp, cairo_program)
            sys.exit(f"Memory files differ. Check file: {failed_input_name}")
    elif rust_err != python_err:
        write_failing_file(fdp, cairo_program)
        assert rust_err == python_err, f"Rust is error: {rust_err}, Python is error: {python_err}"
    
LOADED_HINTS = load_hints()
atheris.Setup(sys.argv, diff_fuzzer)
atheris.Fuzz()

