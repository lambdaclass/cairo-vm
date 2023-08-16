#!../cairo-vm-env/bin/python3
import os 
import sys 
import subprocess
import atheris
import json
from cairo_program_gen import generate_cairo_hint_program, REPLACEABLE_TOKEN

def check_mem(filename1, filename2):
    cairo_mem = {}
    cairo_rs_mem = {}

    with open(filename1, 'rb') as f:
        cairo_raw = f.read()
        assert len(cairo_raw) % 40 == 0, f'{filename1}: malformed memory file from Cairo VM'
        chunks = len(cairo_raw) // 40
        for i in range(0, chunks):
            chunk = cairo_raw[i*40:(i+1)*40]
            k, v = int.from_bytes(chunk[:8], 'little'), int.from_bytes(chunk[8:], 'little')
            assert k not in cairo_mem, f'{filename1}: address {k} has two values'
            cairo_mem[k] = v
        assert len(cairo_mem) * 40 == len(cairo_raw), f'{filename1}: {len(cairo_mem) * 40} != {len(cairo_raw)}'

    with open(filename2, 'rb') as f:
        cairo_rs_raw = f.read()
        assert len(cairo_rs_raw) % 40 == 0, f'{filename2}: malformed memory file from cairo-vm'
        chunks = len(cairo_rs_raw) // 40
        for i in range(0, chunks):
            chunk = cairo_rs_raw[i*40:(i+1)*40]
            k, v = int.from_bytes(chunk[:8], 'little'), int.from_bytes(chunk[8:], 'little')
            assert k not in cairo_rs_mem, f'{filename2}: address {k} has two values'
            cairo_rs_mem[k] = v
        assert len(cairo_rs_mem) * 40 == len(cairo_rs_raw), f'{filename2}: {len(cairo_rs_mem) * 40} != {len(cairo_rs_raw)}'

    assert len(cairo_mem) == len(cairo_rs_mem), f'{filename2}: len(cairo_mem)={len(cairo_mem)} len(cairo_mem)={len(cairo_rs_mem)}'
    if cairo_mem != cairo_rs_mem:
        print(f'Mismatch between {filename1} (Cairo) and {filename2} (cairo_rs)')
        print('keys in Cairo but not cairo-vm:')
        for k in cairo_mem:
            if k in cairo_rs_mem:
                continue
            print(f'{k}:{v}')
        print('keys in cairo_rs but not Cairo:')
        for k in cairo_rs_mem:
            if k in cairo_mem:
                continue
            print(f'{k}:{v}')
        print('mismatched values (Cairo <-> cairo_rs)):')
        for k in cairo_rs_mem:
            if k not in cairo_mem:
                continue
            if cairo_rs_mem[k] == cairo_mem[k]:
                continue
            print(f'{k}:({cairo_mem[k]} <-> {cairo_rs_mem[k]})')
        exit(1)

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

@atheris.instrument_func
def diff_fuzzer(data):
    fdp = atheris.FuzzedDataProvider(data)
    hint = fdp.PickValueInList(LOADED_HINTS)

    program = generate_cairo_hint_program(hint)
    replace_count = program.count(REPLACEABLE_TOKEN)
    for _ in range(replace_count):
        program = program.replace(REPLACEABLE_TOKEN, str(generate_limb(fdp)), 1)
    
    base_filename = hex(fdp.ConsumeUInt(8))
    cairo_filename = base_filename + ".cairo"
    json_filename = base_filename + ".json"
    py_mem_filename = base_filename + ".py_mem"
    rs_mem_filename = base_filename + ".rs_mem"

    with open(cairo_filename, 'w', encoding='utf-8') as file:
        data = file.write(program)
    
    subprocess.run(["cairo-compile", cairo_filename, "--output", json_filename])

    py_command = ["cairo-run", "--program", json_filename, "--memory_file", py_mem_filename]
    rs_command = ["./../../target/release/cairo-vm-cli", json_filename, "--memory_file", rs_mem_filename]

    py_process = subprocess.Popen(py_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    rs_process = subprocess.Popen(rs_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    py_stdout, py_stderr = py_process.communicate()
    rs_stdout, rs_stderr = rs_process.communicate()

    if py_stdout and rs_stdout:
        check_mem(py_mem_filename, rs_mem_filename)
    
        os.remove(cairo_filename)
        os.remove(json_filename)
        os.remove(rs_mem_filename)
        os.remove(py_mem_filename)

    elif py_stderr and rs_stderr:
        print("py error: ", py_stderr , "\n")
        print("rs error: ", rs_stderr , "\n")
    elif py_stderr and not rs_stderr or rs_stderr and not py_stderr:
        print("py stdout: ", py_stdout , "\n")
        print("rs stdout: ", rs_stdout , "\n")
        print("py error: ", py_stderr , "\n")
        print("rs error: ", rs_stderr , "\n")
        raise TypeError("the results differ")
    
LOADED_HINTS = load_hints()
atheris.Setup(sys.argv, diff_fuzzer)
atheris.Fuzz()

