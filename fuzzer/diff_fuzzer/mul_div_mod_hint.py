#!../cairo-vm-env/bin/python3
import os 
import sys 
import subprocess
import atheris
import json

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
    return range_check_max -1
    if fdp.ConsumeProbability() > 0.3:
       return fdp.ConsumeIntInRange(range_check_max >> 1, range_check_max) 
    elif fdp.ConsumeBool():
       return fdp.ConsumeIntInRange(0, 10) 
    else:
       return fdp.ConsumeIntInRange(0, range_check_max)

def generalize_variable(line, fdp):
    
    if line.rfind('(') != -1 :
        trimed_var_line = line.split("(", 1)[1].split(")", 1)[0]
        trimed_var_line = "(" + trimed_var_line + ")"
        trimed_var_line = trimed_var_line.replace("=,", "=" + str(generate_limb(fdp)) + ",")
        trimed_var_line = trimed_var_line.replace(")", str(generate_limb(fdp)) + ")")
        return line.split("(", 1)[0] + trimed_var_line + line.split(")", 1)[1]
    else :
        rand_line = line.replace(";", str(generate_limb(fdp)) + ";")
        return rand_line
    

def generalize_main(main, fdp):
    # Find variables to replace and inject rand data
    new_main = []

    for line in main:
        # Find variables
        if line.rfind(' let ') != -1 :
            new_main.append(generalize_variable(line, fdp))
        else:
            new_main.append(line)
    return new_main

def get_main_lines(program):
    main_begin = False
    main_end = False
    main = []
    it = 0
    init = 0
    end = 0

    while not main_end: 
        if program[it].rfind('func main') != -1 :
            main_begin = True
            init = it

        if main_begin == True :
            main.append(program[it])

        if program[it].rfind('}') != -1 :
            main_end = True
            end = it
        it = it + 1
    
    return (main, init, end)

def change_main(program, new_main, init, end):
    it = 0 
    main_it = 0

    for line in program:
        if it >= init and it <= end:
            program[it] = new_main[main_it]
            main_it = main_it + 1
        it = it + 1
    return program

def get_random_hint(fdp):
    hint_number = fdp.ConsumeIntInRange(1, 102)
    f = open('hint_accountant/whitelists/latest.json')
    data = json.load(f)
    it = 1

    rand_hint_lines = []
    for entry in data["allowed_reference_expressions_for_hint"]:
        hint_lines = entry["hint_lines"]
        if it == hint_number:
            rand_hint_lines.extend(hint_lines)
        it = it +1

    return rand_hint_lines

@atheris.instrument_func
def diff_fuzzer(data):
    fdp = atheris.FuzzedDataProvider(data)
    hint = get_random_hint(fdp)
    
    with open('fuzzer/diff_fuzzer/uint256_split64.cairo', 'r', encoding='utf-8') as file:
        program = file.readlines()
        
    (main, init, end) = get_main_lines(program)

    new_main = generalize_main(main, fdp)

    new_program = change_main(program, new_main, init, end)

    with open('uint256_split64_modif.cairo', 'w', encoding='utf-8') as file:
        data = file.writelines(new_program)

    cairo_filename = "uint256_split64_modif.cairo"
    json_filename = "uint256_split64_modif.json"

    rust_output = subprocess.run(["cairo-compile", cairo_filename, "--output",  json_filename])
    rust_output = subprocess.run(["target/release/cairo-vm-cli", json_filename, "--memory_file", json_filename + "rs_mem"], stdout=subprocess.PIPE)
    python_output = subprocess.run(["cairo-run", "--program", json_filename, "--memory_file", json_filename + "py_mem"], stdout=subprocess.PIPE)

    check_mem(json_filename + "py_mem", json_filename + "rs_mem")
    
    check_mem("py.mem", "rs.mem")

    os.remove(json_filename)
    os.remove(json_filename + "rs_mem")
    os.remove(json_filename + "py_mem")

    rust_nums = [int(n) for n in rust_output.stdout.split() if n.isdigit()]
    python_nums = [int(n) for n in python_output.stdout.split() if n.isdigit()]

    assert rust_nums == python_nums

atheris.Setup(sys.argv, diff_fuzzer)
atheris.Fuzz()

diff_fuzzer(23424)
