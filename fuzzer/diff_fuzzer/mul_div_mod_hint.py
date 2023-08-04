#!../cairo-vm-env/bin/python3
import os 
import sys 
import subprocess
#import atheris

#@atheris.instrument_func
def generate_limb(fdp):
    range_check_max = 340282366920938463463374607431768211456 
    return range_check_max -1
    #if fdp.ConsumeProbability() > 0.3:
    #    return fdp.ConsumeIntInRange(range_check_max >> 1, range_check_max) 
    #elif fdp.ConsumeBool():
    #    return fdp.ConsumeIntInRange(0, 10) 
    #else:
    #    return fdp.ConsumeIntInRange(0, range_check_max)

#@atheris.instrument_func
def diff_fuzzer():
    #fdp = atheris.FuzzedDataProvider(data)
    fdp = 1
    a_low = generate_limb(fdp)
    a_high = generate_limb(fdp)
    b_low = generate_limb(fdp)
    b_high = generate_limb(fdp)
    div_low = generate_limb(fdp)
    div_high = generate_limb(fdp)

    # Ensure div != 0
    #if div_low + div_high == 0:
    #    new_limb = fdp.ConsumeIntInRange(1, 340282366920938463463374607431768211456)     
    #    if fdp.ConsumeBool():
    #        div_low = new_limb
    #    else:
    #        div_high = new_limb

    """
    with open('uint256_mul_div_mod.json', 'r', encoding='utf-8') as file:
        data = file.readlines()

    data[326] = '"' + hex(a_low) + '"' + ",\n" 
    data[328] = '"' + hex(a_high) + '"' + ",\n" 
    data[330] = '"' + hex(b_low) + '"' + ",\n" 
    data[332] = '"' + hex(b_high) + '"' + ",\n" 
    data[334] = '"' + hex(div_low) + '"' + ",\n" 
    data[336] = '"' + hex(div_high) + '"' + ",\n" 

    filename = hex(5555555) + ".input"

    with open(filename, 'w', encoding='utf-8') as file:
        file.writelines(data)

    rust_output = subprocess.run(["./../../target/release/cairo-vm-cli", "--layout", "starknet", filename, "--memory_file", filename + "rs_mem"], stdout=subprocess.PIPE)
    python_output = subprocess.run(["cairo-run", "--layout", "starknet", "--program", "uint256_mul_div_mod.json", "--memory_file", filename + "py_mem"], stdout=subprocess.PIPE)

    check_mem(filename + "py_mem", filename + "rs_mem")
    """
    check_mem("py.mem", "rs.mem")

    #os.remove(filename)
    #os.remove(filename + "rs_mem")
    #os.remove(filename + "py_mem")

    #rust_nums = [int(n) for n in rust_output.stdout.split() if n.isdigit()]
    #python_nums = [int(n) for n in python_output.stdout.split() if n.isdigit()]

    #assert rust_nums == python_nums

#atheris.Setup(sys.argv, diff_fuzzer)
#atheris.Fuzz()

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

diff_fuzzer()
