#!../cairo-vm-env/bin/python3
import os 
import sys 
import subprocess
import atheris

@atheris.instrument_func
def generate_limb(fdp):
    range_check_max = 340282366920938463463374607431768211456 
    if fdp.ConsumeProbability() > 0.3:
        return fdp.ConsumeIntInRange(range_check_max >> 1, range_check_max) 
    elif fdp.ConsumeBool():
        return fdp.ConsumeIntInRange(0, 10) 
    else:
        return fdp.ConsumeIntInRange(0, range_check_max)

@atheris.instrument_func
def diff_fuzzer(data):
    fdp = atheris.FuzzedDataProvider(data)

    a_low = generate_limb(fdp)
    a_high = generate_limb(fdp)
    b_low = generate_limb(fdp)
    b_high = generate_limb(fdp)
    div_low = generate_limb(fdp)
    div_high = generate_limb(fdp)

    # Ensure div != 0
    if div_low + div_high == 0:
        new_limb = fdp.ConsumeIntInRange(1, 340282366920938463463374607431768211456)     
        if fdp.ConsumeBool():
            div_low = new_limb
        else:
            div_high = new_limb

    with open('uint256_mul_div_mod.json', 'r', encoding='utf-8') as file:
        data = file.readlines()

    data[331] = '"' + hex(a_low) + '"' + ",\n" 
    data[333] = '"' + hex(a_high) + '"' + ",\n" 
    data[335] = '"' + hex(b_low) + '"' + ",\n" 
    data[337] = '"' + hex(b_high) + '"' + ",\n" 
    data[339] = '"' + hex(div_low) + '"' + ",\n" 
    data[341] = '"' + hex(div_high) + '"' + ",\n" 

    filename = hex(fdp.ConsumeUInt(8)) + ".input"

    with open(filename, 'w', encoding='utf-8') as file:
        file.writelines(data)

    rust_output = subprocess.run(["./../../target/release/cairo-vm-cli", "--layout", "starknet", "--print_output", filename], stdout=subprocess.PIPE)
    python_output = subprocess.run(["cairo-run", "--layout", "starknet", "--print_output", "--program", filename], stdout=subprocess.PIPE)

    os.remove(filename)

    rust_nums = [int(n) for n in rust_output.stdout.split() if n.isdigit()]
    python_nums = [int(n) for n in python_output.stdout.split() if n.isdigit()]

    assert rust_nums == python_nums

atheris.Setup(sys.argv, diff_fuzzer)
atheris.Fuzz()

