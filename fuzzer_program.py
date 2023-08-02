import sys
import atheris 
import subprocess

def diff_fuzzer(data):
    fdp = atheris.FuzzedDataProvider(data)
    num1 = fdp.ConsumeIntInRange(1,3618502788666131213697322783095070105623107215331596699973092056135872020481)
    num2 = fdp.ConsumeIntInRange(1,3618502788666131213697322783095070105623107215331596699973092056135872020481)
    num3 = fdp.ConsumeIntInRange(1,3618502788666131213697322783095070105623107215331596699973092056135872020481)
    num4 = fdp.ConsumeIntInRange(1,3618502788666131213697322783095070105623107215331596699973092056135872020481)
    num5 = fdp.ConsumeIntInRange(1,3618502788666131213697322783095070105623107215331596699973092056135872020481)
    num6 = fdp.ConsumeIntInRange(1,3618502788666131213697322783095070105623107215331596699973092056135872020481)
    

    with open('test_256.json', 'r', encoding='utf-8') as file:
        data = file.readlines()

    data[331] = '"' + hex(num1) + '"' + ",\n" 
    data[333] = '"' + hex(num2) + '"' + ",\n" 
    data[335] = '"' + hex(num3) + '"' + ",\n" 
    data[337] = '"' + hex(num4) + '"' + ",\n" 
    data[339] = '"' + hex(num5) + '"' + ",\n" 
    data[341] = '"' + hex(num6) + '"' + ",\n" 

    with open('test_256_a.json', 'w', encoding='utf-8') as file:
        file.writelines(data)

    rust_output = subprocess.run(["./target/release/cairo-vm-cli", "--layout", "starknet", "--print_output", "test_256_a.json"], stdout=subprocess.PIPE)
    python_output = subprocess.run(["cairo-run", "--layout", "starknet", "--print_output", "--program", "test_256_a.json"], stdout=subprocess.PIPE)

    rust_nums = [int(n) for n in rust_output.stdout.split() if n.isdigit()]
    python_nums = [int(n) for n in python_output.stdout.split() if n.isdigit()]

    print(rust_nums)
    print(python_nums)
    assert rust_nums == python_nums
    

atheris.instrument_all()
atheris.Setup(sys.argv, diff_fuzzer)
atheris.Fuzz()

fdp = atheris.FuzzedDataProvider(data)

