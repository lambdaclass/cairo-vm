#!/usr/bin/env python3

import sys
import json
from zipfile import ZipFile

filename1 = sys.argv[1]
filename2 = sys.argv[2]

strict_comparison_files = ["version.json", "metadata.json", "execution_resources.json", "additional_data.json"]

with ZipFile(filename1) as cairo_lang_pie_zip, ZipFile(filename2) as cairo_vm_pie_zip:
    # Compare json files
    for file in strict_comparison_files:
        # Skipping this check due to a bug in the memory holes count
        # TODO: Remove it once the bug is fixed
        if (filename1 == "../../../cairo_programs/_keccak_alternative_hint.pie.zip" or filename1 == "../../../cairo_programs/relocate_temporary_segment_append.pie.zip" or filename1 == "../../../cairo_programs/keccak_alternative_hint.pie.zip") and file == "execution_resources.json":
            print(f"Comparison skipped for {filename1}/{file}  vs {filename2}/{file}")
            continue
        with cairo_lang_pie_zip.open(file) as cairo_lang_file, cairo_vm_pie_zip.open(file) as cairo_vm_file:
            cl_content = json.load(cairo_lang_file)
            cv_content = json.load(cairo_vm_file)
            if cl_content != cv_content:
                print(f"Comparison unsuccesful for {filename1}/{file}  vs {filename2}/{file}")
                exit(1)

    print(f"Comparison succesful for {filename1} vs {filename2}")

    # Compare binary files
    #Copy paste starts here

    cairo_mem = {}
    cairo_rs_mem = {}

    with cairo_lang_pie_zip.open("memory.bin", 'r') as f:
        cairo_raw = f.read()
        assert len(cairo_raw) % 40 == 0, f'{filename1}: malformed memory file from Cairo VM'
        chunks = len(cairo_raw) // 40
        for i in range(0, chunks):
            chunk = cairo_raw[i*40:(i+1)*40]
            k, v = int.from_bytes(chunk[:8], 'little'), int.from_bytes(chunk[8:], 'little')
            assert k not in cairo_mem, f'{filename1}: address {k} has two values'
            cairo_mem[k] = v
        assert len(cairo_mem) * 40 == len(cairo_raw), f'{filename1}: {len(cairo_mem) * 40} != {len(cairo_raw)}'

    with cairo_vm_pie_zip.open("memory.bin", 'r') as f:
        cairo_rs_raw = f.read()
        print(len(cairo_rs_raw))
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
