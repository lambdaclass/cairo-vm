#!/usr/bin/env python3

import sys

def main():
    filename1 = sys.argv[1]
    filename2 = sys.argv[2]

    with open(filename1, 'rb') as f1, open(filename2, 'rb') as f2:
        compare_memory_file_contents(f1.read(), f2.read())

def compare_memory_file_contents(cairo_raw_mem, cairo_rs_raw_mem):
    cairo_mem = read_memory_file_contents(cairo_raw_mem)
    cairo_rs_mem = read_memory_file_contents(cairo_rs_raw_mem)

def read_memory_file_contents(raw_mem_content) -> {}:
        mem = {}
        assert len(raw_mem_content) % 40 == 0, f'Malformed memory file'
        chunks = len(raw_mem_content) // 40
        for i in range(0, chunks):
            chunk = raw_mem_content[i*40:(i+1)*40]
            k, v = int.from_bytes(chunk[:8], 'little'), int.from_bytes(chunk[8:], 'little')
            assert k not in mem, f'Address {k} has two values'
            mem[k] = v
        assert len(mem) * 40 == len(raw_mem_content), f'Malformed memory file'
        return mem

if __name__ == '__main__':
    main()

