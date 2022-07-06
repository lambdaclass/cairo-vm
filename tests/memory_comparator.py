#!/usr/bin/env python3

import sys

def main():
    filename1 = sys.argv[1]
    filename2 = sys.argv[2]
    cairo_mem = set()
    cleo_mem = set()

    with open(filename1, 'rb') as f:
        byte = f.read(40)
        cairo_mem.add(byte)

    with open(filename2, 'rb') as f:
        byte = f.read(40)
        cleo_mem.add(byte)

    assert(cairo_mem == cleo_mem)

if __name__ == '__main__':
    main()

