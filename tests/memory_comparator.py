#!/usr/bin/env python3

import sys
from collections import Counter

def main():
    filename1 = sys.argv[1]
    filename2 = sys.argv[2]
    cairo_mem = Counter()
    cleo_mem = Counter()

    with open(filename1, 'rb') as f:
        byte = f.read(40)
        cairo_mem.update(byte)

    with open(filename2, 'rb') as f:
        byte = f.read(40)
        cleo_mem.update(byte)

    assert(cairo_mem == cleo_mem)

if __name__ == '__main__':
    main()

