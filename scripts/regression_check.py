#!/usr/bin/env python

from sys import argv

def estimate(stats):
    Ir, I1mr, ILmr, Dr, D1mr, DLmr, Dw, D1mw, DLmw = stats
    ram_hits = ILmr + DLmr + DLmw
    l3_hits = I1mr + D1mr + D1mw - ram_hits
    l1_hits = Ir + Dr + Dw - (ram_hits + l3_hits)
    cycles = l1_hits + (5 * l3_hits) + (35 * ram_hits)
    return Ir, l1_hits, l3_hits, ram_hits, cycles

_, new_file, old_file = argv[:]
with open(new_file) as new, open(old_file) as old:
    new = [int(events) for events in new.readlines()[-1].split(' ')[1:]]
    old = [int(events) for events in old.readlines()[-1].split(' ')[1:]]

new_estimate = estimate(new)
old_estimate = estimate(old)
diff = [x - y for x, y in zip(new_estimate, old_estimate)]
diff_percent = [100 * diff_x / old_x for diff_x, old_x in zip(diff, old_estimate)]

print(f"{new_file.lstrip('cachegrind.out.')}")
print(f"Instructions:\t\t{new_estimate[0]} ({diff_percent[0]:+.6f}%)")
print(f"L1 Accesses:\t\t{new_estimate[1]} ({diff_percent[1]:+.6f}%)")
print(f"L2 Accesses:\t\t{new_estimate[2]} ({diff_percent[2]:+.6f}%)")
print(f"RAM Accesses:\t\t{new_estimate[3]} ({diff_percent[3]:+.6f}%)")
print(f"Estimated Cycles:\t{new_estimate[4]} ({diff_percent[4]:+.6f}%)")
