from cairo_program_gen import generate_cairo_hint_program
hint_code = """
%{
    ids.c = ids.c + 1
    ids.low = ids.a & ((1<<64) - 1)
    ids.high = ids.a >> 64
%}
"""
print("\n".join(generate_cairo_hint_program(hint_code)))
