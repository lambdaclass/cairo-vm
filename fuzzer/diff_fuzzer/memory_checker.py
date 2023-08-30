def check_mem(raw_py_mem, raw_rs_mem):
    py_mem = {}
    rs_mem = {}

    assert len(raw_py_mem) % 40 == 0, f'Python implementation: malformed memory file'
    chunks = len(raw_py_mem) // 40
    for i in range(0, chunks):
        chunk = raw_py_mem[i*40:(i+1)*40]
        k, v = int.from_bytes(chunk[:8], 'little'), int.from_bytes(chunk[8:], 'little')
        assert k not in py_mem, f'Python implementation: address {k} has two values'
        py_mem[k] = v
    assert len(py_mem) * 40 == len(raw_py_mem), f'Python implementation: {len(py_mem) * 40} != {len(raw_py_mem)}'

    assert len(raw_rs_mem) % 40 == 0, f'Rust implementation: malformed memory file from cairo-vm'
    chunks = len(raw_rs_mem) // 40
    for i in range(0, chunks):
        chunk = raw_rs_mem[i*40:(i+1)*40]
        k, v = int.from_bytes(chunk[:8], 'little'), int.from_bytes(chunk[8:], 'little')
        assert k not in rs_mem, f'Rust implementation: address {k} has two values'
        rs_mem[k] = v
    assert len(rs_mem) * 40 == len(raw_rs_mem), f'Rust implementation: {len(rs_mem) * 40} != {len(raw_rs_mem)}'

    assert rs_mem == py_mem, "Mismatch in memory files"

