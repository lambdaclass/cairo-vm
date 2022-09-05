from typing import Iterable

PRIME = 3618502788666131213697322783095070105623107215331596699973092056135872020481

class Memory:
    data: dict
    changes: dict

    def __init__(self, data: dict):
        self.data = data
        self.changes = {}

    def __getitem__(self, addr: tuple):
        return self.data.get(addr)
    
    def __setitem__(self, addr: tuple, value: int):
        self.data[addr] = value
        self.changes[addr] = value

class Ids:  
    def __init__(self, ids_dict: dict):   
        for key in ids_dict.keys():
            setattr(self, key, ids_dict[key])

class MemorySegmentManager:
    memory: Memory
    num_segments: int

    def __init__(self, memory: Memory, num_segments: int):
        self.memory = memory
        self.num_segments = num_segments
    
    def add(self) -> tuple:
        base = (self.num_segments, 0)
        self.num_segments = self.num_segments + 1
        return base

    def gen_arg(self, arg, apply_modulo_to_args=True):
        if isinstance(arg, Iterable):
            base = self.add()
            self.write_arg(base, arg)
        if apply_modulo_to_args and isinstance(arg, int):
            return arg % PRIME
        return arg

    def write_arg(self, ptr: tuple, arg, apply_modulo_to_args=True):
        assert isinstance(arg, Iterable)
        data = [self.gen_arg(arg=x, apply_modulo_to_args=apply_modulo_to_args) for x in arg]
        return self.load_data(ptr, data)
    
    def load_data(self, ptr, data):
        for i, v in enumerate(data):
            self.memory[(ptr[0], ptr[1] + i)] = v
        return (ptr[0] + ptr[1] + len(data))

# initialize with random data
data = {}
data[(1,2)] = 4
data[(1,3)] = 5
ids_data = {"a": 3}
ids = Ids(ids_data)
memory = Memory(data)
ap = (1,2)
segments = MemorySegmentManager(memory, 0)
print(memory.data)
print(segments.num_segments)

memory[ap] = segments.add()
args = [12, 45, 67, 89, 90]
segments.write_arg(ap, args)
print(memory.data)


