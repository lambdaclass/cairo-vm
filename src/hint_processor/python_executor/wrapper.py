import socket
import os
import time
import json
from typing import Iterable

# VM structures definition

PRIME = 3618502788666131213697322783095070105623107215331596699973092056135872020481

class Memory:
    data: dict
    changes: list

    def __init__(self, data: dict):
        self.data = data
        self.changes = []

    def __getitem__(self, addr: tuple):
        return self.data.get(addr)
    
    def __setitem__(self, addr: tuple, value: int):
        self.data[addr] = value
        self.changes += [((addr, value))]

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
    


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('localhost', 50000))

s.listen()

#Receive data from cairo-rs
while 1:
    conn, addr = s.accept()
    raw_data = bytearray()

    t0 = time.time()
    try:
        while 1:
            data = conn.recv(8192)
            if data:
                raw_data.extend(data)
            else:
                break
        t1 = time.time()

# Parse & organize data from cairo-rs
        data = json.loads(raw_data)

        #Memory
        memory_data = dict()
        for addr, value in data['memory']:
            if value.__contains__('Int'):
                memory_data[(addr[0], addr[1])] = value['Int']
            else:
                memory_data[(addr[0], addr[1])] = (value['RelocatableValue']['segment_index'], value['RelocatableValue']['offset'])
            
        memory = Memory(memory_data)

        #MemorySegmentManager
        segments = MemorySegmentManager(memory, data['num_segments'])

        # RunContext pointers
        ap = (data['ap'][0], data['ap'][1])
        fp = (data['fp'][0], data['fp'][1])
        pc = (data['pc'][0], data['pc'][1])

        t2 = time.time()

        #Execute the hint
        code = data['code']
        globals = {'memory': memory, 'segments': segments, 'ap': ap, 'fp': fp, pc: 'pc'}
        print(memory.data)
        exec(data['code'], globals)
        print(memory.data)

        #Comunicate back to cairo-rs
        #conn.send(bytes(json.dumps(memory.changes),encoding="utf-8"))
        conn.send(bytes(71))

        conn.close()

        print("load time", t1- t0)
        print("execution time", t2- t1)
        break

    finally:
        conn.__exit__
