import socket
import subprocess
import sys
import threading
import time
import json
from typing import Iterable, Union
from urllib import response

# VM structures definition

PRIME = 3618502788666131213697322783095070105623107215331596699973092056135872020481

# MaybeRelocatable & Relocatable classes taken from Python VM
# TODO: check if we can import them directly or need changes/overrides
class RelocatableValue:
    segment_index: int
    offset: int

    def to_tuple(self):
        return (self.segment_index, self.offset)

    def __init__(self, tuple):
        self.segment_index = tuple[0]
        self.offset = tuple[1]

    def __add__(self, other: "MaybeRelocatable") -> "RelocatableValue":
        if isinstance(other, int):
            return RelocatableValue((self.segment_index, self.offset + other))
        assert not isinstance(
            other, RelocatableValue
        ), f"Cannot add two relocatable values: {self} + {other}."
        return NotImplemented

    def __radd__(self, other: "MaybeRelocatable") -> "RelocatableValue":
        return self + other

    def __sub__(self, other: "MaybeRelocatable") -> "MaybeRelocatable":
        if isinstance(other, int):
            return RelocatableValue((self.segment_index, self.offset - other))
        assert self.segment_index == other.segment_index, (
            "Can only subtract two relocatable values of the same segment "
            f"({self.segment_index} != {other.segment_index})."
        )
        return self.offset - other.offset

    def __mod__(self, other: int):
        return RelocatableValue((self.segment_index, self.offset % other))

    def __lt__(self, other: "MaybeRelocatable"):
        if isinstance(other, int):
            # Integers are considered smaller than all relocatable values.
            return False
        if not isinstance(other, RelocatableValue):
            return NotImplemented
        return (self.segment_index, self.offset) < (other.segment_index, other.offset)

    def __le__(self, other: "MaybeRelocatable"):
        return self < other or self == other

    def __ge__(self, other: "MaybeRelocatable"):
        return not (self < other)

    def __gt__(self, other: "MaybeRelocatable"):
        return not (self <= other)

MaybeRelocatable = Union[int, RelocatableValue]

# Impl & definition of messenger classes
class Memory:
    socket: socket
    
    def __init__(self, socket: socket):
        self.socket = socket

    def __getitem__(self, addr: RelocatableValue):
        operation = {'operation': 'MEMORY_GET', 'args': json.dumps(addr.to_tuple())}
        self.socket.send(bytes(json.dumps(operation), 'utf-8'))
        value = self.socket.recv(1024)
        value = json.loads(value)
        if value.__contains__('Int'):
            return value['Int'][1][0]
        elif value.__contains__('RelocatableValue'):
            return (RelocatableValue((value['RelocatableValue']['segment_index'], value['RelocatableValue']['offset'])))
    
    def __setitem__(self, addr: MaybeRelocatable, value: MaybeRelocatable):
        if isinstance(value, RelocatableValue):
            value = value.to_tuple()
        operation = {'operation': 'MEMORY_INSERT', 'args': json.dumps((addr.to_tuple(), value))}
        self.socket.send(bytes(json.dumps(operation), 'utf-8'))
        response = self.socket.recv(2)
        assert(response == b'Ok')
        
class Ids:
    def __init__(self, ids_dict: dict):  
        for key in ids_dict.keys():
            if ids_dict[key]:
                if ids_dict[key].__contains__('Int'):
                    setattr(self, key, ids_dict[key]['Int'][1][0])
                elif ids_dict[key].__contains__('RelocatableValue'):
                    setattr(self, key, (RelocatableValue((ids_dict[key]['RelocatableValue']['segment_index'], ids_dict[key]['RelocatableValue']['offset']))))
            else: 
                setattr(self, key, None)

class MemorySegmentManager:
    socket: socket
    memory: Memory

    def __init__(self, socket: socket, memory: Memory):
        self.socket = socket
        self.memory = memory
    
    def add(self) -> tuple:
        operation = {'operation': 'ADD_SEGMENT'}
        self.socket.send(bytes(json.dumps(operation), 'utf-8'))
        addr = self.socket.recv(10)
        addr = json.loads(addr)
        return (RelocatableValue(addr[0], addr[1]))

    def gen_arg(self, arg, apply_modulo_to_args=True):
        if isinstance(arg, Iterable):
            base = self.add()
            self.write_arg(base, arg)
        if apply_modulo_to_args and isinstance(arg, int):
            return arg % PRIME
        return arg

    def write_arg(self, ptr: RelocatableValue, arg, apply_modulo_to_args=True):
        assert isinstance(arg, Iterable)
        data = [self.gen_arg(arg=x, apply_modulo_to_args=apply_modulo_to_args) for x in arg]
        return self.load_data(ptr, data)
    
    def load_data(self, ptr: RelocatableValue, data):
        for i, v in enumerate(data):
            self.memory[ptr + i] = v
        return ptr + ptr + len(data)

def execute_hints(s: socket):
    while True:
        s.listen()
        conn, addr = s.accept()   
        raw_data = bytearray()
        data = conn.recv(1024)
        if data:
            raw_data.extend(data)
        # Organize & Create data
        if raw_data == b'Terminate':
            conn.close()
            conn.__exit__
            break
        data = json.loads(raw_data)
        # Receive data from cairo-rs
        ap = RelocatableValue((1, data['ap']))
        fp = RelocatableValue((1, data['fp']))
        ids = Ids(data['ids'])
        memory = Memory(conn)
        code = data['code']
        #Execute the hint
        globals = {'memory': memory, 'segments': MemorySegmentManager(conn, memory), 'ap': ap, 'fp': fp, 'ids': ids}
        exec(code, globals)
        #Comunicate back to cairo-rs
        #Update Data
        operation = {'operation': 'UPDATE_DATA', 'args': json.dumps({'ids': ids.__dict__,'ap': ap.offset, 'fp': fp.offset})}
        conn.send(bytes(json.dumps(operation), encoding="utf-8"))
        response = conn.recv(2)
        assert(response == b'Ok')
        #End Hint
        operation = {'operation': 'Ok'}
        conn.send(bytes(json.dumps(operation), encoding="utf-8"))

        conn.close()
        conn.__exit__


# Establish connection to cairo-rs process
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('localhost', 60000))
process_hints = threading.Thread(target=execute_hints, args=(s,))
# Launch cairo-rs as a subprocess
cairo_rs = subprocess.Popen(["target/release/cairo-rs-run", sys.argv[1]])
# Start hint processing thread
process_hints.start()
cairo_rs.wait()
# Stop processing of hints via message
new_s = socket.create_connection(('localhost', 60000))
new_s.send(bytes("Terminate", 'utf-8'))
process_hints.join()
new_s.__exit__()
