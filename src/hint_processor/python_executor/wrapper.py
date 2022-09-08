import select
import socket
import os
import time
import json
from typing import Iterable
from urllib import response

# VM structures definition

PRIME = 3618502788666131213697322783095070105623107215331596699973092056135872020481

class Memory:
    socket: socket
    
    def __init__(self, socket: socket):
        self.socket = socket

    def __getitem__(self, addr: tuple):
        None
    
    def __setitem__(self, addr: tuple, value: int):
        operation = {'operation': 'MEMORY_INSERT', 'args': json.dumps((addr, value))}
        self.socket.send(bytes(json.dumps(operation), 'utf-8'))
        response = self.socket.recv(2)
        assert(response == b'Ok')
        
class Ids:  
    def __init__(self, ids_dict: dict):   
        for key in ids_dict.keys():
            setattr(self, key, ids_dict[key])

class MemorySegmentManager:
    socket: socket

    def __init__(self, socket: socket):
        self.socket = socket
    
    def add(self) -> tuple:
        operation = {'operation': 'ADD_SEGMENT'}
        self.socket.send(bytes(json.dumps(operation), 'utf-8'))
        addr = self.socket.recv(10)
        addr = json.loads(addr)
        return (addr[0], addr[1])

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
    


# Establish connection to cairo-rs process
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('localhost', 60000))
s.listen()
conn, addr = s.accept()

# Receive data from cairo-rs
raw_data = bytearray()
data = conn.recv(1024)
if data:
    raw_data.extend(data)

# Organize & Create data
data = json.loads(raw_data)

ap = (data['ap'][0], data['ap'][1])
fp = (data['fp'][0], data['fp'][1])
code = data['code']

#Execute the hint
globals = {'memory': Memory(conn), 'segments': MemorySegmentManager(conn), 'ap': ap, 'fp': fp,}
exec(code, globals)

#Comunicate back to cairo-rs
operation = {'operation': 'Ok'}
conn.send(bytes(json.dumps(operation), encoding="utf-8"))

conn.close()
conn.__exit__


