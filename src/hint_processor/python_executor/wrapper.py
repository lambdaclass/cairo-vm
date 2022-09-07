import select
import socket
import os
import time
import json
from typing import Iterable

# VM structures definition

PRIME = 3618502788666131213697322783095070105623107215331596699973092056135872020481

class Memory:
    socket: socket
    
    def __init__(self, socket: socket):
        self.socket = socket

    def __getitem__(self, addr: tuple):
        None
    
    def __setitem__(self, addr: tuple, value: int):
        #socket.send(bytes('SETITEM', addr, value))
        None

class Ids:  
    def __init__(self, ids_dict: dict):   
        for key in ids_dict.keys():
            setattr(self, key, ids_dict[key])

class MemorySegmentManager:
    socket: socket

    def __init__(self, socket: socket):
        self.socket = socket
    
    def add(self) -> tuple:
        self.socket.send(bytes('ADD_SEGMENT', encoding="utf-8"))
        print("SENT OP")
        #addr = json.loads()
        addr = self.socket.recv(10)

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
code = 'segments.add()'

#Execute the hint
#globals = {'memory': Memory(conn), 'segments': MemorySegmentManager(conn), 'ap': ap, 'fp': fp,}
#exec(data['code'], globals)

conn.sendall(bytes('ADD_SEGMENT', encoding="utf-8"))
#conn.shutdown(socket.SHUT_WR)
print("SENT OP")
#addr = json.loads()
data = bytearray()
data = conn.recv(1024)
print("DATA",data)
#print(json.loads(data))

#Comunicate back to cairo-rs
print("bytes sent", conn.send(bytes('Ok', encoding="utf-8")))

conn.close()
conn.__exit__


