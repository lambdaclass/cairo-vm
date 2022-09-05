import socket
import os
import time
import json

socket_path = "ipc.sock"

try:
    os.unlink(socket_path)
except OSError:
    pass

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(socket_path)

s.listen()

while 1:
    conn, addr = s.accept()
    raw_memory = bytearray()

    memory = dict()

    t0 = time.time()
    try:
        while 1:
            data = conn.recv(8192)
            if data:
                raw_memory.extend(data)
            else:
                break
        t1 = time.time()

        memory_dict = json.loads(raw_memory)
        for i, value in enumerate(memory_dict['data']):
            if value.__contains__('Int'):
                memory[(0, i)] = value['Int']
            else:
                memory[(0, i)] = (value['RelocatableValue']['segment_index'], value['RelocatableValue']['offset'])
        t2 = time.time()

        conn.close()
        # print(memory)
        print("load time", t1- t0)
        print("execution time", t2- t1)
        break

    finally:
        conn.__exit__
