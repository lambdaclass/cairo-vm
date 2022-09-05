import socket
import os
import sys
from typing import Dict
import utils
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
    xs = bytearray()

    memory = dict()

    t0 = time.time()
    try:
        while 1:
            data = conn.recv(8192)
            if data:
                xs.extend(data)
                # final =+ data
                # print("received ", data)

                # x = utils.Memory
                # x = json.loads(data)
                # print("x ", x.data)
                # print("type x", type(x))
            # print(xs)
            else:
                break
        t1 = time.time()

        x = json.loads(xs)
        for i, value in enumerate(x['data']):
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
