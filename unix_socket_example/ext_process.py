import socket
import os
import sys
import utils
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

    try:
        while 1:
            data = conn.recv(8192)
            if data:
                print("type", type(data))
                print("received ", data)

                # x = utils.Memory
                # x = json.loads(data)
                # print("x ", x.data)
                # print("type x", type(x))


    finally:
        conn.__exit__
