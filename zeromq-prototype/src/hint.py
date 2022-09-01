import zmq

context = zmq.Context()

socket = context.socket(zmq.REP)
socket.connect("tcp://localhost:5555")

message = socket.recv()
num = int.from_bytes(message, "little") << 1

socket.send(num.to_bytes((num.bit_length() + 7) // 8, byteorder='little'))
