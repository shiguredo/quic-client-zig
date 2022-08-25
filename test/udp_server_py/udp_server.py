'''
this is a UDP server to test src/udp.zig
'''
import socket
from sys import stderr

HOST = ''
PORT = 4000
BUFFER_SIZE = 1024

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.bind((HOST, PORT))
    msg, address = server.recvfrom(BUFFER_SIZE)
    if msg == b'send test':
        server.sendto(b'recieve test', address)
    else:
        print("test failed", file=stderr)
