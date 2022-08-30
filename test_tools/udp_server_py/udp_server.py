'''
this is a UDP server to test src/udp.zig
'''
import socket
from sys import stderr
import logging

HOST = ''
PORT = 4000
BUFFER_SIZE = 1024

logger = logging.getLogger("udp test server")
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    level=logging.DEBUG
)

try:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((HOST, PORT))
        logger.debug("server started")
        while True:
            msg, address = server.recvfrom(BUFFER_SIZE)
            logger.debug(f'recieved message from {address}, "{msg.decode()}"')
            if msg == b'send test':
                server.sendto(b'recieve test', address)
            else:
                logger.debug("test failed")
except KeyboardInterrupt:
    pass