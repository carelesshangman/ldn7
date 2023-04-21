import socket
import struct
import sys
import threading
from datetime import datetime

PORT = 1234
HEADER_LENGTH = 2

def receive_fixed_length_msg(sock, msglen):
    message = b''
    while len(message) < msglen:
        chunk = sock.recv(msglen - len(message))
        if chunk == b'':
            raise RuntimeError("socket connection broken")
        message = message + chunk

    return message


def receive_message(sock):
    header = receive_fixed_length_msg(sock, HEADER_LENGTH)
    message_length = struct.unpack("!H", header)[0]

    message = None
    if message_length > 0:
        message = receive_fixed_length_msg(sock, message_length)
        message = message.decode("utf-8")

    return message


def send_message(sock, message):
    encoded_message = message.encode("utf-8")

    header = struct.pack("!H", len(encoded_message))
    message = header + encoded_message
    sock.sendall(message)


def message_receiver():
    while True:
        msg_received = receive_message(sock)
        if len(msg_received) > 0:
            print(msg_received)


print("[system] connecting to chat server ...")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", PORT))
print("[system] connected!")

username = input("Enter your username: ")
send_message(sock, username)

thread = threading.Thread(target=message_receiver)
thread.daemon = True
thread.start()

while True:
    try:
        msg_send = input("")
        timestamp = datetime.now().strftime('%H:%M:%S')
        send_message(sock, f"({timestamp}) {msg_send}")
    except KeyboardInterrupt:
        sys.exit()
