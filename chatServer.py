import signal
import socket
import struct
import threading

signal.signal(signal.SIGINT, signal.SIG_DFL)

PORT = 1234
HEADER_LENGTH = 2


def receive_fixed_length_msg(sock, msglen):
    message = b''
    while len(message) < msglen:
        chunk = sock.recv(msglen - len(message))  # read some bytes
        if chunk == b'':
            raise RuntimeError("socket connection broken")
        message = message + chunk  # attach read bytes to the message

    return message


def receive_message(sock):
    header = receive_fixed_length_msg(sock,
                                      HEADER_LENGTH)  # read message header (the first 2 bytes contain the message length)
    message_length = struct.unpack("!H", header)[0]  # convert message length to int

    message = None
    if message_length > 0:  # if everything is OK
        message = receive_fixed_length_msg(sock, message_length)  # read the message
        message = message.decode("utf-8")

    return message


def send_message(sock, message):
    encoded_message = message.encode("utf-8")  # convert the message to a byte string, use the UTF-8 code table

    header = struct.pack("!H", len(encoded_message))  # create the header, the first 2 bytes contain the message length (HEADER_LENGTH)
                                                      # pack method "!H" : !=network byte order, H=unsigned short
    message = header + encoded_message  # first send the message length, then the message itself
    sock.sendall(message)


def client_thread(client_sock, client_addr):
    global clients

    print("[system] connected with " + client_addr[0] + ":" + str(client_addr[1]))
    print("[system] we now have " + str(len(clients)) + " clients")

    username = receive_message(client_sock)
    if username is None:
        return

    with clients_lock:
        clients[username.lower()] = client_sock

    try:
        while True:
            msg_received = receive_message(client_sock)

            if not msg_received:
                break

            if msg_received.startswith("/whisper"):
                parts = msg_received.split(" ", 2)
                if len(parts) < 3:
                    continue

                target_username, private_message = parts[1], parts[2]
                target_socket = clients.get(target_username.lower())

                if target_socket:
                    send_message(target_socket, f"[Private] {username}: {private_message}")
                else:
                    send_message(client_sock, f"[Error] User '{target_username}' not found.")
            else:
                broadcast_message = f"[RKchat] [{username}] : {msg_received}"
                print(broadcast_message)

                with clients_lock:
                    for target_socket in clients.values():
                        if target_socket != client_sock:
                            send_message(target_socket, broadcast_message)
    except:
        pass

    with clients_lock:
        del clients[username.lower()]
    print("[system] we now have " + str(len(clients)) + " clients")
    client_sock.close()


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", PORT))
server_socket.listen(1)

print("[system] listening ...")
clients = {}
clients_lock = threading.Lock()
while True:
    try:
        client_sock, client_addr = server_socket.accept()
        thread = threading.Thread(target=client_thread, args=(client_sock, client_addr))
        thread.daemon = True
        thread.start()

    except KeyboardInterrupt:
        break

print("[system] closing server socket ...")
server_socket.close()
