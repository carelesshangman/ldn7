import signal

signal.signal(signal.SIGINT, signal.SIG_DFL)
import socket
import struct
import threading

PORT = 1234
HEADER_LENGTH = 2


def receive_fixed_length_msg(sock, msglen):
    message = b''
    while len(message) < msglen:
        chunk = sock.recv(msglen - len(message))  # preberi nekaj bajtov
        if chunk == b'':
            raise RuntimeError("socket connection broken")
        message = message + chunk  # pripni prebrane bajte sporocilu

    return message


def receive_message(sock):
    header = receive_fixed_length_msg(sock,
                                      HEADER_LENGTH)  # preberi glavo sporocila (v prvih 2 bytih je dolzina sporocila)
    message_length = struct.unpack("!H", header)[0]  # pretvori dolzino sporocila v int

    message = None
    if message_length > 0:  # ce je vse OK
        message = receive_fixed_length_msg(sock, message_length)  # preberi sporocilo
        message = message.decode("utf-8")

    return message


def send_message(sock, message):
    encoded_message = message.encode("utf-8")  # pretvori sporocilo v niz bajtov, uporabi UTF-8 kodno tabelo

    # ustvari glavo v prvih 2 bytih je dolzina sporocila (HEADER_LENGTH)
    # metoda pack "!H" : !=network byte order, H=unsigned short
    header = struct.pack("!H", len(encoded_message))

    message = header + encoded_message  # najprj posljemo dolzino sporocilo, slee nato sporocilo samo
    sock.sendall(message)


usernames = []
# funkcija za komunikacijo z odjemalcem (tece v loceni niti za vsakega odjemalca)
def client_thread(client_sock, client_addr):
    global clients
    global usernames
    # Prompt user to enter a username upon connection
    send_message(client_sock, "Enter your username:")
    username = receive_message(client_sock)
    usernames.append((username, client_sock))
    print("[system] connected with " + client_addr[0] + ":" + str(client_addr[1]) + " as " + username)
    print("[system] we now have " + str(len(clients)) + " clients")

    try:

        while True:  # neskoncna zanka
            msg_received = receive_message(client_sock)

            if not msg_received:  # ce obstaja sporocilo
                break

            if (msg_received.split(" ")[1] == '/whisper' or msg_received.split(" ")[1] == '/w') and len(msg_received.split(" ")) >= 4:
                timestamp = msg_received.split(" ")[0]
                sendTo = msg_received.split(" ")[2]
                textBlob = msg_received.split(" ")[3:]
                flagRecipient = False
                for sendToUsername, client_socket in usernames:
                    if sendToUsername == sendTo:
                        flagRecipient = True
                        result = ' '.join(textBlob)
                        send_message(client_socket, f"{timestamp} [{username}]->[{sendToUsername}]: {result}")
                        send_message(client_sock, f"{timestamp} [{username}]->[{sendToUsername}]: {result}")
                if flagRecipient == False:
                    send_message(client_sock, f"{timestamp} [System]: User '{sendTo}' not found.")
                continue

            # Prefix message with username
            msg_with_username = "[" + username + "] " + msg_received

            print("[RKchat] " + msg_with_username)

            for client in clients:
                send_message(client, msg_with_username.upper())
    except:
        # tule bi lahko bolj elegantno reagirali, npr. na posamezne izjeme. Trenutno kar pozremo izjemo
        pass

    # prisli smo iz neskoncne zanke
    with clients_lock:
        clients.remove(client_sock)
    print("[system] we now have " + str(len(clients)) + " clients")
    client_sock.close()


# kreiraj socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", PORT))
server_socket.listen(1)

# cakaj na nove odjemalce
print("[system] listening ...")
clients = set()
clients_lock = threading.Lock()
while True:
    try:
        # pocakaj na novo povezavo - blokirajoc klic
        client_sock, client_addr = server_socket.accept()
        with clients_lock:
            clients.add(client_sock)

        thread = threading.Thread(target=client_thread, args=(client_sock, client_addr));
        thread.daemon = True
        thread.start()

    except KeyboardInterrupt:
        break

print("[system] closing server socket ...")
server_socket.close()
