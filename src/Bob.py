from transport import accept_peer, send_message, receive_message

BOB_PORT = 5000

print(f"Bob: waiting on TCP port {BOB_PORT}...")

sock, peer = accept_peer(BOB_PORT)

print("Bob: connected to ", peer)

message = receive_message(sock);
print("Message from Alice:", message.decode())

send_message(sock, b"Hello Alice from Bob")
print("Message sent to Alice")

sock.close()