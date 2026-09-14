from transport import accept_peer, send_message, receive_message

BOB_PORT = 5000

print(f"Bob: waiting on TCP port {BOB_PORT}...")

sock, peer = accept_peer(BOB_PORT)

print("Bob: connected to ", peer)

message = receive_message(sock);
msgString = message.decode()
print("MSG:", msgString)

send_message(sock, b"Received secret " + msgString[-4:].encode())
print("LOG: Message sent to ", peer)

sock.close()