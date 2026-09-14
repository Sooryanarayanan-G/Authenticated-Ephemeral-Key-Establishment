from transport import accept_peer, send_message, receive_message
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

import json
import secrets

BOB_PORT = 5000

def PerformAuthEphHandshake(sock):
    # Ephermeral private and public keys for Bob
    bobEphPrivateKey = X25519PrivateKey.generate()
    bobEphPublicKey = bobEphPrivateKey.public_key()

    # Get 32B raw public key for Bob
    bobEphemeralPK = bobEphPublicKey.public_bytes(encoding=serialization.Encoding.Raw,
                                                  format=serialization.PublicFormat.Raw)
    if (len(bobEphemeralPK) != 32): return 1  # Check the length

    # Generate 16B SID for Bob
    bobSID = secrets.token_bytes(16)

    # Receive M1
    message = receive_message(sock)
    M1Json = message.decode()
    M1 = json.loads(M1Json)

    # Necessary checks for M1, check sizes of each field
    if (len(bytes.fromhex(M1["Alice_SID"])) != 16 or
        len(bytes.fromhex(M1["Alice_Ephemeral_PK"])) != 32): return 1

    print(M1)
    # Construct M2
    M2 = {
        "Alice_SID": M1["Alice_SID"],
        "Bob_SID": bobSID.hex(),
        "Alice_Ephemeral_PK": M1["Alice_Ephemeral_PK"]
    }

    M2Json = json.dumps(M2)
    send_message(sock, M2Json.encode())     # Send M2

    return 0

print(f"Bob: waiting on TCP port {BOB_PORT}...")

sock, peer = accept_peer(BOB_PORT)

print("Bob: connected to ", peer)

status = PerformAuthEphHandshake(sock)
if (status): print("Authenticated Handshake Failure")
# message = receive_message(sock);
# msgString = message.decode()
# print("MSG:", msgString)

# send_message(sock, b"Received secret " + msgString[-4:].encode())
print("LOG: Message sent to ", peer)

sock.close()