from transport import accept_peer, send_message, receive_message
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from Load_keys import * 

import json
import secrets
import hashlib

BOB_PORT = 5000
PROTOCOL_ID = "CS6530-A2-v1"
ALICE_ID = "CS26D400"
BOB_ID = "CS26M016"

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

    print("M1 ",  M1)   # Debug line

    # Construct M2
    M2 = {
        "Alice_SID": M1["Alice_SID"],
        "Bob_SID": bobSID.hex(),
        "Bob_Ephemeral_PK": bobEphemeralPK.hex()
    }

    M2Json = json.dumps(M2)
    send_message(sock, M2Json.encode())     # Send M2

    # Construct transcript
    # Transcript = Protocol_ID || Alice_ID || Bob_ID || Alice_SID || Bob_SID || Alice_Ephemeral_PK || Bob_Ephemeral_PK 
    transcript = (
        PROTOCOL_ID.encode() + 
        ALICE_ID.encode() + 
        BOB_ID.encode() +
        bytes.fromhex(M1["Alice_SID"]) +
        bobSID +
        bytes.fromhex(M1["Alice_Ephemeral_PK"]) +
        bobEphemeralPK
    )

    # Hash the transcript
    transcriptHash = hashlib.sha256(transcript).digest()

    # Load Bob's LT private and public keys
    bobLTPrivateKey, bobLTPublicKey = LoadLTKeySelf("Bob")
    # Convert the self key back to key object for signing the transcript hash
    bobLTPrivateKey = Ed25519PrivateKey.from_private_bytes(bobLTPrivateKey)
    
    # Load Alice's LT public key
    aliceLTPublicKey = LoadLTKeyPeer("Alice")
    # Convert the peer key back to key object for verification
    aliceLTPublicKey = Ed25519PublicKey.from_public_bytes(aliceLTPublicKey)

    # Receive M3
    message = receive_message(sock)
    M3Json = message.decode()
    M3 = json.loads(M3Json)

    # Necessary checks for M3, verify the signature using alice long term public key
    aliceSignature = bytes.fromhex(M3["Alice_signature"])
    if len(aliceSignature) != 64: return 1

    try:
        aliceLTPublicKey.verify(aliceSignature, transcriptHash)
    except InvalidSignature:
        return 1

    print("M3 ", M3)   # Debug line

    # On a successful verification of M3, send M4 to Alice
    signature = bobLTPrivateKey.sign(transcriptHash)  # Sign the hash using the private key

    # Construct M4
    M4 = {
        "Bob_signature": signature.hex()
    }

    # print(M4)   # Debug line

    M4Json = json.dumps(M4)
    send_message(sock, M4Json.encode())

    print("LOG: Authenticated Handshake complete")

    sharedSecret = ComputeSharedSecret(bobEphPrivateKey, bytes.fromhex(M1["Alice_Ephemeral_PK"]))
    print(sharedSecret) # Debug line

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