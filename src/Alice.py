from transport import connect_to_peer, send_message, receive_message
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from Load_keys import * 
import secrets
import hashlib
import json
import sys

isManInTheMiddle = False
BOB_PORT = 5000
MALLORY_PORT = 5005
PROTOCOL_ID = "CS6530-A2-v1"
ALICE_ID = "CS26D400"
BOB_ID = "CS26M016"

argLen = len(sys.argv)

def SendAndReceiveMessage(ip, port):
    sock = connect_to_peer(ip, port)
    print("LOG: Alice connected to ", ip, ":", port)
    send_message(sock, b"The secret is 1234")
    print("LOG: Message sent to ", ip, ":", port)
    message = receive_message(sock)
    print("MSG: ", message.decode())
    return 0

def ConnectWrapper(ip, port):
    sock = connect_to_peer(ip, port)
    return sock

def PerformAuthEphHandshake(sock):
    # Ephermeral private and public keys for Alice
    aliceEphPrivateKey = X25519PrivateKey.generate()
    aliceEphPublicKey = aliceEphPrivateKey.public_key()

    # Get 32B raw public key for Alice
    aliceEphemeralPK = aliceEphPublicKey.public_bytes(encoding=serialization.Encoding.Raw,
                                                      format=serialization.PublicFormat.Raw)
    if (len(aliceEphemeralPK) != 32): return 1  # Check the length

    # Generate 16B SID for Alice
    aliceSID = secrets.token_bytes(16)

    # Construct M1
    M1 = {
        "Alice_SID": aliceSID.hex(),
        "Alice_Ephemeral_PK": aliceEphemeralPK.hex()
    }

    M1Json = json.dumps(M1)
    send_message(sock, M1Json.encode())     # Send M1

    # Receive M2
    message = receive_message(sock)
    M2Json = message.decode()
    M2 = json.loads(M2Json)

    # Necessary checks for M2, check sizes of each field, Alice SID and PK
    if (len(bytes.fromhex(M2["Bob_SID"])) != 16 or
        M2["Alice_SID"] != M1["Alice_SID"] or
        len(bytes.fromhex(M2["Bob_Ephemeral_PK"])) != 32): return 1

    print(M2)   # Debug line

    # Construct transcript
    # Transcript = Protocol_ID || Alice_ID || Bob_ID || Alice_SID || Bob_SID || Alice_Ephemeral_PK || Bob_Ephemeral_PK 
    transcript = (
        PROTOCOL_ID.encode() + 
        ALICE_ID.encode() + 
        BOB_ID.encode() +
        aliceSID +
        bytes.fromhex(M2["Bob_SID"]) +
        aliceEphemeralPK +
        bytes.fromhex(M2["Bob_Ephemeral_PK"])
    )

    # Hash the transcript
    transcriptHash = hashlib.sha256(transcript).digest()

    # Load Alice's LT private and public keys
    aliceLTPrivateKey, aliceLTPublicKey = LoadLTKeySelf("Alice")

    # Load Bob's LT public key
    bobLTPublicKey = LoadLTKeyPeer("Bob")

    # Convert the key back to key object for signing the transcript hash
    aliceLTPrivateKey = Ed25519PrivateKey.from_private_bytes(aliceLTPrivateKey)
    signature = aliceLTPrivateKey.sign(transcriptHash)  # Sign the hash using the private key

    
    return 0

if (argLen < 2):
    print("Usage: python Alice.py <Receiver-IP> [MITM-IP]")
    raise SystemExit(1)
elif (argLen == 2):
    BobIP = sys.argv[1]
elif (argLen == 3):
    BobIP = sys.argv[1]
    MalloryIP = sys.argv[2]
    isManInTheMiddle = True
else:
    print("Usage: python Alice.py <Receiver-IP> [MITM-IP]")
    raise SystemExit(1)

if (not isManInTheMiddle):
    # sending without MITM
    # SendAndReceiveMessage(BobIP, BOB_PORT)
    sock = ConnectWrapper(BobIP, BOB_PORT)
    status = PerformAuthEphHandshake(sock)
    if (status): print("Authenticated Handshake Failure")

else:
    # sending through MITM
    SendAndReceiveMessage(MalloryIP, MALLORY_PORT)
    pass
