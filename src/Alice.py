from transport import connect_to_peer, send_message, receive_message
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from Load_keys import * 
import secrets
import hashlib
import json
import sys

isManInTheMiddle = False
isAuthEnabled = True
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
    if (len(aliceEphemeralPK) != 32): return {}  # Check the length

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
        len(bytes.fromhex(M2["Bob_Ephemeral_PK"])) != 32): return {}

    print("M2 ", M2)   # Debug line

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
    # Convert the self key back to key object for signing the transcript hash
    aliceLTPrivateKey = Ed25519PrivateKey.from_private_bytes(aliceLTPrivateKey)

    # Load Bob's LT public key
    bobLTPublicKey = LoadLTKeyPeer("Bob")
    # Convert the peer key back to key object for verification
    bobLTPublicKey = Ed25519PublicKey.from_public_bytes(bobLTPublicKey)

    signature = aliceLTPrivateKey.sign(transcriptHash)  # Sign the hash using the private key

    # Construct M3
    M3 = {
        "Alice_signature": signature.hex()
    }

    # print(M3)   # Debug line

    M3Json = json.dumps(M3)
    send_message(sock, M3Json.encode())

    # Receive M4
    message = receive_message(sock)
    M4Json = message.decode()
    M4 = json.loads(M4Json)

    # Necessary checks for M4, verify the signature using bob long term public key
    bobSignature = bytes.fromhex(M4["Bob_signature"])
    if len(bobSignature) != 64: return {}

    try:
        bobLTPublicKey.verify(bobSignature, transcriptHash)
    except InvalidSignature:
        return {}

    print("M4 ", M4)   # Debug line

    print("LOG: Authenticated Handshake complete")

    sharedSecret = ComputeSharedSecret(aliceEphPrivateKey, bytes.fromhex(M2["Bob_Ephemeral_PK"]))
    print(sharedSecret) # Debug line

    #  derive K_Alice_to_Bob and K_Bob_to_Alice using HKDF-SHA-256 with Transcript_Hash as salt and the specified info strings.
    kAliceToBob, kBobToAlice = DeriveTwoDirectionalTrafficKeys(ikm=sharedSecret, salt=transcriptHash)

    # Return all the data needed for later part of the project, which involves AES
    return {
        "K_Alice_to_Bob": kAliceToBob,
        "K_Bob_to_Alice": kBobToAlice,
        "Alice_SID": aliceSID,
        "Bob_SID": bytes.fromhex(M2["Bob_SID"])
    }

# Performs handshake without ed25519 authentication: TR2
def PerformEphHandshake(sock):
    # Ephermeral private and public keys for Alice
    aliceEphPrivateKey = X25519PrivateKey.generate()
    aliceEphPublicKey = aliceEphPrivateKey.public_key()

    # Get 32B raw public key for Alice
    aliceEphemeralPK = aliceEphPublicKey.public_bytes(encoding=serialization.Encoding.Raw,
                                                        format=serialization.PublicFormat.Raw)
    if (len(aliceEphemeralPK) != 32): return {}  # Check the length

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
        len(bytes.fromhex(M2["Bob_Ephemeral_PK"])) != 32): return {}

    print("M2 ", M2)   # Debug line
    pass

if (argLen < 2):
    print("Usage: python Alice.py <Receiver-IP> [MITM-IP] [--disable-ed-auth]")
    raise SystemExit(1)
elif (argLen == 2):
    BobIP = sys.argv[1]
elif (argLen == 3):
    BobIP = sys.argv[1]
    if (sys.argv[2] == "--disable-ed-auth"):
        isAuthEnabled = False
    else:
        MalloryIP = sys.argv[2]
        isManInTheMiddle = True
elif (argLen == 4):
    BobIP = sys.argv[1]
    MalloryIP = sys.argv[2]
    isManInTheMiddle = True
    if (sys.argv[3] == "--disable-ed-auth"):
        isAuthEnabled = False
    else:
        raise SystemExit(1)
else:
    print("Usage: python Alice.py <Receiver-IP> [MITM-IP] [--disable-ed-auth]")
    raise SystemExit(1)

if (not isManInTheMiddle):
    # sending without MITM
    # SendAndReceiveMessage(BobIP, BOB_PORT)
    sock = ConnectWrapper(BobIP, BOB_PORT)

    # Auth is enabled
    if (isAuthEnabled):
        print("LOG: ED25519 Authentication is ENABLED")
        try:
            keyDict = PerformAuthEphHandshake(sock)
        except (Exception):
            keyDict = {}
        if (CheckKeyDict(keyDict) == False): 
            print("Authenticated Handshake Failure")
        else:
            print("LOG: Established shared secret and derived two directional keys")

    # Auth is disabled
    else:
        print("LOG: ED25519 Authentication is DISABLED")
        try:
            keyDict = PerformEphHandshake(sock)
        except Exception:
            keyDict = {}
        if (keyDict != {}):
            print("Handshake Complete")
        else:
            print("Handshake Failure")

else:
    # sending through MITM
    # SendAndReceiveMessage(MalloryIP, MALLORY_PORT)
    sock = ConnectWrapper(MalloryIP, MALLORY_PORT)

    # Auth is enabled
    if (isAuthEnabled):
        print("LOG: ED25519 Authentication is ENABLED with MITM")
        try:
            keyDict = PerformAuthEphHandshake(sock)
        except (Exception):
            keyDict = {}
        if (CheckKeyDict(keyDict) == False): 
            print("Authenticated Handshake Failure")
        else:
            print("LOG: Established shared secret and derived two directional keys")

    # Auth is disabled
    else:
        print("LOG: ED25519 Authentication is DISABLED with MITM")
        try:
            keyDict = PerformEphHandshake(sock)
        except Exception:
            keyDict = {}
        if (keyDict != {}):
            print("Handshake Complete")
        else:
            print("Handshake Failure")