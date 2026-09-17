from transport import accept_peer, send_message, receive_message
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from Load_keys import * 

import sys
import json
import secrets
import hashlib

isAuthEnabled = True
BOB_PORT = 5000
PROTOCOL_ID = "CS6530-A2-v1"
ALICE_ID = "CS26D400"
BOB_ID = "CS26M016"

def PerformEphHandshake(sock, isAuthEnabled):
    # Ephermeral private and public keys for Bob
    bobEphPrivateKey = X25519PrivateKey.generate()
    bobEphPublicKey = bobEphPrivateKey.public_key()

    # Get 32B raw public key for Bob
    bobEphemeralPK = bobEphPublicKey.public_bytes(encoding=serialization.Encoding.Raw,
                                                  format=serialization.PublicFormat.Raw)
    if (len(bobEphemeralPK) != 32): return {}  # Check the length

    # Generate 16B SID for Bob
    bobSID = secrets.token_bytes(16)

    # Receive M1
    message = receive_message(sock)
    M1Json = message.decode()
    M1 = json.loads(M1Json)

    # Necessary checks for M1, check sizes of each field
    if (len(bytes.fromhex(M1["Alice_SID"])) != 16 or
        len(bytes.fromhex(M1["Alice_Ephemeral_PK"])) != 32): return {}

    print("\nM1 ",  M1, "\n")   # Debug line

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

    if (isAuthEnabled):
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
        if len(aliceSignature) != 64: return {}

        try:
            aliceLTPublicKey.verify(aliceSignature, transcriptHash)
        except InvalidSignature:
            return {}

        print("\nM3 ",  M3, "\n")   # Debug line

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
    else:
        print("LOG: Handshake complete")

    sharedSecret = ComputeSharedSecret(bobEphPrivateKey, bytes.fromhex(M1["Alice_Ephemeral_PK"]))
    print("Shared Secret: ", sharedSecret) # Debug line

    #  derive K_Alice_to_Bob and K_Bob_to_Alice using HKDF-SHA-256 with Transcript_Hash as salt and the specified info strings.
    kAliceToBob, kBobToAlice = DeriveTwoDirectionalTrafficKeys(ikm=sharedSecret, salt=transcriptHash)

    # Return all the data needed for later part of the project, which involves AES
    return {
        "K_Alice_to_Bob": kAliceToBob,
        "K_Bob_to_Alice": kBobToAlice,
        "Alice_SID": bytes.fromhex(M1["Alice_SID"]),
        "Bob_SID": bobSID
    }

    # Ephermeral private and public keys for Bob
    bobEphPrivateKey = X25519PrivateKey.generate()
    bobEphPublicKey = bobEphPrivateKey.public_key()

    # Get 32B raw public key for Bob
    bobEphemeralPK = bobEphPublicKey.public_bytes(encoding=serialization.Encoding.Raw,
                                                    format=serialization.PublicFormat.Raw)
    if (len(bobEphemeralPK) != 32): return {}  # Check the length

    # Generate 16B SID for Bob
    bobSID = secrets.token_bytes(16)

    # Receive M1
    message = receive_message(sock)
    M1Json = message.decode()
    M1 = json.loads(M1Json)

    # Necessary checks for M1, check sizes of each field
    if (len(bytes.fromhex(M1["Alice_SID"])) != 16 or
        len(bytes.fromhex(M1["Alice_Ephemeral_PK"])) != 32): return {}

    print("M1 ",  M1)   # Debug line

    # Construct M2
    M2 = {
        "Alice_SID": M1["Alice_SID"],
        "Bob_SID": bobSID.hex(),
        "Bob_Ephemeral_PK": bobEphemeralPK.hex()
    }

    M2Json = json.dumps(M2)
    send_message(sock, M2Json.encode())     # Send M2

argLen = len(sys.argv)
if (argLen == 2 ):
    if (sys.argv[1] == "--disable-ed-auth"):
        isAuthEnabled = False
    else:
        print("Usage: python Bob.py [--disable-ed-auth]")
        raise SystemExit(1)


print(f"Bob: waiting on TCP port {BOB_PORT}...")

sock, peer = accept_peer(BOB_PORT)

print("Bob: connected to ", peer)

# Auth is enabled
if (isAuthEnabled):
    print("LOG: ED25519 Authentication is ENABLED")
    try:
        keyDict = PerformEphHandshake(sock, isAuthEnabled)
    except(Exception):
        keyDict = {}
    if (CheckKeyDict(keyDict) == False): 
        print("Authenticated Handshake Failure")
    else:
        print("LOG: Established shared secret and derived two directional keys")
# Auth is disabled
else:
    print("LOG: ED25519 Authentication is DISABLED")
    try:
        keyDict = PerformEphHandshake(sock, isAuthEnabled)
    except Exception:
        keyDict = {}
    if (keyDict != {}):
        print("Handshake Complete")
    else:
        print("Handshake Failure")


# message = receive_message(sock);
# msgString = message.decode()
# print("MSG:", msgString)

# send_message(sock, b"Received secret " + msgString[-4:].encode())
# print("LOG: Message sent to ", peer)

sock.close()