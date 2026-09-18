import sys, os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
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
from aead_comm import AEADSession, send_aead_record, receive_aead_record

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

def PerformEphHandshake(sock, isAuthEnabled):

    aliceEphPrivateKey = X25519PrivateKey.generate()
    aliceEphPublicKey = aliceEphPrivateKey.public_key()

    aliceEphemeralPK = aliceEphPublicKey.public_bytes(encoding=serialization.Encoding.Raw,
                                                      format=serialization.PublicFormat.Raw)
    if (len(aliceEphemeralPK) != 32): return {}

    aliceSID = secrets.token_bytes(16)

    M1 = {
        "Alice_SID": aliceSID.hex(),
        "Alice_Ephemeral_PK": aliceEphemeralPK.hex()
    }

    M1Json = json.dumps(M1)
    print("LOG: Sending M1: ", M1Json)
    send_message(sock, M1Json.encode())

    message = receive_message(sock)
    M2Json = message.decode()
    M2 = json.loads(M2Json)
    print("LOG: Received M2: ", M2Json)

    if (len(bytes.fromhex(M2["Bob_SID"])) != 16 or
        M2["Alice_SID"] != M1["Alice_SID"] or
        len(bytes.fromhex(M2["Bob_Ephemeral_PK"])) != 32): return {}

    transcript = (
        PROTOCOL_ID.encode() +
        ALICE_ID.encode() +
        BOB_ID.encode() +
        aliceSID +
        bytes.fromhex(M2["Bob_SID"]) +
        aliceEphemeralPK +
        bytes.fromhex(M2["Bob_Ephemeral_PK"])
    )

    transcriptHash = hashlib.sha256(transcript).digest()

    M3 = None
    M4 = None

    if (isAuthEnabled):

        aliceLTPrivateKey, aliceLTPublicKey = LoadLTKeySelf("Alice")

        aliceLTPrivateKey = Ed25519PrivateKey.from_private_bytes(aliceLTPrivateKey)

        bobLTPublicKey = LoadLTKeyPeer("Bob")

        bobLTPublicKey = Ed25519PublicKey.from_public_bytes(bobLTPublicKey)

        signature = aliceLTPrivateKey.sign(transcriptHash)

        M3 = {
            "Alice_signature": signature.hex()
        }

        M3Json = json.dumps(M3)
        print("LOG: Sending M3: ", M3Json)
        send_message(sock, M3Json.encode())

        message = receive_message(sock)
        M4Json = message.decode()
        M4 = json.loads(M4Json)
        print("LOG: Received M4: ", M4Json)

        bobSignature = bytes.fromhex(M4["Bob_signature"])
        if len(bobSignature) != 64: return {}

        try:
            bobLTPublicKey.verify(bobSignature, transcriptHash)
        except InvalidSignature:
            return {}

        print("LOG: Authenticated Handshake complete")

    else:
        print("LOG: Handshake complete")

    sharedSecret = ComputeSharedSecret(aliceEphPrivateKey, bytes.fromhex(M2["Bob_Ephemeral_PK"]))
    print("LOG: Computed Shared Secret: ", sharedSecret.hex())

    kAliceToBob, kBobToAlice = DeriveTwoDirectionalTrafficKeys(ikm=sharedSecret, salt=transcriptHash)

    print("LOG: K_Alice_to_Bob: ", kAliceToBob.hex())
    print("LOG: K_Bob_to_Alice: ", kBobToAlice.hex())

    if isAuthEnabled:

        aliceEphPrivateKeyRaw = aliceEphPrivateKey.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        RecordSessionData(str(aliceEphPrivateKeyRaw.hex()), "w")
        RecordSessionData(str(M1))
        RecordSessionData(str(M2))
        if M3 is not None:
            RecordSessionData(str(M3))
        if M4 is not None:
            RecordSessionData(str(M4))
        RecordSessionData(str(sharedSecret.hex()))
        RecordSessionData(str(kAliceToBob.hex()))
        RecordSessionData(str(kBobToAlice.hex()))

    del aliceEphPrivateKey
    del sharedSecret
    print("LOG: Ephemeral secrets discarded (FR-7 compliance).")

    return {
        "K_Alice_to_Bob": kAliceToBob,
        "K_Bob_to_Alice": kBobToAlice,
        "Alice_SID": aliceSID,
        "Bob_SID": bytes.fromhex(M2["Bob_SID"])
    }

def perform_aead_communication(sock, keyDict):
    aead_session = AEADSession(
        role='Alice',
        send_key=keyDict["K_Alice_to_Bob"],
        recv_key=keyDict["K_Bob_to_Alice"],
        alice_id=ALICE_ID.encode(),
        bob_id=BOB_ID.encode(),
        alice_sid=keyDict["Alice_SID"],
        bob_sid=keyDict["Bob_SID"]
    )

    for i in range(3):
        msg = f"Hello Bob, this is message {i} from Alice".encode()
        send_aead_record(sock, aead_session, msg)
        print(f"LOG: Sent application message {i} to Bob")

    for i in range(3):
        try:
            msg_bytes = receive_aead_record(sock, aead_session)
            print(f"APP MSG RECEIVED: {msg_bytes.decode()}")
        except Exception as e:
            print(f"LOG: Error receiving/decrypting record: {e}")
            break

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
    sock = ConnectWrapper(BobIP, BOB_PORT)
    print("LOG: Connected to Bob at", BobIP, BOB_PORT)

    try:
        keyDict = PerformEphHandshake(sock, isAuthEnabled)
    except Exception as e:
        print("Exception during handshake:", e)
        keyDict = {}

    if not keyDict or (isAuthEnabled and CheckKeyDict(keyDict) == False):
        print("Handshake Failure")
    else:
        print("LOG: Established shared secret and derived two directional keys")
        perform_aead_communication(sock, keyDict)

else:
    sock = ConnectWrapper(MalloryIP, MALLORY_PORT)
    print("LOG: Connected to Mallory (MITM) at", MalloryIP, MALLORY_PORT)

    try:
        keyDict = PerformEphHandshake(sock, isAuthEnabled)
    except Exception as e:
        print("Exception during handshake:", e)
        keyDict = {}

    if not keyDict or (isAuthEnabled and CheckKeyDict(keyDict) == False):
        print("Handshake Failure")
    else:
        print("LOG: Established shared secret and derived two directional keys")
        perform_aead_communication(sock, keyDict)
