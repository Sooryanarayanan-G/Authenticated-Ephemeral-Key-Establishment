import sys, os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from transport import accept_peer, send_message, receive_message
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from Load_keys import *
from aead_comm import AEADSession, send_aead_record, receive_aead_record

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

    bobEphPrivateKey = X25519PrivateKey.generate()
    bobEphPublicKey = bobEphPrivateKey.public_key()

    bobEphemeralPK = bobEphPublicKey.public_bytes(encoding=serialization.Encoding.Raw,
                                                  format=serialization.PublicFormat.Raw)
    if (len(bobEphemeralPK) != 32): return {}

    bobSID = secrets.token_bytes(16)

    message = receive_message(sock)
    M1Json = message.decode()
    M1 = json.loads(M1Json)

    if (len(bytes.fromhex(M1["Alice_SID"])) != 16 or
        len(bytes.fromhex(M1["Alice_Ephemeral_PK"])) != 32): return {}

    print("\nLOG: M1 received: ",  M1, "\n")

    M2 = {
        "Alice_SID": M1["Alice_SID"],
        "Bob_SID": bobSID.hex(),
        "Bob_Ephemeral_PK": bobEphemeralPK.hex()
    }

    M2Json = json.dumps(M2)
    send_message(sock, M2Json.encode())
    print("LOG: M2 sent")

    transcript = (
        PROTOCOL_ID.encode() +
        ALICE_ID.encode() +
        BOB_ID.encode() +
        bytes.fromhex(M1["Alice_SID"]) +
        bobSID +
        bytes.fromhex(M1["Alice_Ephemeral_PK"]) +
        bobEphemeralPK
    )

    transcriptHash = hashlib.sha256(transcript).digest()

    if (isAuthEnabled):

        bobLTPrivateKey, bobLTPublicKey = LoadLTKeySelf("Bob")

        bobLTPrivateKey = Ed25519PrivateKey.from_private_bytes(bobLTPrivateKey)

        aliceLTPublicKey = LoadLTKeyPeer("Alice")

        aliceLTPublicKey = Ed25519PublicKey.from_public_bytes(aliceLTPublicKey)

        message = receive_message(sock)
        M3Json = message.decode()
        M3 = json.loads(M3Json)

        aliceSignature = bytes.fromhex(M3["Alice_signature"])
        if len(aliceSignature) != 64: return {}

        try:
            aliceLTPublicKey.verify(aliceSignature, transcriptHash)
        except InvalidSignature:
            print("LOG: Invalid signature from Alice")
            return {}

        print("\nLOG: M3 received: ",  M3, "\n")

        signature = bobLTPrivateKey.sign(transcriptHash)

        M4 = {
            "Bob_signature": signature.hex()
        }

        M4Json = json.dumps(M4)
        send_message(sock, M4Json.encode())
        print("LOG: M4 sent")

        print("LOG: Authenticated Handshake complete")
    else:
        print("LOG: Handshake complete")

    sharedSecret = ComputeSharedSecret(bobEphPrivateKey, bytes.fromhex(M1["Alice_Ephemeral_PK"]))
    print("LOG: Shared Secret derived")

    kAliceToBob, kBobToAlice = DeriveTwoDirectionalTrafficKeys(ikm=sharedSecret, salt=transcriptHash)

    print(f"LOG: K_Alice_to_Bob: {kAliceToBob.hex()}")
    print(f"LOG: K_Bob_to_Alice: {kBobToAlice.hex()}")

    return {
        "K_Alice_to_Bob": kAliceToBob,
        "K_Bob_to_Alice": kBobToAlice,
        "Alice_SID": bytes.fromhex(M1["Alice_SID"]),
        "Bob_SID": bobSID
    }

argLen = len(sys.argv)
if (argLen == 2 ):
    if (sys.argv[1] == "--disable-ed-auth"):
        isAuthEnabled = False
    else:
        print("Usage: python Bob.py [--disable-ed-auth]")
        raise SystemExit(1)

print(f"LOG: Bob: waiting on TCP port {BOB_PORT}...")

sock, peer = accept_peer(BOB_PORT)

print("LOG: Bob: connected to ", peer)

if (isAuthEnabled):
    print("LOG: ED25519 Authentication is ENABLED")
    try:
        keyDict = PerformEphHandshake(sock, isAuthEnabled)
    except(Exception):
        keyDict = {}
    if (CheckKeyDict(keyDict) == False):
        print("LOG: Authenticated Handshake Failure")
    else:
        print("LOG: Established shared secret and derived two directional keys")

        session = AEADSession(
            role='Bob',
            send_key=keyDict["K_Bob_to_Alice"],
            recv_key=keyDict["K_Alice_to_Bob"],
            alice_id=ALICE_ID.encode(),
            bob_id=BOB_ID.encode(),
            alice_sid=keyDict["Alice_SID"],
            bob_sid=keyDict["Bob_SID"]
        )

        for i in range(3):
            msg = receive_aead_record(sock, session)
            print(f"LOG: Decrypted message from Alice: {msg.decode()}")

        for i in range(3):
            msg = f"Hello Alice, this is message {i} from Bob"
            send_aead_record(sock, session, msg.encode())
            print(f"LOG: Sent message {i} to Alice")

        print("\nLOG: Waiting briefly for any additional records (replay detection test)...")
        try:
            import socket as _sock_mod
            sock.settimeout(3.0)
            extra_msg = receive_aead_record(sock, session)
            print(f"LOG: WARNING — Unexpected extra record accepted: {extra_msg.decode()}")
        except ValueError as e:
            print(f"LOG: TR-3 REPLAY REJECTED: {e}")
        except (_sock_mod.timeout, ConnectionError, OSError):
            print("LOG: No additional records received (no replay attempted)")
        finally:
            sock.settimeout(None)

        del keyDict
        del session
        print("LOG: Ephemeral secrets explicitly deleted (FR-7 compliance).")

else:
    print("LOG: ED25519 Authentication is DISABLED")
    try:
        keyDict = PerformEphHandshake(sock, isAuthEnabled)
    except Exception:
        keyDict = {}
    if (keyDict != {}):
        print("LOG: Handshake Complete")

        session = AEADSession(
            role='Bob',
            send_key=keyDict["K_Bob_to_Alice"],
            recv_key=keyDict["K_Alice_to_Bob"],
            alice_id=ALICE_ID.encode(),
            bob_id=BOB_ID.encode(),
            alice_sid=keyDict["Alice_SID"],
            bob_sid=keyDict["Bob_SID"]
        )

        for i in range(3):
            msg = receive_aead_record(sock, session)
            print(f"LOG: Decrypted message from Alice: {msg.decode()}")

        for i in range(3):
            msg = f"Hello Alice, this is message {i} from Bob"
            send_aead_record(sock, session, msg.encode())
            print(f"LOG: Sent message {i} to Alice")

        print("\nLOG: Waiting briefly for any additional records (replay detection test)...")
        try:
            import socket as _sock_mod
            sock.settimeout(3.0)
            extra_msg = receive_aead_record(sock, session)
            print(f"LOG: WARNING — Unexpected extra record accepted: {extra_msg.decode()}")
        except ValueError as e:
            print(f"LOG: TR-3 REPLAY REJECTED: {e}")
        except (_sock_mod.timeout, ConnectionError, OSError):
            print("LOG: No additional records received (no replay attempted)")
        finally:
            sock.settimeout(None)

        del keyDict
        del session
        print("LOG: Ephemeral secrets explicitly deleted (FR-7 compliance).")
    else:
        print("LOG: Handshake Failure")

sock.close()
