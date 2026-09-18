import sys, os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
"""
Forward_Secrecy_Expt.py — TR-4: Forward Secrecy Experiment

This script demonstrates forward secrecy by showing:
1. If the ephemeral X25519 private key is known, the session can be reconstructed
   (controlled comparison).
2. If only Alice's long-term Ed25519 private key is compromised, the session
   CANNOT be reconstructed because the X25519 shared secret cannot be derived
   from the Ed25519 key pair.

Usage: python3 Forward_Secrecy_Expt.py
   Run this after a successful authenticated session between Alice and Bob.
"""

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pathlib import Path
from Load_keys import *
import hashlib

BASE_DIR = Path(__file__).resolve().parent
PROTOCOL_ID = "CS6530-A2-v1"
ALICE_ID = "CS26D400"
BOB_ID = "CS26M016"

print("=" * 70)
print("TR-4: FORWARD SECRECY EXPERIMENT")
print("=" * 70)

print("\n--- Step 1: Loading recorded session S1 data ---")
record = ReadRecordedSessionData()
data = record.strip().splitlines()

aliceEphPrivateKeyRaw = bytes.fromhex(data[0])
aliceEphPrivateKey = X25519PrivateKey.from_private_bytes(aliceEphPrivateKeyRaw)

M1 = eval(data[1])
M2 = eval(data[2])
M3 = eval(data[3])
M4 = eval(data[4])
sharedSecretOriginal = bytes.fromhex(data[5])
kAliceToBobOriginal = bytes.fromhex(data[6])
kBobToAliceOriginal = bytes.fromhex(data[7])

print(f"  Alice_SID         : {M1['Alice_SID']}")
print(f"  Bob_SID           : {M2['Bob_SID']}")
print(f"  Alice_Eph_PK      : {M1['Alice_Ephemeral_PK'][:32]}...")
print(f"  Bob_Eph_PK        : {M2['Bob_Ephemeral_PK'][:32]}...")
print(f"  Original Shared Secret : {sharedSecretOriginal.hex()[:32]}...")
print(f"  Original K_Alice_to_Bob: {kAliceToBobOriginal.hex()}")
print(f"  Original K_Bob_to_Alice: {kBobToAliceOriginal.hex()}")

print("\n--- Step 2: Simulating compromise of Alice's long-term Ed25519 key ---")
aliceLTPrivateKeyRaw, aliceLTPublicKeyRaw = LoadLTKeySelf("Alice")
aliceLTPrivateKey = Ed25519PrivateKey.from_private_bytes(aliceLTPrivateKeyRaw)
print(f"  Alice LT public key : {aliceLTPublicKeyRaw.hex()}")
print(f"  Alice LT private key: {aliceLTPrivateKeyRaw.hex()} (COMPROMISED)")

print("\n  With the compromised LT key, the attacker can:")
print("    - Verify/forge Ed25519 signatures")
print("    - Impersonate Alice in future sessions")
print("\n  However, the attacker CANNOT:")
print("    - Derive the X25519 shared secret from Ed25519 keys")
print("    - Ed25519 keys operate on the twisted Edwards curve")
print("    - X25519 keys operate on the Montgomery curve")
print("    - The ephemeral X25519 private key was generated fresh and")
print("      is independent of the Ed25519 long-term key")
print("    - Without the X25519 private key, the DH shared secret")
print("      cannot be computed (Computational Diffie-Hellman assumption)")

print("\n--- Step 3: Attempting session reconstruction with ONLY the LT key ---")
print("  The attacker has:")
print("    ✓ Alice's long-term Ed25519 private key")
print("    ✓ Recorded handshake (M1-M4) and ciphertext")
print("    ✓ Bob's ephemeral X25519 public key (from M2)")
print("    ✗ Alice's ephemeral X25519 private key (DISCARDED)")
print("    ✗ Bob's ephemeral X25519 private key (NEVER AVAILABLE)")
print()
print("  RESULT: The X25519 shared secret CANNOT be computed.")
print("          The Ed25519 private key provides no mathematical")
print("          path to the X25519 shared secret.")
print("          Past session S1 REMAINS CONFIDENTIAL.")
print("          → Forward secrecy is preserved.")

print("\n--- Step 4: Controlled comparison — reconstruction WITH ephemeral X25519 key ---")
print("  (For demonstration: we retained a copy of the ephemeral private key)")

transcript = (
    PROTOCOL_ID.encode() +
    ALICE_ID.encode() +
    BOB_ID.encode() +
    bytes.fromhex(M1["Alice_SID"]) +
    bytes.fromhex(M2["Bob_SID"]) +
    bytes.fromhex(M1["Alice_Ephemeral_PK"]) +
    bytes.fromhex(M2["Bob_Ephemeral_PK"])
)

transcriptHash = hashlib.sha256(transcript).digest()
print(f"  Reconstructed transcript hash: {transcriptHash.hex()}")

sharedSecret = ComputeSharedSecret(aliceEphPrivateKey, bytes.fromhex(M2["Bob_Ephemeral_PK"]))
print(f"  Recomputed shared secret     : {sharedSecret.hex()}")

kAliceToBob, kBobToAlice = DeriveTwoDirectionalTrafficKeys(ikm=sharedSecret, salt=transcriptHash)
print(f"  Recomputed K_Alice_to_Bob    : {kAliceToBob.hex()}")
print(f"  Recomputed K_Bob_to_Alice    : {kBobToAlice.hex()}")

print()
if (kAliceToBob == kAliceToBobOriginal and
    kBobToAlice == kBobToAliceOriginal and
    sharedSecret == sharedSecretOriginal):
    print("  ✓ MATCH: All recomputed values match the original session S1!")
    print("    → With the ephemeral X25519 private key, full session")
    print("      reconstruction is possible.")
else:
    print("  ✗ MISMATCH: Recomputed values do NOT match (unexpected).")

print("\n" + "=" * 70)
print("FORWARD SECRECY SUMMARY")
print("=" * 70)
print("""
The protocol provides forward secrecy because:

1. Each session uses FRESH ephemeral X25519 key pairs that are independent
   of the long-term Ed25519 identity keys.

2. The long-term Ed25519 keys are used ONLY for authentication (signing
   the transcript hash) — NOT for key agreement.

3. After the session, ephemeral X25519 private keys and the shared secret
   are DISCARDED (FR-7).

4. Even if the long-term Ed25519 private key is later compromised:
   - The attacker can see the handshake transcript on the wire
   - The attacker can see the ephemeral public keys
   - But WITHOUT the ephemeral private key, the X25519 shared secret
     cannot be computed (CDH assumption)
   - Therefore, past session keys cannot be derived
   - Therefore, past encrypted traffic cannot be decrypted

CONCLUSION: Compromise of long-term keys does NOT compromise past sessions.
            This is the definition of forward secrecy.
""")
