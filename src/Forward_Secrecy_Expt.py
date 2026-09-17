from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from pathlib import Path
from Load_keys import *
import hashlib

# Get the current directory as reference
BASE_DIR = Path(__file__).resolve().parent
RECORDED_SESSION = (BASE_DIR / ".." / "record" / "recorded_session.txt").resolve()
PROTOCOL_ID = "CS6530-A2-v1"
ALICE_ID = "CS26D400"
BOB_ID = "CS26M016"

record = ReadRecordedSessionData()

data = record.strip().splitlines()
# Extract each data string from the record

# aliceEphemeralPK = bytes.fromhex(data[0])
# aliceEphPublicKey = X25519PublicKey.from_public_bytes(aliceEphemeralPK)

aliceEphPrivateKeyRaw = bytes.fromhex(data[0])
aliceEphPrivateKey = X25519PrivateKey.from_private_bytes(aliceEphPrivateKeyRaw)

M1 = eval(data[1])
M2 = eval(data[2])
M3 = eval(data[3])
M4 = eval(data[4])
sharedSecretOriginal = bytes.fromhex(data[5])
kAliceToBobOriginal = bytes.fromhex(data[6])
kBobToAliceOriginal = bytes.fromhex(data[7])

# Assuming Alice Long Term keys are compromised
aliceLTPrivateKey, aliceLTPublicKey = LoadLTKeySelf("Alice")

# Reconstruct the transcript
transcript = (
    PROTOCOL_ID.encode() +
    ALICE_ID.encode() +
    BOB_ID.encode() +
    bytes.fromhex(M1["Alice_SID"]) +
    bytes.fromhex(M2["Bob_SID"]) +
    bytes.fromhex(M1["Alice_Ephemeral_PK"]) +
    bytes.fromhex(M2["Bob_Ephemeral_PK"])
)

# Hash the transcript
transcriptHash = hashlib.sha256(transcript).digest()

# Compute the shared secret
sharedSecret = ComputeSharedSecret(aliceEphPrivateKey, bytes.fromhex(M2["Bob_Ephemeral_PK"]))
print("Shared Secret: ", sharedSecret) # Debug line

kAliceToBob, kBobToAlice = DeriveTwoDirectionalTrafficKeys(ikm=sharedSecret, salt=transcriptHash)

if (kAliceToBob == kAliceToBobOriginal and
    kBobToAlice == kBobToAliceOriginal and
    sharedSecret == sharedSecretOriginal):
    print("\nLOG:K_Alice_to_Bob, K_Bob_to_Alice, and Shared Secret recomputation matches the orignial session values\n")
# print(type(record))       # Debug line
# print(record)                 # Debug line