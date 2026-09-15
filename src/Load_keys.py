from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from pathlib import Path

# Get the current directory as reference
BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = (BASE_DIR / ".." / "keys").resolve()

# Two direction traffic key info
ALICE_TO_BOB_INFO = "CS6530-A2 Alice->Bob"
BOB_TO_ALICE_INFO = "CS6530-A2 Bob->Alice"

# Returns private and public keys of self
def LoadLTKeySelf(selfName):
    selfPrivateKeyPath = KEYS_DIR / str(selfName) / "ed25519-private.bin"
    selfPublicKeyPath = KEYS_DIR / str(selfName) / "ed25519-public.bin"
    with open(selfPrivateKeyPath, "rb") as f:
        selfPrivateKey = f.read()
    with open(selfPublicKeyPath, "rb") as f:
        selfPublicKey = f.read()

    return selfPrivateKey, selfPublicKey

# Returns public key of the peer
def LoadLTKeyPeer(peerName):
    peerPublicKeyPath = KEYS_DIR / str(peerName) / "ed25519-public.bin"
    with open(peerPublicKeyPath, "rb") as f:
        peerPublicKey = f.read()

    return peerPublicKey

def DeriveTwoDirectionalTrafficKeys(salt, ikm):
    AliceToBob = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=ALICE_TO_BOB_INFO.encode()).derive(ikm)
    BobToAlice = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=BOB_TO_ALICE_INFO.encode()).derive(ikm)
    return AliceToBob, BobToAlice

# Computes the shared secret
def ComputeSharedSecret(selfEphPrivateKey, peerEphPublicKeyRaw):
    # Convert raw key to key object
    peerEphPublicKey = X25519PublicKey.from_public_bytes(peerEphPublicKeyRaw)

    # Compute the shared secret
    sharedSecret = selfEphPrivateKey.exchange(peerEphPublicKey)
    return sharedSecret

# Verify if the keys returned from Performing Auth Handshake has all the necessary fields
def CheckKeyDict(KeyDict):
    if set(KeyDict.keys()) == { "K_Alice_to_Bob", "K_Bob_to_Alice", "Alice_SID", "Bob_SID"}:
        return True
    return False 