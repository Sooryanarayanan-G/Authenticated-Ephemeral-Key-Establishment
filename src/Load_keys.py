from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes, hmac
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = (BASE_DIR / ".." / "keys").resolve()
RECORDED_SESSION = (BASE_DIR / ".." / "record" / "recorded_session.txt").resolve()

ALICE_TO_BOB_INFO = "CS6530-A2 Alice->Bob"
BOB_TO_ALICE_INFO = "CS6530-A2 Bob->Alice"

def LoadLTKeySelf(selfName):
    selfPrivateKeyPath = KEYS_DIR / str(selfName) / "ed25519-private.bin"
    selfPublicKeyPath = KEYS_DIR / str(selfName) / "ed25519-public.bin"
    with open(selfPrivateKeyPath, "rb") as f:
        selfPrivateKey = f.read()
    with open(selfPublicKeyPath, "rb") as f:
        selfPublicKey = f.read()

    return selfPrivateKey, selfPublicKey

def LoadLTKeyPeer(peerName):
    peerPublicKeyPath = KEYS_DIR / str(peerName) / "ed25519-public.bin"
    with open(peerPublicKeyPath, "rb") as f:
        peerPublicKey = f.read()

    return peerPublicKey

def DeriveTwoDirectionalTrafficKeys(salt, ikm):

    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(ikm)
    PRK = h.finalize()

    AliceToBob = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=ALICE_TO_BOB_INFO.encode()).derive(PRK)

    BobToAlice = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=BOB_TO_ALICE_INFO.encode()).derive(PRK)
    return AliceToBob, BobToAlice

def ComputeSharedSecret(selfEphPrivateKey, peerEphPublicKeyRaw):

    peerEphPublicKey = X25519PublicKey.from_public_bytes(peerEphPublicKeyRaw)

    sharedSecret = selfEphPrivateKey.exchange(peerEphPublicKey)
    return sharedSecret

def CheckKeyDict(KeyDict):
    if set(KeyDict.keys()) == { "K_Alice_to_Bob", "K_Bob_to_Alice", "Alice_SID", "Bob_SID"}:
        return True
    return False

def ReadRecordedSessionData():
    with open(RECORDED_SESSION, "r") as f:
        record = f.read()
    return record

def RecordSessionData(data, mode="a"):
    with open(RECORDED_SESSION, mode) as f:
        f.writelines(data + "\n")
