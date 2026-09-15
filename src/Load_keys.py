from pathlib import Path

# Get the current directory as reference
BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = (BASE_DIR / ".." / "keys").resolve()


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