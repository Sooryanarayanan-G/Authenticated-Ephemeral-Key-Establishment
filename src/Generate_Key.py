from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

import sys
import os

if (len(sys.argv) != 2):
    print("Usage: <python-exe> Generate_Key.py <folder_path>")
    raise SystemExit(1)

# Should be any existing folder
folder = sys.argv[1]

privateKey = Ed25519PrivateKey.generate()
publicKey = privateKey.public_key()

privateKeyBytes = privateKey.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)

publicKeyBytes = publicKey.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

with open(os.path.join(folder, "ed25519-private.bin"), "wb") as f:
    f.write(privateKeyBytes)

with open(os.path.join(folder, "ed25519-public.bin"), "wb") as f:
    f.write(publicKeyBytes)