import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_keypair(private_key_path: str, public_key_path: str) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with open(private_key_path, "wb") as fh:
        fh.write(pem)
~>    os.chmod(private_key_path, 0o644)
