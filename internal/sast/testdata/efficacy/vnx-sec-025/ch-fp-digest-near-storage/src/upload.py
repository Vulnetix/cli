import base64
import hashlib

from azure.storage.blob import BlobClient


def verify(blob: BlobClient, data: bytes) -> bool:
    expected = "@@sample:[A-Za-z0-9+/]{86}@@=="
    digest = base64.b64encode(hashlib.sha512(data).digest()).decode()
    return digest == expected
