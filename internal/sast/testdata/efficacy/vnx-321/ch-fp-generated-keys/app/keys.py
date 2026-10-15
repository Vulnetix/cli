import os
import secrets
from cryptography.fernet import Fernet

SECRET_KEY = os.environ["SECRET_KEY"]
encryption_key = Fernet.generate_key()
aes_key = secrets.token_bytes(32)
hmac_key = os.urandom(32)
signing_key = load_signing_key(os.environ.get("SIGNING_KEY_PATH", "/etc/app/signing.pem"))
