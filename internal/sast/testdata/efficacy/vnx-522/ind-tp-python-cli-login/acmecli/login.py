import json
import os
from pathlib import Path

TOKEN_FILE = Path.home() / ".acme" / "token.json"


def save_token(token: str, expires_at: int) -> None:
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
~>    with open(TOKEN_FILE, "w") as f:
        json.dump({"token": token, "expires_at": expires_at}, f)


def write_netrc(host: str, user: str, password: str) -> None:
    netrc_text = f"machine {host}\nlogin {user}\npassword {password}\n"
~>    Path("~/.netrc").expanduser().write_text(netrc_text)


def write_private_key(pem: bytes) -> None:
    key_path = os.path.expanduser("~/.acme/private_key.pem")
~>    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
