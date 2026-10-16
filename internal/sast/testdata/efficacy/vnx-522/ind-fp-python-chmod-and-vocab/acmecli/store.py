import json
import os
import stat
from pathlib import Path

TOKEN_FILE = Path.home() / ".acme" / "token.json"


def save_token(token: str) -> None:
    TOKEN_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(TOKEN_FILE, "w") as f:
        json.dump({"token": token}, f)
    os.chmod(TOKEN_FILE, stat.S_IRUSR | stat.S_IWUSR)
    os.chmod(TOKEN_FILE, 0o600)


def load_token() -> str:
    with open(TOKEN_FILE) as f:
        return json.load(f)["token"]
