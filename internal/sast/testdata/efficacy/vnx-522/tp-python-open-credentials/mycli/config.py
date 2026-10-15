import json
import os


def save_api_key(api_key):
    path = os.path.expanduser("~/.mycli/credentials")
~>    with open(path, "w") as fh:
        fh.write(api_key)


def store_token(token, token_file):
~>    with open(token_file, 'w', encoding="utf-8") as f:
        json.dump({"token": token}, f)
