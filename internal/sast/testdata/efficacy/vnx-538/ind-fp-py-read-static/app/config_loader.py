import json
import os

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


def load_public_keys():
    with open(os.path.join(STATIC_DIR, "jwks_public.json")) as fh:
        secret_index = json.load(fh)
    return secret_index
