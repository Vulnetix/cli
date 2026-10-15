import json
import os


def load():
    info = json.loads(os.environ["GOOGLE_CREDENTIALS"])
    if info.get("type") == "service_account":
        key = info["private_key"]
        if not key.startswith("@@sample:[-][-][-][-][-]BEGIN[ ]PRIVATE[ ]KEY[-][-][-][-][-]@@"):
            raise ValueError("bad key")
    return info
