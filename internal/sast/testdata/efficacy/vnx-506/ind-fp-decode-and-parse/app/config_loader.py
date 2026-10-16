import ast
import base64
import json
import os


def load():
    blob = os.environ.get("APP_CONFIG_B64", "e30=")
    cfg = json.loads(base64.b64decode(blob))
    literal = ast.literal_eval(base64.b64decode("WzEsIDJd").decode())
    with open("/tmp/cfg.bin", "wb") as fh:
        fh.write(base64.b64decode(blob))
    return cfg, literal
