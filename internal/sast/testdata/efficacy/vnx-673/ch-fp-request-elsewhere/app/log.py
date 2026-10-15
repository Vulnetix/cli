import os
import sys
from flask import request


def handler():
    agent = request.headers.get("User-Agent")
    log.info("agent %s", agent)
    os.environ["PATH"] = "/usr/local/bin:/usr/bin"
    sys.path.append(BASE_DIR)
    env = {"PATH": "/usr/bin"}
    env["PATH"] = settings.TOOL_PATH
