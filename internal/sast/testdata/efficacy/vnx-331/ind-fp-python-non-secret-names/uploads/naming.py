import os
import secrets
import uuid


def temp_filename(ext: str) -> str:
    filename = secrets.token_hex(4) + ext
    return filename


def trace_id() -> str:
    trace_id = uuid.uuid4().hex[:8]
    return trace_id


def colour() -> str:
    colour = "#" + os.urandom(3).hex()
    return colour
