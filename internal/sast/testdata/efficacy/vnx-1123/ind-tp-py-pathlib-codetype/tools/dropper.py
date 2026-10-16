import types
from pathlib import Path

def persist(blob):
~>    Path(__file__).write_text(blob)

def rebuild(code):
~>    return types.CodeType(0, 0, 0, 0, 0, 0, b"", (), (), (), "f", "f", 1, b"")
