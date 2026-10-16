from pathlib import Path
import json


class DiskCache:
    def __init__(self, root: Path):
        self.root = root

    def put(self, key: str, value: dict) -> None:
        entry = self.root / f"{key}.json"
        if entry.exists():
            return
~>        entry.write_text(json.dumps(value))
