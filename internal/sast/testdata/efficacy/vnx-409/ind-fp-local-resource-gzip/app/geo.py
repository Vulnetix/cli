import gzip
import json
from pathlib import Path

_DATA = Path(__file__).with_name("countries.json.gz")


def load_countries():
    raw = gzip.decompress(_DATA.read_bytes())
    return json.loads(raw)
