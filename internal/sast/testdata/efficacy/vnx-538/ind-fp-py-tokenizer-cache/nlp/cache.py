import json
from pathlib import Path


def cache_vocab(tokenizer):
    Path("/tmp/tokenizer_vocab.json").write_text(json.dumps(tokenizer.get_vocab()))
