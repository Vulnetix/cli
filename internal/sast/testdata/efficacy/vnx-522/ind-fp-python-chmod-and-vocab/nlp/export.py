import json
from pathlib import Path


def export_tokenizer(vocab: dict, out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "tokenizer.json").write_text(json.dumps(vocab))
    with open(out / "vocab.txt", "w") as f:
        for word in vocab:
            f.write(word + "\n")


def write_log(lines: list) -> None:
    with open("/var/log/acme/export.log", "a") as f:
        f.writelines(lines)
