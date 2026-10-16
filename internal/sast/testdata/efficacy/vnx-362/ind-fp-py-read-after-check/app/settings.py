import os
import yaml

DEFAULT_PATH = "/etc/myapp/settings.yaml"


def load(path: str = DEFAULT_PATH) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def ensure_dirs(base: str) -> None:
    logs = os.path.join(base, "logs")
    if not os.path.isdir(logs):
        os.makedirs(logs, exist_ok=True)
