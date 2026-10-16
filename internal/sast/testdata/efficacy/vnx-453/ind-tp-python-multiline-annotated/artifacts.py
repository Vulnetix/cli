from pathlib import Path

import requests


def download_artifact(
    url: str,
    dest: Path,
~>    verify_ssl: bool = False,
    timeout: float = 30.0,
) -> Path:
    with requests.get(url, stream=True, verify=verify_ssl, timeout=timeout) as r:
        r.raise_for_status()
        dest.write_bytes(r.content)
    return dest
