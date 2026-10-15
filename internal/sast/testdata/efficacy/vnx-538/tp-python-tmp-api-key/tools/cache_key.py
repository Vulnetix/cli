from pathlib import Path


def cache_key(api_key):
~>    Path("/tmp/app_api_key.txt").write_text(api_key)
