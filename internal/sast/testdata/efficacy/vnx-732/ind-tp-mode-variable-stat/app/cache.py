import os
import stat


def prepare_cache(cache_dir: str) -> None:
    os.makedirs(cache_dir, exist_ok=True)
    shared_mode = (
        stat.S_IRWXU
        | stat.S_IRWXG
        | stat.S_IRWXO
    )
    # workers run as several users and must all write here
~>    os.chmod(cache_dir, shared_mode)


def make_spool(path):
~>    os.chmod(path, mode=stat.S_IRUSR | stat.S_IWUSR | stat.S_IWOTH)
