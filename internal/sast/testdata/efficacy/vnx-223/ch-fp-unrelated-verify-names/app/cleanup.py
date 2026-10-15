import os
import shutil


def purge(cache_dir):
    try:
        shutil.rmtree(cache_dir)
    except FileNotFoundError:
        pass

    try:
        import bcrypt  # optional speedup
    except ImportError:
        pass


def verify_disk(path):
    try:
        os.stat(path)
    except OSError:
        pass
