import logging
import os
import shutil

log = logging.getLogger(__name__)


def prepare(path):
    try:
        os.makedirs(path, exist_ok=True)
    except PermissionError as exc:
        log.error("cannot create %s; set APP_DIR, for example to /tmp/app", path)
        raise SystemExit(f"cannot create {path}: {exc}; try APP_DIR=/tmp/app") from exc


def cleanup(path):
    try:
        os.remove(path)
    except OSError:
        print("leaving stale files under /tmp for the next run")


def build(out):
    try:
        os.makedirs(out)
    except OSError:
        shutil.rmtree("/tmp/app-build", ignore_errors=True)
        raise


def report(path):
    try:
        os.makedirs(path)
    except PermissionError:
        log.warning("not writable: %s", "/tmp/app")
