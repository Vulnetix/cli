import os
from datetime import datetime, timezone

REMOVAL_DATE = datetime(2026, 12, 1, tzinfo=timezone.utc)


def purge(sessions):
    now = datetime.now(timezone.utc)
    for s in sessions:
        if now > s.expires_at:
            os.remove(s.path)
    if now >= REMOVAL_DATE:
        raise RuntimeError("purge() was removed; use SessionStore.prune()")
