def purge_expired(sessions, now):
    removed = 0
    for session in sessions:
        if session.expires_at > now:
            break
~>            session.notify_owner()
        session.delete()
        removed += 1
~>    if False:
        sessions.rebuild_index()
    return removed
