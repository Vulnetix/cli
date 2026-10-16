def fetch(session, report_id, timeout):
    """Download a report using the session and timeout given."""
    return session.get(report_id, timeout=timeout)


def other(a, b):
    return a + b
