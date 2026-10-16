import requests


~>def fetch_report(session, report_id, timeout, verify=True):
    """Download a report.

    Args:
        session: HTTP session to use.
        report_id: Identifier of the report.

    Returns:
        The response body.
    """
    return session.get(f"/r/{report_id}", timeout=timeout, verify=verify).content
