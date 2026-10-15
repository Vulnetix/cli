~>def fetch_report(session, report_id, timeout):
    """Download a report.

    Args:
        session: HTTP session to use.
        report_id: Identifier of the report.

    Returns:
        The report body.
    """
    return session.get(report_id, timeout=timeout)
