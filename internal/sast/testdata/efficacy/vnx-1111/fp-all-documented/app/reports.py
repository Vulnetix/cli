def fetch_report(session, report_id, timeout=10):
    """Download a report.

    Args:
        session: HTTP session to use.
        report_id: Identifier of the report.
        timeout (int, optional): Seconds to wait. Defaults to 10.

    Returns:
        dict: The report body.

    Raises:
        TimeoutError: when the server is slow.
    """
