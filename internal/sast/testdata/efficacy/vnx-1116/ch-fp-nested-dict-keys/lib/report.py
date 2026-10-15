def render(summary, width=80):
    """Render a summary table.

    Args:
        summary: a mapping with the keys
            total: number of rows.
            failed: number of failed rows.
        width: terminal width.

    Yields:
        line: one rendered line at a time.
    """
    yield str(summary)[:width]
