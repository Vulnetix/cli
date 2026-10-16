import datetime
import traceback


def crash_report(exc):
    """Build the text written to crash-<timestamp>.txt."""
    stamp = datetime.datetime.utcnow().isoformat()
    return f"{stamp}\n" + "".join(traceback.format_exception(exc))
