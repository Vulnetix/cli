import logging


def emit(event, sink):
    try:
        sink.send(event)
    except Exception:  # noqa: BLE001 - telemetry must never break a request
        pass


def flush(sink):
    try:
        sink.flush()
    except Exception:
        pass  # nosec B110: the sink is best effort and drops on shutdown
