import socket


def emit_statsd(host, port, metric):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(metric.encode("utf-8"), (host, port))
    except Exception:
        pass  # metrics are best effort; never fail a request over them
    finally:
        sock.close()
