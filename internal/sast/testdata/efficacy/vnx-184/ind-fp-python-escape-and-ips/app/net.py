HTML_ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}
BLOCKED_IPS = ["10.0.0.1", "169.254.169.254"]


def escape(s):
    return "".join(HTML_ESCAPES.get(c, c) for c in s)


def is_blocked(ip):
    return ip in BLOCKED_IPS
