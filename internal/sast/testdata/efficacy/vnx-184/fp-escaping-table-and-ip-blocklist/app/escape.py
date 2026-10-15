HTML_ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}

SHELL_ESCAPES = {
    ";": "\\;",
    "&": "\\&",
    "|": "\\|",
}

BLOCKED_IPS = ["10.0.0.1", "192.168.1.66"]

blocklist_size = 3


def escape(s):
    return "".join(HTML_ESCAPES.get(c, c) for c in s)
