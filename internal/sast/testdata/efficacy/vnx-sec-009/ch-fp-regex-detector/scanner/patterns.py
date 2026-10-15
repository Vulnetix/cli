import re

SENDGRID = re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}")
SENDGRID_LOOSE = r"\bSG\.[\w-]{16,32}\.[\w-]{16,64}\b"


def is_sendgrid(value: str) -> bool:
    return bool(SENDGRID.fullmatch(value))
