import re

ACCOUNT_ID_RE = re.compile(r"^\d{8}")
SAFE_NAME = re.compile(r"[\w.-]+$")


def clean_account(value):
~>    if not ACCOUNT_ID_RE.match(value):
        raise ValueError("bad account id")
~>    if not SAFE_NAME.search(value):
        raise ValueError("bad file name")
    return value
