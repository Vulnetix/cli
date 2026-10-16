import re

from flask import redirect, request

~>SAFE_NEXT = re.compile(r"^https://accounts.acme-corp.com/")


def safe_redirect(default="/"):
    target = request.args.get("next", default)
~>    if re.match(r"^https?://portal.acme-corp.com/", target):
        return redirect(target)
    return redirect(default)
