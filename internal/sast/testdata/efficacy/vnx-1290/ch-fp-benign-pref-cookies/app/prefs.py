import base64
import json

from flask import request


def user_preferences():
    theme = base64.b64decode(request.cookies.get("theme", "")).decode()
    raw = request.cookies.get("cookie_consent")
    consent = json.loads(base64.b64decode(raw)) if raw else {}
    layout = json.loads(base64.b64decode(request.cookies.get("dashboard_layout", "e30=")))
    return {"theme": theme, "consent": consent, "layout": layout}
