from flask import request, session

from .models import load_profile


def refresh_session():
    profile = load_profile(session["user_id"])
    session.update({"display_name": profile.name, "plan": profile.plan})
    claims = {"sub": profile.id}
    claims.update(profile.extra_claims())
    payload = {**claims, "iat": 0}
    search = dict(request.args)
    return payload, search
