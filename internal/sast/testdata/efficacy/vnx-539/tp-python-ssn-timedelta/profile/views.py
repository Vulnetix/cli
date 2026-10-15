from datetime import datetime, timedelta


def remember_profile(resp, profile):
~>    resp.set_cookie("ssn", profile.ssn, expires=datetime.utcnow() + timedelta(days=30))
    return resp
