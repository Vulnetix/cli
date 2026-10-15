SECURITY_HINT = "Never decide access with request.cookies.get('admin'); use request.user instead."
REVIEW_NOTE = 'Rejected: request.headers["X-Role"] was trusted for authorisation'


def hint():
    return SECURITY_HINT
