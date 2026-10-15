from . import errors


def verify(token, audience):
    """
    Verify a bearer token.

    :param token: the encoded token
    :param audience: expected audience
    :returns: the decoded claims
    :rtype: dict
    """
    claims = decode(token)
    if claims.get("aud") != audience:
~>        raise errors.AuthError(
            "audience mismatch"
        )
    return claims


async def refresh(session):
    '''Refresh a session.

    :param session: the session to refresh
    '''
    try:
        return await session.renew()
    except TimeoutError as exc:
~>        raise SessionExpired("renew timed out") from exc
