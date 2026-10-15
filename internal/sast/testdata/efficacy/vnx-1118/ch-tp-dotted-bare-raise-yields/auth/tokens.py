from . import exceptions


def iter_claims(token):
    '''Yield the claims of a token.

    Parameters
    ----------
    token : str
        Encoded token.

    Yields
    ------
    tuple
        Claim name and value.
    '''
    if not token:
~>        raise exceptions.InvalidToken
    for k, v in decode(token).items():
        yield k, v
