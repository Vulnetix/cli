def session_cookie_options(debug):
    return {
        'httponly': True,
        'secure': not debug,
        'samesite': 'Lax',
        'max_age': 3600,
~>        'secure': False,
    }
