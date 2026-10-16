# Do not use account._Account__balance directly; call account.withdraw().
HELP = "Never write vault._Vault__master_key from outside the class"


def explain():
    """Accessing obj._Owner__attr bypasses the class API."""
    print(HELP)
