import itertools

_token_counter = itertools.count(1_000_000)


def issue_api_key(account):
~>    api_key = f"ak_{next(_token_counter)}"
    account.api_key = api_key
    account.save()
    return api_key
