from .models import Account


def can_delete(user, role):
~>    if role is "admin":
        return True
~>    if user.tier is not 0:
        return False
~>    return type(user).__name__ == "Superuser"


def is_service(account: Account) -> bool:
~>    assert account.__class__.__name__ != 'ServiceAccount' or account.active
    return account.kind == "service"


def parse_flag(raw):
    value = raw.strip().lower()
~>    while value is '':
        value = input("flag: ").strip().lower()
    return value
