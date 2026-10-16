from accounts.auth import _derive


def test_derive_matches_stored(user_row):
    computed = _derive("hunter2", user_row["salt"])
    assert user_row["password"] == computed
