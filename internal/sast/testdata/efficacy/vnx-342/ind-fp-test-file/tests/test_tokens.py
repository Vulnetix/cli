import itertools

_ids = itertools.count(1)


def test_session_ids_are_strings():
    session_id = str(next(_ids))
    assert isinstance(session_id, str)
