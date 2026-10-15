import uuid


def test_unknown_session():
    session_id = str(uuid.uuid1())
    assert lookup(session_id) is None
