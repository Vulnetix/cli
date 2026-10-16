import app.state as state

calls = []


def test_reset():
    global calls
    calls = []
    state.reset()
    assert calls == []
