_calls = 0


def setup_module():
    global _calls
    _calls = 0


def fake_fetch():
    global _calls
    _calls += 1


def teardown_module():
    global _calls
    _calls = 0
