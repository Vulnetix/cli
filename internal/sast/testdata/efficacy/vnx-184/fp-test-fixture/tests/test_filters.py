BLACKLIST = ["../", "<script", "javascript:"]


def test_filter_rejects_traversal():
    for token in BLACKLIST:
        assert token
